<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class RequestCorrelation
{
    private const LOG_BYTES = 524288;
    private const MAX_CLOCK_DIFFERENCE = 300;

    public static function build(array $waf, bool $wafLimited, string $path, int $since, int $limit): array
    {
        $byRequest = [];
        $withoutId = [];
        foreach ($waf as $event) {
            if ($event['request_id'] === '') {
                $withoutId[] = $event['id'];
            } else {
                $byRequest[$event['request_id']][] = $event;
            }
        }
        [$proxy, $posts, $coverage] = self::readProxy($path, $since, $limit, $byRequest);
        $requests = [];
        $confirmed = [];
        $conflicted = [];
        foreach ($byRequest + $proxy as $id => $_) {
            $wafEvents = $byRequest[$id] ?? [];
            $proxyRows = $proxy[$id]['rows'] ?? [];
            $proxyCount = $proxy[$id]['count'] ?? 0;
            $gaps = [];
            $delta = [];
            if (!$wafEvents) {
                $status = 'proxy_only';
                $gaps[] = 'no_waf_match_in_sample';
            } elseif (!$proxyCount) {
                $status = 'waf_only';
                $gaps[] = match ($coverage['status']) {
                    'not_configured' => 'proxy_log_not_selected',
                    'unavailable' => 'proxy_log_unavailable',
                    default => 'no_proxy_match_in_sample',
                };
            } else {
                [$conflicts, $gaps, $delta] = self::compare($wafEvents, $proxyRows[0], $proxyCount);
                $status = $conflicts ? 'conflict' : 'confirmed';
                $gaps = array_merge($gaps, $conflicts);
                if ($conflicts) {
                    $conflicted[$id] = true;
                } else {
                    foreach ($wafEvents as $event) {
                        $confirmed[$event['id']] = [$proxyRows[0]['id']];
                        $confirmed[$proxyRows[0]['id']][] = $event['id'];
                    }
                }
            }
            if ($status === 'proxy_only' && $proxyCount > 1) {
                $gaps[] = 'duplicate_proxy_id';
            }
            $requests[] = ['request_id' => (string) $id, 'status' => $status,
                'confirmed_sources' => $status === 'confirmed' ? ['waf', 'proxy'] : [], 'gaps' => $gaps,
                'sources' => ['waf' => $wafEvents, 'proxy' => $proxyRows], 'proxy_rows' => $proxyCount,
                'proxy_after_waf_seconds' => $delta];
        }
        return [['waf' => ['sampled_events' => count($waf), 'event_limit_reached' => $wafLimited,
                'events_without_id' => $withoutId, 'early_events_require_drain' => (bool) get_option('sd_early_enabled')],
            'proxy' => $coverage, 'requests' => $requests], $posts, $confirmed, $conflicted];
    }

    private static function compare(array $waf, array $proxy, int $proxyCount): array
    {
        $conflicts = $proxyCount > 1 ? ['duplicate_proxy_id'] : [];
        $gaps = [];
        $delta = [];
        foreach ($waf as $event) {
            $delta[$event['id']] = $proxy['time'] - $event['time'];
            if (abs($delta[$event['id']]) > self::MAX_CLOCK_DIFFERENCE) {
                $conflicts[] = 'timestamp_mismatch';
            }
            foreach (['method', 'path'] as $field) {
                if ($event[$field] === '' || $proxy[$field] === '') {
                    $gaps[] = $field . '_unavailable';
                } elseif ($event[$field] !== $proxy[$field]) {
                    $conflicts[] = $field . '_mismatch';
                }
            }
            if ($event['kind'] === 'waf_block' && $proxy['status'] !== 403) {
                $conflicts[] = 'block_status_mismatch';
            }
        }
        return [array_values(array_unique($conflicts)), array_values(array_unique($gaps)), $delta];
    }

    private static function readProxy(string $path, int $since, int $limit, array $waf): array
    {
        $coverage = ['status' => $path === '' ? 'not_configured' : 'unavailable', 'rows_with_id' => 0,
            'rows_without_id' => 0, 'unparsed_lines' => 0, 'oldest_time' => null, 'newest_time' => null,
            'request_limit_reached' => false];
        if ($path === '' || !is_file($path) || !is_readable($path) || !($file = @fopen($path, 'rb'))) {
            return [[], [], $coverage];
        }
        try {
            $stat = fstat($file);
            if (!$stat) {
                return [[], [], $coverage];
            }
            $offset = max(0, (int) $stat['size'] - self::LOG_BYTES);
            if ($offset && fseek($file, $offset - 1) !== 0) {
                return [[], [], $coverage];
            }
            $skipFirst = $offset && fgetc($file) !== "\n";
            $raw = stream_get_contents($file, self::LOG_BYTES);
            if (!is_string($raw)) {
                return [[], [], $coverage];
            }
        } finally {
            fclose($file);
        }
        $coverage['status'] = $offset ? 'sampled_tail' : 'available';
        $groups = [];
        $posts = [];
        $selected = 0;
        $position = $offset + strlen($raw) + 1;
        $until = time();
        foreach (array_reverse(explode("\n", $raw), true) as $number => $line) {
            $position -= strlen($line) + 1;
            if (($skipFirst && $number === 0) || trim($line) === '') {
                continue;
            }
            $row = self::parse(rtrim($line, "\r"));
            if (!$row) {
                ++$coverage['unparsed_lines'];
                continue;
            }
            if ($row['time'] < $since || $row['time'] > $until) {
                continue;
            }
            $coverage['oldest_time'] = min($coverage['oldest_time'] ?? $row['time'], $row['time']);
            $coverage['newest_time'] = max($coverage['newest_time'] ?? $row['time'], $row['time']);
            $id = $row['request_id'];
            ++$coverage[$id === '' ? 'rows_without_id' : 'rows_with_id'];
            $post = $row['method'] === 'POST' && $row['status'] >= 200 && $row['status'] < 400 &&
                ($row['path'] === '/wp-login.php' || str_starts_with($row['path'], '/wp-content/plugins/'));
            $matched = $id !== '' && isset($waf[$id]);
            $row['kind'] = $post ? 'http_post' : 'proxy_request';
            // Preserve legacy combined-log references for existing reports and cleanup plans.
            $row['id'] = $row['format'] === 'combined'
                ? 'http:' . substr(hash('sha256', $row['time'] . '|' . $row['path'] . '|' . $number), 0, 20)
                : 'proxy:' . substr(hash('sha256', $id . '|' . $row['time'] . '|' . $position), 0, 20);
            if ($post && (count($posts) < $limit || $matched)) {
                if (!$matched || !isset($groups[$id])) {
                    $posts[] = $row;
                }
            }
            if ($id === '') {
                continue;
            }
            if (!isset($groups[$id])) {
                if (!$matched && $selected >= $limit) {
                    $coverage['request_limit_reached'] = true;
                    continue;
                }
                $groups[$id] = ['count' => 0, 'rows' => []];
                $selected += $matched ? 0 : 1;
            }
            ++$groups[$id]['count'];
            if (count($groups[$id]['rows']) < 3) {
                $groups[$id]['rows'][] = $row;
            }
        }
        return [$groups, $posts, $coverage];
    }

    private static function parse(string $line): ?array
    {
        if (str_starts_with(ltrim($line), '{')) {
            $data = json_decode($line, true, 4);
            if (!is_array($data) || !is_string($data['time'] ?? null) || strlen($data['time']) !== 25 ||
                !is_string($data['path'] ?? null) || !str_starts_with($data['path'], '/') ||
                !is_int($data['status'] ?? null)) {
                return null;
            }
            $date = \DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:sP', $data['time']);
            $method = RequestEvidence::method($data['method'] ?? null);
            $path = RequestEvidence::requestPath($data['path']);
            $status = $data['status'];
            $id = RequestEvidence::id($data['sd_request_id'] ?? null);
            $format = 'site_defense_json';
        } else {
            if (!preg_match('~^\S+ \S+ \S+ \[([^]]{1,32})\] "([A-Z]{1,16}) (/[^ "]*) HTTP/[^" ]+" (\d{3})\b~', $line, $match)) {
                return null;
            }
            $date = \DateTimeImmutable::createFromFormat('!d/M/Y:H:i:s O', $match[1]);
            $method = $match[2];
            $path = RequestEvidence::requestPath($match[3]);
            $status = (int) $match[4];
            $id = '';
            $format = 'combined';
        }
        if (!$date || \DateTimeImmutable::getLastErrors() !== false || $method === '' || $status < 100 || $status > 599) {
            return null;
        }
        return ['time' => $date->getTimestamp(), 'method' => $method, 'path' => $path,
            'status' => $status, 'request_id' => $id, 'format' => $format];
    }
}
