<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Investigation
{
    public static function allowed(): bool
    {
        return current_user_can('manage_options') || current_user_can('site_defense_investigate');
    }

    public static function status(): array
    {
        $scan = (array) get_option('sd_scan', []);
        $audit = DbAudit::report();
        return ['file_scan' => $scan['status'] ?? 'idle', 'file_scan_finished' => $scan['last_success'] ?? 0,
            'database_audit' => $audit['status'] ?? 'idle', 'database_audit_finished' => $audit['finished'] ?? 0,
            'vulnerabilities_checked' => get_option('sd_findings', [])['checked'] ?? 0,
            'response_mode' => ResponseMode::status()['active'], 'heartbeat' => Heartbeat::status()];
    }

    public static function report(int $hours, int $limit, string $accessLog = ''): array
    {
        $since = time() - $hours * HOUR_IN_SECONDS;
        $events = [];
        foreach (Timeline::read($hours, $limit) as $row) {
            $context = $row['context'];
            $events[] = ['id' => 'journal:' . $row['id'], 'time' => $row['occurred'], 'kind' => $row['kind'],
                'path' => self::path($context['path'] ?? ''), 'user_id' => absint($context['user_id'] ?? 0),
                'actor_id' => absint($context['actor_id'] ?? 0)];
        }
        [$waf, $wafLimited] = self::wafEvents($since, $limit);
        [$correlation, $posts, $confirmed, $conflicted] = RequestCorrelation::build($waf, $wafLimited, $accessLog, $since, $limit);
        $blocked = [];
        foreach ($waf as $event) {
            if ($event['kind'] === 'waf_block' && $event['request_id'] !== '') {
                $blocked[$event['request_id']] = true;
            }
        }
        $events = array_merge($events, $waf, $posts);
        usort($events, static fn ($a, $b) => $b['time'] <=> $a['time']);
        $events = array_slice($events, 0, $limit);
        $versions = [];
        foreach (get_option('sd_findings', [])['items'] ?? [] as $row) {
            if (!empty($row['informational'])) {
                continue;
            }
            $versions[] = array_intersect_key($row, array_flip(['key', 'version', 'active', 'cve', 'id', 'score', 'fixed', 'kev']));
            if (count($versions) === $limit) {
                break;
            }
        }
        $database = [];
        foreach (array_slice(DbAudit::report()['findings'] ?? [], 0, $limit) as $row) {
            $row['location'] = self::path($row['location']);
            $database[] = array_intersect_key($row, array_flip(['type', 'source', 'id', 'location', 'object_id', 'event_sha256']));
        }
        $files = [];
        foreach (array_slice(get_option('sd_scan', [])['findings'] ?? [], 0, $limit) as $row) {
            $files[] = ['finding' => $row[0], 'path' => self::path($row[1]), 'sha256' => $row[2] ?? '',
                'confidence' => $row[3]['confidence'] ?? ''];
        }
        $targets = CleanupPlan::targets();
        $contentTargets = array_filter($targets, static fn (array $step) => $step['type'] === 'db_content');
        return [
            'status' => self::status(), 'window_start' => $since, 'access_log' => $correlation['proxy']['status'],
            'events' => $events, 'vulnerabilities' => $versions,
            'file_findings' => $files, 'database_findings' => $database,
            'cleanup_targets' => array_slice(array_diff_key($targets, $contentTargets), 0, $limit, true) +
                array_slice($contentTargets, 0, $limit, true),
            'request_correlation' => $correlation,
            'entry_hypotheses' => self::hypotheses($events, $versions, $confirmed, $conflicted, $blocked),
            'limits' => ['The first observed event may follow the initial entry.',
                'A vulnerable installed version and a blocked request are insufficient to establish compromise.',
                'A confirmed request links records in the selected sources. A later file event is a time-based association.',
                'Scan reports describe their last recorded run. Event output is bounded.'],
        ];
    }

    private static function wafEvents(int $since, int $limit): array
    {
        global $wpdb;
        $events = State::table('events');
        $current = get_option('sd_event_schema') === '2' ? ($wpdb->get_results($wpdb->prepare(
            "SELECT id,kind,detail,occurred AS time,context FROM $events WHERE occurred >= %d
             AND kind IN ('waf_block','waf_observe') AND context IS NOT NULL ORDER BY occurred DESC,id DESC LIMIT %d", $since, $limit + 1
        ), ARRAY_A) ?: []) : [];
        $table = State::table('incidents');
        // Current incident summaries point to an individual event and would duplicate that evidence.
        $eventMarker = '%' . $wpdb->esc_like('"request_event_id":') . '%';
        $legacy = $wpdb->get_results($wpdb->prepare(
            "SELECT id,kind,detail,last_seen AS time,context FROM $table WHERE last_seen >= %d AND kind IN ('waf_block','waf_observe')
             AND context NOT LIKE %s ORDER BY last_seen DESC,id DESC LIMIT %d", $since, $eventMarker, $limit + 1
        ), ARRAY_A) ?: [];
        $rows = [];
        foreach (['waf-event:' => $current, 'waf:' => $legacy] as $prefix => $source) {
            foreach ($source as $row) {
                $context = RequestEvidence::wafContext((array) json_decode($row['context'], true));
                preg_match('/^([A-Z0-9][A-Z0-9_-]{2,63})(?: · |$)/D', $row['detail'], $rule);
                $rule = $rule[1] ?? '';
                $rows[] = ['id' => $prefix . $row['id'], 'time' => (int) $row['time'], 'kind' => $row['kind'],
                    'rule' => $rule, 'cve' => preg_match('/^CVE-\d{4}-\d{4,}$/D', $rule) ? $rule : '',
                    'path' => $context['route'], 'method' => $context['method'], 'request_id' => $context['request_id'],
                    'layer' => $context['layer'] ?: 'unknown'];
            }
        }
        usort($rows, static fn ($a, $b) => $b['time'] <=> $a['time']);
        return [array_slice($rows, 0, $limit), count($rows) > $limit];
    }

    private static function hypotheses(array $events, array $versions, array $confirmed, array $conflicted, array $blocked): array
    {
        $candidates = [];
        $seen = [];
        foreach ($events as $request) {
            if ($request['kind'] === 'login_success' && $request['user_id']) {
                foreach ($events as $change) {
                    if (in_array($change['kind'], ['application_password', 'privileged_user', 'user_role'], true) &&
                        $change['actor_id'] === $request['user_id'] && $change['time'] >= $request['time'] &&
                        $change['time'] <= $request['time'] + 30 * MINUTE_IN_SECONDS) {
                        $candidates[] = ['vector' => 'privileged_access_review', 'confidence' => 'possible',
                            'user_id' => $request['user_id'], 'evidence' => [$request['id'], $change['id']]];
                        break;
                    }
                }
            }
            if (count($candidates) >= 10) {
                return $candidates;
            }
            if (($request['kind'] !== 'waf_observe' && $request['kind'] !== 'http_post') ||
                isset($blocked[$request['request_id']]) ||
                ($request['kind'] === 'http_post' && isset($conflicted[$request['request_id']]))) {
                continue;
            }
            foreach ($versions as $row) {
                $slug = str_starts_with($row['key'], 'plugin:') ? substr($row['key'], 7) : '';
                $componentHit = $slug !== '' && str_starts_with($request['path'], '/wp-content/plugins/' . $slug . '/');
                $cveHit = !empty($row['cve']) && $row['cve'] === ($request['cve'] ?? '');
                if (empty($row['active']) || (!$componentHit && !$cveHit)) {
                    continue;
                }
                foreach ($events as $file) {
                    if (!in_array($file['kind'], ['file_detected', 'file_changed'], true) ||
                        $file['time'] < $request['time'] || $file['time'] > $request['time'] + 30 * MINUTE_IN_SECONDS ||
                        !preg_match('~^wp-content/(?:uploads/|plugins/' . preg_quote($slug, '~') . '/)~',
                            ltrim($file['path'], '/'))) {
                        continue;
                    }
                    $partners = $confirmed[$request['id']] ?? [];
                    $key = ($partners ? $request['request_id'] : $request['id']) . '|' . $row['key'] . '|' . $row['id'] . '|' . $file['id'];
                    if (!isset($seen[$key])) {
                        $seen[$key] = true;
                        $candidates[] = ['vector' => 'suspected_vulnerable_component', 'confidence' => 'possible', 'component' => $row['key'],
                            'cve' => $row['cve'], 'advisory' => $row['id'], 'route' => $request['path'],
                            'evidence' => array_merge([$request['id'], $file['id']], $partners)];
                    }
                    break;
                }
                if (count($candidates) >= 10) {
                    return $candidates;
                }
            }
        }
        return $candidates;
    }

    public static function path(string $path): string
    {
        return RequestEvidence::path($path);
    }
}
