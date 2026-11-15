<?php
namespace SiteDefense;

// Shared by the PHP prepend loader and the WordPress request hooks.
final class FirewallMatcher
{
    public static function version(string $file, bool $core): string
    {
        $header = @file_get_contents($file, false, null, 0, 8192);
        if (!is_string($header)) {
            return '';
        }
        $pattern = $core ? '/^\s*\$wp_version\s*=\s*[\x27\x22]([^"\x27]+)[\x27\x22]/m'
            : '/^[ \t\/*#@]*Version:[ \t]*([^\r\n*]+)/mi';
        return preg_match($pattern, $header, $match) ? trim($match[1]) : '';
    }

    public static function affected(array $ranges, string $version): bool
    {
        if ($version === '') {
            return false;
        }
        foreach ($ranges as [$low, $inclusiveLow, $high, $inclusiveHigh]) {
            if (($low === '*' || version_compare($version, $low, $inclusiveLow ? '>=' : '>')) &&
                ($high === '*' || version_compare($version, $high, $inclusiveHigh ? '<=' : '<'))) {
                return true;
            }
        }
        return false;
    }

    public static function traversal(string $value): bool
    {
        for ($pass = 0; $pass < 3; $pass++) {
            if (preg_match('~(?:^|/|\\\\)\.\.(?:/|\\\\|$)~', $value)) {
                return true;
            }
            $value = urldecode($value);
        }
        return false;
    }

    public static function matches(array $rule, array $server, array $get, array $post, ?string $page = null, bool $slashed = false): bool
    {
        if ($rule['mode'] === 'off' || ($rule['methods'] &&
            !in_array($server['REQUEST_METHOD'] ?? '', $rule['methods'], true))) {
            return false;
        }
        foreach ($rule['conditions'] as $condition) {
            $key = $condition['key'];
            $values = match ($condition['source']) {
                'header' => [$server['HTTP_' . str_replace('-', '_', strtoupper($key))] ?? null],
                'get' => [$get[$key] ?? null],
                'post' => [$post[$key] ?? null],
                'page' => $page !== null ? [$page] : [$post[$key] ?? null, $get[$key] ?? null],
            };
            $matched = false;
            foreach ($values as $value) {
                if ($condition['op'] === 'present') {
                    $matched = $matched || $value !== null;
                } elseif (is_string($value)) {
                    if ($slashed && $condition['source'] !== 'header') {
                        $value = stripslashes($value);
                    }
                    $matched = $matched || ($condition['op'] === 'equals'
                        ? $value === $condition['value'] : strlen($value) > 2048 || self::traversal($value));
                }
            }
            if (!$matched) {
                return false;
            }
        }
        return self::routeMatches($rule, $server, $get, $page) &&
            self::affected($rule['ranges'], self::version($rule['version_file'], $rule['component'] === 'core'));
    }

    private static function routeMatches(array $rule, array $server, array $get, ?string $page): bool
    {
        if ($rule['route'] === 'front') {
            return $page !== null || self::sameScript($server['SCRIPT_FILENAME'] ?? '', $rule['endpoint_file']);
        }
        if ($rule['route'] === 'plugin') {
            $path = rawurldecode(explode('?', $server['REQUEST_URI'] ?? '', 2)[0]);
            return $path === $rule['path'] || self::sameScript($server['SCRIPT_FILENAME'] ?? '', $rule['endpoint_file']);
        }
        if ($rule['route'] === 'rest') {
            $path = rawurldecode(explode('?', $server['REQUEST_URI'] ?? '', 2)[0]);
            $route = $get['rest_route'] ?? '';
            return strcasecmp(rtrim($path, '/'), $rule['path']) === 0 ||
                (is_string($route) && strcasecmp(rtrim($route, '/'), $rule['endpoint']) === 0);
        }
        return true;
    }

    private static function sameScript(string $actual, string $expected): bool
    {
        if ($actual === '') {
            return false;
        }
        $actual = str_replace('\\', '/', $actual);
        if ($actual === $expected) {
            return true;
        }
        $resolved = realpath($actual);
        return $resolved !== false && $resolved === realpath($expected);
    }
}
