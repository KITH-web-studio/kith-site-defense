<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class ScanReport
{
    public const PAGE_SIZE = 50;

    public static function start(): bool
    {
        global $wpdb;
        $table = State::table('scan_skips');
        if (get_option('sd_scan_report_schema') !== '1') {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            $charset = $wpdb->get_charset_collate();
            dbDelta("CREATE TABLE $table (
                id bigint unsigned NOT NULL AUTO_INCREMENT,
                scan_id varchar(36) NOT NULL,
                path text NOT NULL,
                reason varchar(120) NOT NULL,
                bytes bigint unsigned NOT NULL DEFAULT 0,
                partial tinyint unsigned NOT NULL DEFAULT 0,
                scope varchar(16) NOT NULL DEFAULT 'file',
                PRIMARY KEY  (id),
                KEY scan_id (scan_id,id)
            ) $charset;");
            if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table))) !== $table) {
                return false;
            }
            update_option('sd_scan_report_schema', '1', false);
        }
        return $wpdb->query("DELETE FROM $table") !== false;
    }

    public static function skipped(array &$scan, string $path, string $reason, int $bytes = 0, bool $partial = false, string $scope = 'file'): void
    {
        global $wpdb;
        $scan['skipped_count'] = ($scan['skipped_count'] ?? 0) + 1;
        $scan['skip_reasons'][$reason] = ($scan['skip_reasons'][$reason] ?? 0) + 1;
        if ($wpdb->insert(State::table('scan_skips'), [
            'scan_id' => $scan['id'], 'path' => Scanner::relativePath($path), 'reason' => $reason,
            'bytes' => max(0, $bytes), 'partial' => (int) $partial, 'scope' => $scope,
        ], ['%s', '%s', '%s', '%d', '%d', '%s']) === false) {
            $scan['report_error'] = true;
        }
    }

    public static function skippedPage(array $scan, int $page): array
    {
        if (empty($scan['id']) || get_option('sd_scan_report_schema') !== '1') {
            return [];
        }
        global $wpdb;
        $table = State::table('scan_skips');
        return $wpdb->get_results($wpdb->prepare(
            "SELECT id,path,reason,bytes,partial,scope FROM $table WHERE scan_id=%s ORDER BY id LIMIT %d OFFSET %d",
            $scan['id'], self::PAGE_SIZE + 1, ($page - 1) * self::PAGE_SIZE
        ), ARRAY_A) ?: [];
    }

    public static function exclusions(): array
    {
        return (array) get_option('sd_scan_exclusions', []);
    }

    public static function excludedDigest(string $path): ?string
    {
        return self::exclusions()[hash('sha256', Scanner::relativePath($path))]['sha256'] ?? null;
    }

    public static function exclude(string $selector): string
    {
        return Scanner::locked(static function () use ($selector): string {
            foreach (get_option('sd_scan', [])['findings'] ?? [] as $finding) {
                if (hash_equals(Quarantine::selector($finding), $selector) &&
                    is_string($finding[2] ?? null) && preg_match('/^[a-f0-9]{64}$/D', $finding[2])) {
                    $location = Quarantine::resolve($finding[1]);
                    if (!$location || !is_file($location[0]) || is_link($location[0]) ||
                        !hash_equals($finding[2], (string) @hash_file('sha256', $location[0]))) {
                        return __('The file changed since it was scanned. Scan it again before moving it.', 'site-defense');
                    }
                    $entries = self::exclusions();
                    $key = hash('sha256', Scanner::relativePath($location[0]));
                    if (count($entries) >= 1000 && !isset($entries[$key])) {
                        return __('The hash exclusion limit has been reached.', 'site-defense');
                    }
                    $entries[$key] = ['path' => Scanner::relativePath($location[0]), 'sha256' => $finding[2], 'created' => time()];
                    if ($entries !== self::exclusions() && !update_option('sd_scan_exclusions', $entries, false)) {
                        return __('Unable to save hash exclusions.', 'site-defense');
                    }
                    State::log('protection_changed', 'Hash exclusion added', true, ['path' => $finding[1]]);
                    return __('Hash exclusion saved.', 'site-defense');
                }
            }
            return __('This finding is no longer available. Scan again before quarantining the file.', 'site-defense');
        });
    }

    public static function remove(string $key): string
    {
        return Scanner::locked(static function () use ($key): string {
            $entries = self::exclusions();
            if (!isset($entries[$key])) {
                return __('Hash exclusion not found.', 'site-defense');
            }
            unset($entries[$key]);
            if (!update_option('sd_scan_exclusions', $entries, false)) {
                return __('Unable to save hash exclusions.', 'site-defense');
            }
            State::log('protection_changed', 'Hash exclusion removed', true);
            return __('Hash exclusion removed.', 'site-defense');
        });
    }
}
