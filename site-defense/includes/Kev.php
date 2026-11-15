<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Kev
{
    private const URL = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
    private const MAX_BODY = 4 * 1024 * 1024;

    public static function cache(): array
    {
        return array_replace(['released' => '', 'attempt' => 0, 'success' => 0, 'entries' => [], 'error' => false],
            (array) get_option('sd_kev', []));
    }

    public static function refresh(bool $force = false): string
    {
        global $wpdb;
        $lock = 'sd-kev-' . md5($wpdb->options);
        if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $lock)) !== 1) {
            return __('CISA KEV update is already running.', 'site-defense');
        }
        try {
            wp_cache_delete('sd_kev', 'options');
            return self::refreshLocked($force);
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }

    private static function refreshLocked(bool $force): string
    {
        $cache = self::cache();
        $now = time();
        if (!$force && $cache['attempt'] > $now - 23 * HOUR_IN_SECONDS) {
            return $cache['error'] ? __('Unable to refresh CISA KEV.', 'site-defense') : __('CISA KEV is current.', 'site-defense');
        }
        $response = wp_safe_remote_get(self::URL, [
            'timeout' => 5, 'redirection' => 0, 'limit_response_size' => self::MAX_BODY + 1,
            'user-agent' => 'Site Defense CISA KEV check', 'headers' => ['Accept' => 'application/json'],
        ]);
        $body = wp_remote_retrieve_body($response);
        $document = wp_remote_retrieve_response_code($response) === 200 && strlen($body) <= self::MAX_BODY
            ? json_decode($body, true, 24) : null;
        $released = $document['dateReleased'] ?? '';
        $rows = $document['vulnerabilities'] ?? null;
        $entries = [];
        if (is_string($released) && preg_match('/^\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[-+]\d{2}:\d{2})$/D', $released) &&
            strtotime($released) >= strtotime($cache['released']) && strtotime($released) <= $now + DAY_IN_SECONDS &&
            is_array($rows) && array_is_list($rows) && count($rows) === ($document['count'] ?? null)) {
            foreach ($rows as $row) {
                $cve = $row['cveID'] ?? '';
                $date = $row['dateAdded'] ?? '';
                if (!is_string($cve) || !preg_match('/^CVE-\d{4}-\d{4,}$/D', $cve) ||
                    !is_string($date) || !preg_match('/^\d{4}-\d{2}-\d{2}$/D', $date)) {
                    $entries = [];
                    break;
                }
                $entries[$cve] = $date;
            }
        }
        $cache['attempt'] = $now;
        $cache['error'] = !$entries;
        if ($entries) {
            $cache['released'] = $released;
            $cache['success'] = $now;
            $cache['entries'] = $entries;
        }
        update_option('sd_kev', $cache, false);
        return $entries ? __('CISA KEV is current.', 'site-defense') : __('Unable to refresh CISA KEV.', 'site-defense');
    }
}
