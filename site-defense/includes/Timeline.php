<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Timeline
{
    private const KINDS = ['login_success', 'privileged_user', 'user_role', 'user_capabilities', 'application_password',
        'two_factor', 'plugin_activated', 'plugin_deactivated', 'component_updated', 'theme_switched', 'file_detected',
        'file_changed', 'file_quarantined', 'file_restored', 'file_repaired', 'file_repair_undone', 'session_revoked',
        'response_started', 'response_stopped', 'protection_changed', 'cleanup_applied', 'cleanup_undone'];

    public static function register(): void
    {
        add_action('activated_plugin', static function (string $file): void {
            State::log('plugin_activated', $file);
        });
        add_action('deactivated_plugin', static function (string $file): void {
            State::log('plugin_deactivated', $file);
        });
        add_action('switch_theme', static function (string $name, \WP_Theme $theme): void {
            State::log('theme_switched', $theme->get_stylesheet());
        }, 10, 2);
        add_action('upgrader_process_complete', static function ($upgrader, array $update): void {
            $type = $update['type'] ?? '';
            $action = $update['action'] ?? '';
            if (!in_array($action, ['install', 'update'], true) || !in_array($type, ['plugin', 'theme', 'core'], true)) {
                return;
            }
            $list = $update[$type . 's'] ?? $update[$type] ?? [];
            if (!$list && $action === 'install') {
                if ($type === 'plugin' && $upgrader instanceof \Plugin_Upgrader) {
                    $list = $upgrader->plugin_info();
                } elseif ($type === 'theme' && $upgrader instanceof \Theme_Upgrader) {
                    $theme = $upgrader->theme_info();
                    $list = $theme instanceof \WP_Theme ? $theme->get_stylesheet() : [];
                }
            }
            $items = array_filter((array) $list, 'is_string');
            foreach ($items ?: [$type] as $item) {
                State::log('component_updated', $type . ' · ' . $action . ' · ' . $item);
            }
        }, 10, 2);
    }

    public static function tracks(string $kind): bool
    {
        return in_array($kind, self::KINDS, true);
    }

    public static function context(array $context): array
    {
        $result = ['actor_id' => get_current_user_id()];
        if (!empty($context['user_id'])) {
            $result['user_id'] = absint($context['user_id']);
        }
        foreach (['path', 'finding', 'digest', 'application_uuid'] as $field) {
            if (is_string($context[$field] ?? null)) {
                $result[$field] = wp_html_excerpt(sanitize_text_field($context[$field]), 400, '');
            }
        }
        return $result;
    }

    public static function read(int $hours, int $limit): array
    {
        global $wpdb;
        $table = State::table('events');
        $context = get_option('sd_event_schema') === '2' ? 'context' : 'NULL AS context';
        $placeholders = implode(',', array_fill(0, count(self::KINDS), '%s'));
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT id,occurred,kind,detail,$context FROM $table WHERE occurred>=%d AND kind IN ($placeholders)
             ORDER BY occurred DESC,id DESC LIMIT %d", array_merge([time() - HOUR_IN_SECONDS * $hours], self::KINDS, [$limit])
        ), ARRAY_A) ?: [];
        foreach ($rows as &$row) {
            $row['id'] = (int) $row['id'];
            $row['occurred'] = (int) $row['occurred'];
            $row['context'] = json_decode((string) $row['context'], true) ?: [];
        }
        return $rows;
    }
}
