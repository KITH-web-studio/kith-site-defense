<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class State
{
    public const DEFAULTS = [
        'limit' => true, 'privacy' => false, 'xml_login' => false,
        'xml_pingback' => false, 'file_editor' => false, 'feed_auto' => true, 'wpvulnerability' => false, 'kev_auto' => true,
        'waf' => true, 'observe' => false, 'scan_auto' => false,
        'notify' => false, 'notify_types' => ['privileged_user', 'user_role', 'application_password', 'two_factor',
            'file_detected', 'file_changed', 'waf_block', 'login_limit', 'login_pressure', 'protection_changed', 'vulnerability_found'],
        'email' => '', 'proxy' => '', 'waf_exception' => '',
        'fast_watch' => true, 'require_2fa' => false, 'plugin_release_candidates' => false,
    ];

    public static function settings(): array
    {
        return array_replace(self::DEFAULTS, (array) get_option('sd_settings', []));
    }

    public static function enabled(string $name): bool
    {
        return !empty(self::settings()[$name]);
    }

    public static function table(string $name): string
    {
        global $wpdb;
        return $wpdb->prefix . 'sd_' . $name;
    }

    public static function activate(bool $network = false): void
    {
        if (is_multisite() || $network) {
            self::loadTranslations();
            wp_die(esc_html__('Site Defense currently supports single-site WordPress installations.', 'site-defense'));
        }
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        $limits = self::table('limits');
        self::installEvents();
        dbDelta("CREATE TABLE $limits (
            bucket char(64) NOT NULL,
            hits int unsigned NOT NULL,
            expires bigint unsigned NOT NULL,
            PRIMARY KEY  (bucket),
            KEY expires (expires)
        ) $charset;");
        if (!wp_next_scheduled('sd_daily')) {
            wp_schedule_event(time() + 60, 'daily', 'sd_daily');
        }
    }

    public static function deactivate(): void
    {
        EarlyProtection::disable();
        delete_option(ResponseMode::OPTION);
        foreach (['sd_daily', 'sd_scan_slice', 'sd_db_audit_slice', 'sd_check_versions', 'sd_alert_tick', 'sd_watch_tick', 'sd_watch_slice', Heartbeat::HOOK] as $hook) {
            wp_clear_scheduled_hook($hook);
        }
        delete_option('sd_pending_route');
    }

    public static function register(): void
    {
        if (get_option('sd_event_schema') !== '2') {
            self::installEvents();
        }
        add_action('sd_daily', [self::class, 'prune']);
    }

    private static function installEvents(): void
    {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $table = self::table('events');
        $charset = $wpdb->get_charset_collate();
        dbDelta("CREATE TABLE $table (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            occurred bigint unsigned NOT NULL,
            kind varchar(40) NOT NULL,
            detail varchar(240) NOT NULL,
            context text NULL,
            PRIMARY KEY  (id),
            KEY occurred (occurred)
        ) $charset;");
        if ($wpdb->get_var("SHOW COLUMNS FROM $table LIKE 'context'") === 'context') {
            update_option('sd_event_schema', '2');
        }
    }

    public static function loadTranslations(): void
    {
        $path = dirname(plugin_basename(SITE_DEFENSE_DIR . '/site-defense.php')) . '/languages';
        load_plugin_textdomain('site-defense', false, $path);
    }

    public static function roleLabel(string $role): string
    {
        return translate_user_role(wp_roles()->get_names()[$role] ?? $role);
    }

    public static function eventLabel(string $kind): string
    {
        return match ($kind) {
            'privileged_user' => __('New privileged account', 'site-defense'),
            'user_role' => __('User role change', 'site-defense'),
            'user_capabilities' => __('User capabilities changed', 'site-defense'),
            'application_password' => __('Application password created or revoked', 'site-defense'),
            'two_factor' => __('Two-factor setting changed', 'site-defense'),
            'login_limit' => __('Login throttling', 'site-defense'),
            'login_pressure' => __('Repeated login failures', 'site-defense'),
            'login_route' => __('Login address changed', 'site-defense'),
            'waf_block' => __('Request blocked by firewall', 'site-defense'),
            'waf_observe' => __('Suspicious request', 'site-defense'),
            'file_quarantined' => __('File quarantined', 'site-defense'),
            'file_restored' => __('File restored', 'site-defense'),
            'file_repaired' => __('File replaced with official copy', 'site-defense'),
            'file_repair_undone' => __('File repair undone', 'site-defense'),
            'cleanup_applied' => __('Cleanup step applied', 'site-defense'),
            'cleanup_undone' => __('Cleanup step undone', 'site-defense'),
            'file_detected' => __('Suspicious file detected', 'site-defense'),
            'file_changed' => __('Critical file changed', 'site-defense'),
            'vulnerability_found' => __('New vulnerability found', 'site-defense'),
            'vulnerability_escalated' => __('Known vulnerability is being exploited', 'site-defense'),
            'response_started' => __('Incident mode enabled', 'site-defense'),
            'response_stopped' => __('Incident mode disabled', 'site-defense'),
            'plugin_activated' => __('Plugin activated', 'site-defense'),
            'plugin_deactivated' => __('Plugin deactivated', 'site-defense'),
            'component_updated' => __('Component installed or updated', 'site-defense'),
            'theme_switched' => __('Theme changed', 'site-defense'),
            'session_revoked' => __('Browser sessions revoked', 'site-defense'),
            'login_success' => __('Privileged login', 'site-defense'),
            'protection_changed' => __('Protection settings changed', 'site-defense'),
            'notification_test' => __('Notification delivery test', 'site-defense'),
            default => $kind,
        };
    }

    public static function eventDetail(string $detail): string
    {
        // The journal stores language-neutral source messages, including rows from older versions.
        if (!preg_match('/^(.*?) #([0-9]+)(?: \(([a-z0-9_-]*)\))?$/D', $detail, $parts)) {
            return translate($detail, 'site-defense');
        }
        $userId = (int) $parts[2];
        // translators: %d is the WordPress user ID. In the role-change message, %2$s is the role name.
        return match ($parts[1]) {
            'New privileged user' => sprintf(__('New privileged user #%d', 'site-defense'), $userId),
            'Role change for user' => sprintf(__('Role change for user #%1$d (%2$s)', 'site-defense'), $userId, self::roleLabel($parts[3] ?? '')),
            'Capability metadata changed for user' => sprintf(__('Capability metadata changed for user #%d', 'site-defense'), $userId),
            'Application password created for user' => sprintf(__('Application password created for user #%d', 'site-defense'), $userId),
            'Application password revoked for user' => sprintf(__('Application password revoked for user #%d', 'site-defense'), $userId),
            'Two-factor authentication enabled for user' => sprintf(__('Two-factor authentication enabled for user #%d', 'site-defense'), $userId),
            'Two-factor authentication was disabled for user' => sprintf(__('Two-factor authentication was disabled for user #%d', 'site-defense'), $userId),
            'Browser sessions revoked for user' => sprintf(__('Browser sessions revoked for user #%d', 'site-defense'), $userId),
            'Privileged user signed in' => sprintf(__('Privileged user signed in #%d', 'site-defense'), $userId),
            'Database audit trusted user' => sprintf(__('Database audit confirmed user #%d', 'site-defense'), $userId),
            'Database audit removed trust for user' => sprintf(__('Database audit removed confirmation for user #%d', 'site-defense'), $userId),
            default => $detail,
        };
    }

    public static function log(string $kind, string $detail, bool $notify = false, array $context = [], ?int $observed = null): void
    {
        global $wpdb;
        $detail = wp_html_excerpt(sanitize_text_field($detail), 220, '');
        $row = ['occurred' => $observed ?? time(), 'kind' => $kind, 'detail' => $detail];
        $formats = ['%d', '%s', '%s'];
        $waf = RequestEvidence::isWaf($kind);
        if (get_option('sd_event_schema') === '2') {
            if ($waf) {
                $row['context'] = wp_json_encode(RequestEvidence::wafContext($context));
            } elseif (Timeline::tracks($kind)) {
                $row['context'] = wp_json_encode(Timeline::context($context));
            }
            if (isset($row['context'])) {
                $formats[] = '%s';
            }
        }
        $recorded = $wpdb->insert(self::table('events'), $row, $formats);
        if ($waf && $recorded && isset($row['context'])) {
            $context['request_event_id'] = $wpdb->insert_id;
        }
        self::pruneEvents();
        Incidents::record($kind, $detail, $context, $notify, $observed);
    }

    private static function pruneEvents(): void
    {
        global $wpdb;
        $events = self::table('events');
        $wpdb->query($wpdb->prepare("DELETE FROM $events WHERE occurred < %d", time() - 14 * DAY_IN_SECONDS));
        $oldest = $wpdb->get_var("SELECT id FROM $events ORDER BY id DESC LIMIT 1 OFFSET 9999");
        if ($oldest) {
            $wpdb->query($wpdb->prepare("DELETE FROM $events WHERE id < %d", $oldest));
        }
    }

    public static function prune(): void
    {
        global $wpdb;
        self::pruneEvents();
        $limits = self::table('limits');
        $wpdb->query($wpdb->prepare("DELETE FROM $limits WHERE expires <= %d", time()));
    }

    public static function field(array $data, string $key): string
    {
        return isset($data[$key]) && is_string($data[$key]) ? wp_unslash($data[$key]) : '';
    }
}

