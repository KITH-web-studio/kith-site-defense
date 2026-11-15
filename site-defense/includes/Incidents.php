<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Incidents
{
    public static function register(): void
    {
        if (get_option('sd_incident_schema') !== '1') {
            self::install();
        }
    }

    public static function install(): void
    {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $table = State::table('incidents');
        $charset = $wpdb->get_charset_collate();
        dbDelta("CREATE TABLE $table (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            fingerprint char(64) NOT NULL,
            kind varchar(40) NOT NULL,
            severity varchar(16) NOT NULL,
            detail varchar(240) NOT NULL,
            context text NOT NULL,
            first_seen bigint unsigned NOT NULL,
            last_seen bigint unsigned NOT NULL,
            hits bigint unsigned NOT NULL DEFAULT 1,
            pending tinyint unsigned NOT NULL DEFAULT 1,
            due bigint unsigned NOT NULL,
            delivery text NOT NULL,
            resolved tinyint unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            UNIQUE KEY fingerprint (fingerprint),
            KEY pending_due (pending,due),
            KEY last_seen (last_seen)
        ) $charset;");
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table))) === $table) {
            update_option('sd_incident_schema', '1');
        }
    }

    public static function record(string $kind, string $detail, array $context = [], bool $important = false, ?int $observed = null): void
    {
        if (!in_array($kind, [
            'login_limit', 'login_pressure', 'waf_block', 'waf_observe', 'privileged_user', 'user_role',
            'user_capabilities', 'application_password', 'two_factor', 'file_detected', 'file_changed',
            'file_quarantined', 'file_restored', 'session_revoked', 'login_success', 'protection_changed',
            'response_started', 'response_stopped',
        ], true)) {
            return;
        }
        global $wpdb;
        $table = State::table('incidents');
        $context = array_intersect_key($context, array_flip(['user_id', 'path', 'finding', 'digest', 'application_uuid', 'route', 'request_event_id']));
        $context['user_id'] = absint($context['user_id'] ?? 0);
        $context['actor_id'] = in_array($kind, ['waf_block', 'waf_observe'], true) ? 0 : get_current_user_id();
        $fingerprintContext = $context;
        unset($fingerprintContext['route'], $fingerprintContext['request_event_id']);
        $ip = Login::ip();
        if ($ip !== 'unknown') {
            $context['source_ip'] = $ip;
        }
        $urgent = $important || in_array($kind, ['file_detected', 'file_changed', 'privileged_user', 'two_factor', 'protection_changed'], true);
        $severity = in_array($kind, ['waf_block', 'login_limit', 'login_pressure'], true) ? 'blocked' : ($urgent ? 'review' : 'info');
        $now = $observed ?? time();
        // Attack summaries are grouped into five-minute windows. File events retain their digest.
        $bucket = $severity === 'blocked' ? intdiv($now, 300) : intdiv($now, DAY_IN_SECONDS);
        $fingerprint = hash('sha256', $kind . '|' . $detail . '|' . wp_json_encode($fingerprintContext) . '|' . $bucket);
        $due = $severity === 'blocked' ? ($bucket + 1) * 300 : $now;
        $wpdb->query($wpdb->prepare(
            "INSERT INTO $table (fingerprint,kind,severity,detail,context,first_seen,last_seen,hits,pending,due,delivery)
             VALUES (%s,%s,%s,%s,%s,%d,%d,1,1,%d,'{}')
             ON DUPLICATE KEY UPDATE hits=hits+1,context=IF(last_seen<=VALUES(last_seen),VALUES(context),context),
               first_seen=LEAST(first_seen,VALUES(first_seen)),last_seen=GREATEST(last_seen,VALUES(last_seen)),
               pending=1,resolved=0,due=LEAST(due,VALUES(due))",
            $fingerprint, $kind, $severity, wp_html_excerpt($detail, 220, ''), wp_json_encode($context), $now, $now, $due
        ));
    }

    public static function get(int $id): ?array
    {
        global $wpdb;
        $table = State::table('incidents');
        return $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id=%d", $id), ARRAY_A) ?: null;
    }

    public static function recordVulnerability(string $fingerprint, array $finding, string $kind = 'vulnerability_found'): bool
    {
        global $wpdb;
        $table = State::table('incidents');
        $now = time();
        $detail = wp_html_excerpt(sanitize_text_field($finding['title']), 220, '');
        $context = array_intersect_key($finding, array_flip(['key', 'version', 'id', 'title', 'cve', 'score', 'fixed', 'link', 'kev', 'kev_cve']));
        return $wpdb->query($wpdb->prepare(
            "INSERT INTO $table (fingerprint,kind,severity,detail,context,first_seen,last_seen,hits,pending,due,delivery)
             VALUES (%s,%s,'review',%s,%s,%d,%d,1,1,%d,'{}')
             ON DUPLICATE KEY UPDATE id=id",
            $fingerprint, $kind, $detail, wp_json_encode(['vulnerability' => $context]), $now, $now, $now
        )) !== false;
    }

    public static function recent(int $page): array
    {
        global $wpdb;
        $table = State::table('incidents');
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM $table ORDER BY last_seen DESC,id DESC LIMIT 26 OFFSET %d", ($page - 1) * 25
        ), ARRAY_A) ?: [];
    }

    public static function respond(int $id, string $task): string
    {
        $incident = self::get($id);
        if (!$incident) {
            return __('Incident not found.', 'site-defense');
        }
        $context = json_decode($incident['context'], true) ?: [];
        $userId = absint($context['user_id'] ?? 0);
        if ($task === 'incident_sessions' || $task === 'incident_password') {
            if (!$userId || (!(defined('WP_CLI') && WP_CLI) && !current_user_can('edit_user', $userId))) {
                return __('Permission denied.', 'site-defense');
            }
            if ($task === 'incident_sessions') {
                \WP_Session_Tokens::get_instance($userId)->destroy_all();
                State::log('session_revoked', 'Browser sessions revoked for user #' . $userId, context: ['user_id' => $userId]);
                return __('Browser sessions revoked.', 'site-defense');
            }
            $uuid = $context['application_uuid'] ?? '';
            if (!is_string($uuid) || !wp_is_uuid($uuid)) {
                return __('No application password is attached to this incident.', 'site-defense');
            }
            $result = \WP_Application_Passwords::delete_application_password($userId, $uuid);
            return is_wp_error($result) ? __('The password could not be revoked.', 'site-defense') : __('Application password revoked.', 'site-defense');
        }
        if ($task === 'incident_scan') {
            return Scanner::command('start');
        }
        if ($task === 'incident_quarantine' && Quarantine::available() && !empty($context['path'])) {
            return Quarantine::moveFinding([
                $context['finding'] ?? 'Executable file in uploads', $context['path'], $context['digest'] ?? null,
            ]);
        }
        if ($task === 'incident_resolve') {
            global $wpdb;
            $wpdb->update(State::table('incidents'), ['resolved' => 1], ['id' => $id], ['%d'], ['%d']);
            return __('Incident marked as reviewed.', 'site-defense');
        }
        return __('Invalid or unauthorized request.', 'site-defense');
    }
}

