<?php
defined('WP_UNINSTALL_PLUGIN') || exit;

require_once __DIR__ . '/includes/EarlyProtection.php';
\SiteDefense\EarlyProtection::disable();

global $wpdb;
// Preserve quarantined copies so files can still be recovered after reinstalling the plugin.
foreach (['events', 'limits', 'incidents', 'watched', 'scan_skips'] as $table) {
    $name = $wpdb->prefix . 'sd_' . $table;
    $wpdb->query("DROP TABLE IF EXISTS `$name`");
}
foreach (['sd_settings', 'sd_pending_route', 'sd_login_route', 'sd_scan', 'sd_debug_probe',
    'sd_vulnerability_db', 'sd_findings', 'sd_feed_status', 'sd_vulnerability_seen', 'sd_wpvulnerability_cache', 'sd_incident_schema', 'sd_watch_schema',
    'sd_watch', 'sd_alerts', 'sd_alert_worker', 'sd_waf_rules', 'sd_firewall',
    'sd_scan_report_schema', 'sd_scan_exclusions', 'sd_malware_rules', 'sd_db_audit', 'sd_db_audit_trusted',
    'sd_event_schema', 'sd_response_mode', 'sd_heartbeat', 'sd_heartbeat_status', 'sd_kev', 'sd_kev_seen'] as $option) {
    delete_option($option);
}
delete_metadata('user', 0, '_sd_totp', '', true);
foreach (['sd_daily', 'sd_scan_slice', 'sd_db_audit_slice', 'sd_check_versions', 'sd_alert_tick', 'sd_watch_tick', 'sd_watch_slice', 'sd_heartbeat_tick'] as $hook) {
    wp_clear_scheduled_hook($hook);
}

