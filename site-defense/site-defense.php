<?php
/**
 * Plugin Name: Site Defense
 * Description: Local WordPress login protection, vulnerability checks and file monitoring.
 * Version: 1.0.0
 * Update URI: https://github.com/KITH-web-studio/kith-site-defense
 * Requires at least: 6.8
 * Requires PHP: 8.2
 * Text Domain: site-defense
 * Domain Path: /languages
 */
namespace SiteDefense;

defined('ABSPATH') || exit;

define('SITE_DEFENSE_DIR', __DIR__);
foreach (['State', 'PluginUpdates', 'Incidents', 'Alerts', 'FileWatch', 'EarlyProtection', 'Firewall', 'Login', 'Hardening', 'WPVulnerability', 'Vulnerabilities', 'PhpAnalyzer', 'Malware', 'ScanReport', 'OfficialFiles', 'Scanner', 'StoredHtml', 'DbContentCleanup', 'DbAudit', 'Quarantine', 'FileRepair', 'LoginRoute', 'TwoFactor', 'ResponseMode', 'Heartbeat', 'Timeline', 'Kev', 'CronCleanup', 'CleanupPlan', 'RequestEvidence', 'RequestCorrelation', 'Investigation', 'CleanupVerification'] as $module) {
    require_once __DIR__ . '/includes/' . $module . '.php';
}

register_activation_hook(__FILE__, [State::class, 'activate']);
register_deactivation_hook(__FILE__, [State::class, 'deactivate']);
add_action('init', [State::class, 'loadTranslations'], -1001);
add_action('plugins_loaded', static function () {
    State::register();
    PluginUpdates::register();
    Incidents::register();
    Firewall::register();
    Alerts::register();
    FileWatch::register();
    EarlyProtection::register();
    Login::register();
    Hardening::register();
    ResponseMode::register();
    Heartbeat::register();
    Timeline::register();
    Vulnerabilities::register();
    Scanner::register();
    DbAudit::register();
    LoginRoute::register();
    TwoFactor::register();

    if (defined('WP_CLI') && WP_CLI) {
        require_once __DIR__ . '/includes/Cli.php';
        \WP_CLI::add_command('site-defense', Cli::class);
    }

    if (is_admin()) {
        require_once __DIR__ . '/includes/Admin.php';
        Admin::register();
    }
});

