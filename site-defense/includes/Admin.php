<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Admin
{
    private const OPTIONS = [
        'limit' => 'Limit login attempts and unify credential errors',
        'privacy' => 'Require authentication for WordPress REST user profiles',
        'xml_login' => 'Disable authenticated XML-RPC methods',
        'xml_pingback' => 'Disable incoming XML-RPC pingbacks',
        'file_editor' => 'Disable editing PHP files in the dashboard',
        'feed_auto' => 'Download vulnerability database updates daily',
        'wpvulnerability' => 'Check WPVulnerability daily',
        'kev_auto' => 'Check CISA KEV daily',
        'waf' => 'Block known exploits with tested rules',
        'observe' => 'Log possible injections and executable uploads',
        'scan_auto' => 'Schedule a daily file scan',
        'notify' => 'Send email notifications',
        'fast_watch' => 'Check critical file changes every five minutes',
        'require_2fa' => 'Require two-factor authentication for privileged accounts',
    ];

    private const SETTINGS_GROUPS = [
        'protection' => ['privacy', 'xml_login', 'xml_pingback', 'file_editor'],
        'firewall' => ['waf', 'observe'],
        'login' => ['limit', 'require_2fa'],
        'vulnerabilities' => ['feed_auto', 'wpvulnerability', 'kev_auto'],
        'files' => ['scan_auto', 'fast_watch'],
        'notifications' => ['notify'],
    ];

    private const MAIL_EVENTS = [
        'privileged_user' => 'New privileged account', 'user_role' => 'User role change',
        'application_password' => 'Application password created or revoked', 'two_factor' => 'Two-factor setting changed',
        'file_detected' => 'Suspicious file detected', 'file_changed' => 'Critical file changed',
        'waf_block' => 'Request blocked by firewall', 'login_limit' => 'Login throttling',
        'login_pressure' => 'Repeated login failures', 'user_capabilities' => 'User capabilities changed',
        'protection_changed' => 'Protection settings changed',
        'vulnerability_found' => 'New vulnerability found',
        'response_started' => 'Incident mode enabled',
        'response_stopped' => 'Incident mode disabled',
    ];

    public static function register(): void
    {
        add_action('admin_menu', static function (): void {
            if (($GLOBALS['pagenow'] ?? '') === 'admin.php' && State::field($_GET, 'page') === 'site-defense-db-audit' &&
                current_user_can('manage_options')) {
                $page = absint(State::field($_GET, 'db_page'));
                wp_safe_redirect(self::url('database', $page > 1 ? ['db_page' => $page] : []));
                exit;
            }
            add_menu_page('Site Defense', 'Site Defense', 'manage_options', 'site-defense', [self::class, 'page'], 'dashicons-shield');
        });
        add_action('admin_enqueue_scripts', static function (string $screen): void {
            if ($screen === 'toplevel_page_site-defense') {
                wp_enqueue_style('site-defense-admin', plugins_url('assets/admin.css', SITE_DEFENSE_DIR . '/site-defense.php'), [], '0.7.0');
            }
        });
        add_action('admin_post_sd_action', [self::class, 'action']);
    }

    public static function action(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Permission denied.', 'site-defense'), '', ['response' => 403]);
        }
        $task = sanitize_key(State::field($_POST, 'task'));
        $fileAction = in_array($task, ['quarantine_file', 'restore_file', 'exclude_file', 'remove_exclusion'], true) ||
            str_starts_with($task, 'incident_') || str_starts_with($task, 'repair_');
        $accountAction = in_array($task, ['db_trust', 'db_untrust'], true);
        $selection = ($fileAction || $accountAction) ? State::field($_POST, 'selection') : '';
        check_admin_referer('sd_' . $task . ($fileAction || $accountAction ? ':' . $selection : ''));
        if ($accountAction && (!current_user_can('promote_users') || State::field($_POST, 'confirm') !== 'yes')) {
            wp_die(esc_html__('Invalid or unauthorized request.', 'site-defense'), '', ['response' => 403]);
        }
        if (in_array($task, ['response_start', 'response_stop'], true) &&
            (!current_user_can('promote_users') || State::field($_POST, 'confirm') !== 'yes')) {
            wp_die(esc_html__('Invalid or unauthorized request.', 'site-defense'), '', ['response' => 403]);
        }
        if (in_array($task, ['rules_import', 'rules_rollback', 'rules_mode'], true) && !Quarantine::available()) {
            wp_die(esc_html__('Permission denied.', 'site-defense'), '', ['response' => 403]);
        }
        if ($fileAction && (!Quarantine::available() ||
            (!in_array($task, ['repair_preview', 'repair_discard'], true) && State::field($_POST, 'confirm') !== 'yes'))) {
            wp_die(esc_html__('Invalid or unauthorized request.', 'site-defense'), '', ['response' => 403]);
        }
        if (in_array($task, ['early_install', 'early_disable'], true) &&
            (!Quarantine::available() || State::field($_POST, 'confirm') !== 'yes')) {
            wp_die(esc_html__('Invalid or unauthorized request.', 'site-defense'), '', ['response' => 403]);
        }
        $message = '';
        $user = get_current_user_id();
        $tab = self::actionTab($task);
        switch ($task) {
            case 'db_start':
                $message = DbAudit::start();
                break;
            case 'db_trust':
                [$id, $fingerprint] = array_pad(explode(':', $selection, 2), 2, '');
                $message = DbAudit::trust(absint($id), $fingerprint);
                break;
            case 'db_untrust':
                $message = DbAudit::untrust(absint($selection));
                break;
            case 'settings':
                $group = State::field($_POST, 'settings_group');
                if ($group !== '' && !isset(self::SETTINGS_GROUPS[$group])) {
                    wp_die(esc_html__('Invalid or unauthorized request.', 'site-defense'), '', ['response' => 400]);
                }
                $tab = $group ?: 'protection';
                $message = self::saveSettings($group, $user);
                break;
            case 'plugin_channel':
                $channel = State::field($_POST, 'channel');
                if (!in_array($channel, ['stable', 'rc'], true)) {
                    wp_die(esc_html__('Invalid or unauthorized request.', 'site-defense'), '', ['response' => 400]);
                }
                $settings = State::settings();
                $settings['plugin_release_candidates'] = $channel === 'rc';
                update_option('sd_settings', $settings, true);
                $message = __('Settings saved.', 'site-defense');
                break;
            case 'channels':
                $message = Alerts::save($_POST);
                break;
            case 'test_channels':
                $message = Alerts::test();
                break;
            case 'heartbeat_save':
                $message = Heartbeat::save($_POST);
                break;
            case 'heartbeat_send':
                $message = Heartbeat::send();
                break;
            case 'response_preview':
            case 'response_start':
            case 'response_stop':
            case 'response_cancel':
                $message = self::responseAction($task, $user);
                break;
            case 'incident_sessions':
            case 'incident_password':
            case 'incident_scan':
            case 'incident_quarantine':
            case 'incident_resolve':
                $message = Incidents::respond(absint($selection), $task);
                break;
            case 'early_install':
                $message = EarlyProtection::install();
                break;
            case 'early_disable':
                EarlyProtection::disable();
                $message = __('Early protection disabled.', 'site-defense');
                break;
            case 'early_verify':
                $message = EarlyProtection::verify();
                break;
            case 'rules_import':
                $file = $_FILES['rules'] ?? [];
                $message = __('Choose a valid signed database package.', 'site-defense');
                if (is_string($file['tmp_name'] ?? null) && is_uploaded_file($file['tmp_name']) &&
                    (int) ($file['size'] ?? 0) < 1024 * 1024) {
                    $message = EarlyProtection::import((string) file_get_contents($file['tmp_name']));
                }
                break;
            case 'rules_rollback':
                if (State::field($_POST, 'confirm') !== 'yes') {
                    wp_die(esc_html__('Invalid or unauthorized request.', 'site-defense'), '', ['response' => 403]);
                }
                $message = Firewall::rollback();
                break;
            case 'rules_mode':
                $message = Firewall::setMode(State::field($_POST, 'rule_id'), State::field($_POST, 'mode'));
                break;
            case 'malware_import':
                $file = $_FILES['malware_package'] ?? [];
                $message = __('Choose a valid signed database package.', 'site-defense');
                if (current_user_can('update_plugins') && is_string($file['tmp_name'] ?? null) &&
                    is_uploaded_file($file['tmp_name']) && (int) ($file['size'] ?? 0) <= 1024 * 1024) {
                    $message = Malware::import((string) file_get_contents($file['tmp_name']));
                }
                break;
            case 'watch_now':
                FileWatch::start();
                $message = __('A file change check is queued.', 'site-defense');
                break;
            case 'clear_limits':
                global $wpdb;
                $table = State::table('limits');
                $wpdb->query("DELETE FROM $table");
                $message = __('Login limits reset.', 'site-defense');
                break;
            case 'check':
                Vulnerabilities::schedule();
                $message = __('A vulnerability check is queued.', 'site-defense');
                break;
            case 'update':
                $message = Vulnerabilities::refresh();
                break;
            case 'kev_refresh':
                if (State::enabled('kev_auto')) {
                    $message = Kev::refresh(true);
                    Vulnerabilities::schedule();
                }
                break;
            case 'import':
                $file = $_FILES['package'] ?? [];
                if (!empty($file['tmp_name']) && is_string($file['tmp_name']) &&
                    is_uploaded_file($file['tmp_name']) && (int) $file['size'] < 70 * 1024 * 1024) {
                    $message = Vulnerabilities::import((string) file_get_contents($file['tmp_name']));
                } else {
                    $message = __('Choose a valid signed database package.', 'site-defense');
                }
                break;
            case 'start':
            case 'cancel':
            case 'resume':
                $message = Scanner::command($task);
                break;
            case 'quarantine_file':
                $message = Quarantine::move($selection);
                break;
            case 'restore_file':
                $message = Quarantine::restore(absint($selection));
                break;
            case 'repair_preview':
            case 'repair_apply':
            case 'repair_discard':
            case 'repair_undo':
                $message = self::repairAction($task, $selection, $user);
                break;
            case 'exclude_file':
                $message = ScanReport::exclude($selection);
                break;
            case 'remove_exclusion':
                $message = ScanReport::remove($selection);
                break;
            case 'debug':
                update_option('sd_debug_probe', ['result' => Hardening::debugLog(), 'time' => time()], false);
                $message = __('Debug log check finished.', 'site-defense');
                break;
            case 'route':
                $message = LoginRoute::propose(State::field($_POST, 'slug'), $user);
                break;
            case 'clear_route':
                delete_option('sd_login_route');
                delete_option('sd_pending_route');
                $message = __('Standard login address restored.', 'site-defense');
                break;
            case 'cancel_route':
                delete_option('sd_pending_route');
                $message = __('Pending address change cancelled.', 'site-defense');
                break;
            case 'setup_totp':
                if (!is_ssl() || !function_exists('sodium_crypto_secretbox')) {
                    $message = __('Two-factor enrollment requires HTTPS and PHP Sodium.', 'site-defense');
                    break;
                }
                if (get_user_meta($user, '_sd_totp', true)) {
                    break;
                }
                set_transient('sd_enroll_' . $user, TwoFactor::secret(), 600);
                $message = __('Enter the setup key in your authenticator, then verify a code.', 'site-defense');
                break;
            case 'confirm_totp':
                if (!is_ssl() || get_user_meta($user, '_sd_totp', true)) {
                    break;
                }
                $codes = TwoFactor::enroll($user, trim(State::field($_POST, 'code')));
                if ($codes) {
                    self::showCodes($codes);
                }
                $message = __('Invalid code or expired setup.', 'site-defense');
                break;
            case 'disable_totp':
                if (State::enabled('require_2fa') && Hardening::privileged(wp_get_current_user())) {
                    $message = __('Disable the mandatory two-factor policy before removing your second factor.', 'site-defense');
                    break;
                }
                if (get_user_meta($user, '_sd_totp', true) && wp_check_password(
                    State::field($_POST, 'password'), wp_get_current_user()->user_pass, $user
                )) {
                    delete_user_meta($user, '_sd_totp');
                    State::log('two_factor', 'Two-factor authentication was disabled for user #' . $user, true, ['user_id' => $user]);
                    $message = __('Two-factor authentication disabled.', 'site-defense');
                } else {
                    $message = __('Current password did not match.', 'site-defense');
                }
                break;
            case 'revoke':
                $id = absint(State::field($_POST, 'user_id'));
                $target = get_userdata($id);
                $uuid = State::field($_POST, 'uuid');
                if (!$target || !current_user_can('edit_user', $id) || !Hardening::privileged($target) ||
                    !wp_is_uuid($uuid) || State::field($_POST, 'confirm') !== 'yes') {
                    wp_die(esc_html__('Invalid or unauthorized request.', 'site-defense'), '', ['response' => 403]);
                }
                $result = \WP_Application_Passwords::delete_application_password($id, $uuid);
                $message = is_wp_error($result) ? __('The password could not be revoked.', 'site-defense') : __('Application password revoked.', 'site-defense');
                break;
        }
        set_transient('sd_notice_' . $user, $message, 90);
        wp_safe_redirect(self::url($tab));
        exit;
    }

    private static function saveSettings(string $group, int $user): string
    {
        $keys = $group === '' ? array_keys(self::OPTIONS) : self::SETTINGS_GROUPS[$group];
        if (in_array('require_2fa', $keys, true) && isset($_POST['require_2fa']) &&
            (!is_ssl() || !function_exists('sodium_crypto_secretbox'))) {
            return __('Two-factor enrollment requires HTTPS and PHP Sodium.', 'site-defense');
        }
        $settings = State::settings();
        $wasExternalEnabled = $settings['wpvulnerability'];
        foreach ($keys as $key) {
            $settings[$key] = isset($_POST[$key]);
        }
        if ($group === '' || $group === 'notifications') {
            $settings['email'] = sanitize_email(State::field($_POST, 'email'));
            $types = isset($_POST['notify_types']) && is_array($_POST['notify_types']) ? $_POST['notify_types'] : [];
            $settings['notify_types'] = array_values(array_intersect(array_keys(self::MAIL_EVENTS), array_filter($types, 'is_string')));
        }
        if ($group === '' || $group === 'protection') {
            $proxy = trim(State::field($_POST, 'proxy'));
            $settings['proxy'] = filter_var($proxy, FILTER_VALIDATE_IP) ? $proxy : '';
        }
        update_option('sd_settings', $settings, true);
        if ($settings['wpvulnerability'] !== $wasExternalEnabled) {
            Vulnerabilities::schedule();
        }
        State::log('protection_changed', 'Protection settings changed', true, ['user_id' => $user]);
        return __('Settings saved.', 'site-defense');
    }

    private static function actionTab(string $task): string
    {
        if (str_starts_with($task, 'db_')) {
            return 'database';
        }
        if (str_starts_with($task, 'incident_') || str_starts_with($task, 'response_')) {
            return 'incidents';
        }
        if (str_starts_with($task, 'rules_') || str_starts_with($task, 'early_')) {
            return 'firewall';
        }
        return match ($task) {
            'channels', 'test_channels', 'heartbeat_save', 'heartbeat_send' => 'notifications',
            'clear_limits', 'route', 'clear_route', 'cancel_route', 'setup_totp', 'confirm_totp', 'disable_totp', 'revoke' => 'login',
            'check', 'update', 'import', 'kev_refresh' => 'vulnerabilities',
            'watch_now', 'start', 'cancel', 'resume', 'quarantine_file', 'restore_file', 'exclude_file',
                'remove_exclusion', 'malware_import', 'repair_preview', 'repair_apply', 'repair_discard', 'repair_undo' => 'files',
            default => 'protection',
        };
    }

    private static function url(string $tab, array $args = []): string
    {
        return add_query_arg(['page' => 'site-defense', 'tab' => $tab] + $args, admin_url('admin.php'));
    }

    private static function showCodes(array $codes): never
    {
        nocache_headers();
        State::log('two_factor', 'Two-factor authentication enabled for user #' . get_current_user_id(), true, ['user_id' => get_current_user_id()]);
        $body = '<p>' . esc_html__('Save these recovery codes now. Each can be used once.', 'site-defense') . '</p><ul>';
        foreach ($codes as $code) {
            $body .= '<li><code>' . esc_html($code) . '</code></li>';
        }
        $body .= '</ul><p><a href="' . esc_url(self::url('login')) . '">' . esc_html__('Return to Site Defense', 'site-defense') . '</a></p>';
        wp_die($body, __('Two-factor recovery codes', 'site-defense'), ['response' => 200]);
    }

    private static function form(string $task, string $fields, string $label, bool $multipart = false, bool $primary = false, string $selection = ''): void
    {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"' . ($multipart ? ' enctype="multipart/form-data"' : '') . '>';
        echo '<input type="hidden" name="action" value="sd_action"><input type="hidden" name="task" value="' . esc_attr($task) . '">';
        wp_nonce_field('sd_' . $task . ($selection === '' ? '' : ':' . $selection));
        if ($selection !== '') {
            echo '<input type="hidden" name="selection" value="' . esc_attr($selection) . '">';
        }
        echo $fields;
        echo ' <button class="button' . ($primary ? ' button-primary' : '') . '">' . esc_html($label) . '</button></form>';
    }

    private static function time(int $timestamp): string
    {
        return $timestamp ? wp_date(get_option('date_format') . ' ' . get_option('time_format'), $timestamp) : __('Never', 'site-defense');
    }

    public static function page(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $tabs = [
            'protection' => __('Protection', 'site-defense'),
            'firewall' => 'WAF',
            'login' => __('Login', 'site-defense'),
            'vulnerabilities' => __('Vulnerabilities', 'site-defense'),
            'files' => __('Files', 'site-defense'),
            'database' => __('Database audit', 'site-defense'),
            'incidents' => __('Incidents', 'site-defense'),
            'notifications' => __('Notifications', 'site-defense'),
        ];
        $tab = State::field($_GET, 'tab');
        if (!isset($tabs[$tab])) {
            $tab = match (true) {
                isset($_GET['incident']) || isset($_GET['incidents_page']) || isset($_GET['journal_page']) => 'incidents',
                isset($_GET['skip_page']) || isset($_GET['quarantine_page']) => 'files',
                isset($_GET['accounts_page']) => 'login',
                default => 'protection',
            };
        }
        echo '<div class="wrap site-defense' . ($tab === 'database' ? ' sd-db-audit' : '') . '"><h1>Site Defense</h1>';
        echo '<nav class="nav-tab-wrapper sd-tabs" aria-label="Site Defense">';
        foreach ($tabs as $id => $label) {
            $active = $id === $tab;
            echo '<a class="nav-tab' . ($active ? ' nav-tab-active' : '') . '" href="' . esc_url(self::url($id)) . '"' .
                ($active ? ' aria-current="page"' : '') . '>' . esc_html($label) . '</a>';
        }
        echo '</nav>';
        self::notice();
        switch ($tab) {
            case 'firewall':
                self::firewallRules();
                self::earlyProtection();
                break;
            case 'login':
                self::login();
                self::access();
                break;
            case 'vulnerabilities':
                self::vulnerabilities();
                break;
            case 'files':
                $canQuarantine = Quarantine::available();
                $quarantine = $canQuarantine && Quarantine::install();
                if ($quarantine) {
                    self::repairPreview();
                }
                self::scanner($quarantine);
                if ($quarantine) {
                    self::quarantine();
                } elseif ($canQuarantine) {
                    echo '<p>' . esc_html__('Quarantine storage is unavailable.', 'site-defense') . '</p>';
                }
                self::fileMonitoring();
                break;
            case 'database':
                self::databaseAudit();
                break;
            case 'incidents':
                self::responseMode();
                self::incidents();
                self::timeline();
                self::journal();
                break;
            case 'notifications':
                self::notifications();
                self::heartbeat();
                break;
            default:
                self::settings();
                break;
        }
        echo '</div>';
    }

    private static function notice(): void
    {
        $notice = get_transient('sd_notice_' . get_current_user_id());
        delete_transient('sd_notice_' . get_current_user_id());
        if ($notice) {
            echo '<div class="notice notice-info"><p>' . esc_html(translate($notice, 'site-defense')) . '</p></div>';
        }
    }

    private static function databaseAudit(): void
    {
        $report = DbAudit::report();
        $status = match ($report['status'] ?? 'idle') {
            'running' => __('Running', 'site-defense'),
            'complete' => __('Complete', 'site-defense'),
            'failed' => __('Database audit failed. Check database access and try again.', 'site-defense'),
            default => __('Not started', 'site-defense'),
        };
        $findings = $report['findings'] ?? [];
        $total = array_sum($report['counts'] ?? []);
        $skipped = array_sum($report['skipped'] ?? []);
        echo '<h2>' . esc_html__('Database audit', 'site-defense') . '</h2>';
        echo '<p>' . esc_html__('Review privileged accounts, WP-Cron, stored scripts and redirects.', 'site-defense') . '</p>';
        echo '<p><strong>' . esc_html($status) . '</strong> · ' . esc_html(self::time((int) ($report['finished'] ?? 0))) . '</p>';
        if (($report['status'] ?? '') === 'running') {
            echo '<p>' . esc_html__('The audit is running in the background. Refresh this page for progress.', 'site-defense') . '</p>';
            echo '<p><a class="button" href="' . esc_url(self::url('database')) . '">' . esc_html__('Refresh results', 'site-defense') . '</a></p>';
        } else {
            self::form('db_start', '', __('Start database audit', 'site-defense'), false, true);
        }
        echo '<div class="sd-audit-metrics">';
        foreach ([
            __('Records and scheduled events checked', 'site-defense') => array_sum($report['checked'] ?? []),
            __('Findings', 'site-defense') => $total,
            __('Skipped by audit limits', 'site-defense') => $skipped,
        ] as $label => $count) {
            echo '<div><strong>' . esc_html(number_format_i18n($count)) . '</strong><span>' . esc_html($label) . '</span></div>';
        }
        echo '</div>';
        if ($total > count($findings)) {
            echo '<p>' . esc_html__('The report lists the first 500 findings. The counters include all matches.', 'site-defense') . '</p>';
        }
        if ($skipped) {
            echo '<p>' . esc_html__('Some values exceeded the audit limits. The WP-CLI status lists skipped values by source.', 'site-defense') . '</p>';
        }
        echo '<h2 id="sd-db-findings">' . esc_html__('Database findings', 'site-defense') . '</h2>';
        echo '<p>' . esc_html__('A finding needs review. Some plugins register their cron callbacks only in certain requests.', 'site-defense') . '</p>';
        self::databaseFindings($findings);
        self::databaseTrusted();
    }

    private static function databaseFindings(array $findings): void
    {
        if (!$findings) {
            echo '<p>' . esc_html__('No database findings recorded.', 'site-defense') . '</p>';
            return;
        }
        $page = max(1, min((int) ceil(count($findings) / DbAudit::PAGE_SIZE), absint(State::field($_GET, 'db_page'))));
        $trusted = DbAudit::trusted();
        echo '<div class="sd-table" tabindex="0" role="region" aria-label="' . esc_attr__('Database findings', 'site-defense') . '">';
        echo '<table class="widefat striped sd-db-findings"><thead><tr><th scope="col">' . esc_html__('Finding', 'site-defense') . '</th>';
        echo '<th scope="col">' . esc_html__('Location', 'site-defense') . '</th><th scope="col">' . esc_html__('Actions', 'site-defense') . '</th></tr></thead><tbody>';
        foreach (array_slice($findings, ($page - 1) * DbAudit::PAGE_SIZE, DbAudit::PAGE_SIZE) as $row) {
            $id = $row['id'];
            echo '<tr><td>' . esc_html(DbAudit::findingLabel($row['type'])) . '</td>';
            $location = $row['source'] === 'cron' ? 'WP-Cron' : $row['source'];
            if ($id) {
                $location .= ' · ' . ($row['source'] === 'cron' ? self::time($id) : '#' . $id);
            }
            echo '<td><code>' . esc_html($row['location']) . '</code><br>' . esc_html($location);
            if (!empty($row['roles'])) {
                echo '<br>' . esc_html(implode(', ', array_map([State::class, 'roleLabel'], $row['roles'])));
            }
            if ($row['object_id']) {
                echo '<br>' . esc_html(sprintf(__('Post #%d', 'site-defense'), $row['object_id']));
            }
            echo '</td><td>';
            if (isset($row['fingerprint']) && current_user_can('promote_users')) {
                if (($trusted[$id]['fingerprint'] ?? '') === $row['fingerprint']) {
                    echo esc_html__('Confirmed', 'site-defense');
                } else {
                    self::fileConfirmation('db_trust', $id . ':' . $row['fingerprint'],
                        __('Confirm the current privileges', 'site-defense'), __('Confirm account', 'site-defense'));
                }
            }
            echo '</td></tr>';
        }
        echo '</tbody></table></div>';
        $base = self::url('database');
        if ($page > 1) {
            echo '<a href="' . esc_url(add_query_arg('db_page', $page - 1, $base) . '#sd-db-findings') . '">' . esc_html__('Previous page', 'site-defense') . '</a> ';
        }
        if ($page * DbAudit::PAGE_SIZE < count($findings)) {
            echo '<a href="' . esc_url(add_query_arg('db_page', $page + 1, $base) . '#sd-db-findings') . '">' . esc_html__('Next page', 'site-defense') . '</a>';
        }
    }

    private static function databaseTrusted(): void
    {
        echo '<h2>' . esc_html__('Confirmed accounts', 'site-defense') . '</h2>';
        echo '<p>' . esc_html__('Confirm accounts you recognize. Changed privileges appear in the next audit.', 'site-defense') . '</p>';
        foreach (DbAudit::trusted() as $id => $row) {
            echo '<p><code>' . esc_html($row['login']) . '</code> #' . esc_html((string) $id) . '</p>';
            if (current_user_can('promote_users')) {
                self::fileConfirmation('db_untrust', (string) $id,
                    __('Confirm removing the account approval', 'site-defense'), __('Remove confirmation', 'site-defense'));
            }
        }
    }

    private static function settings(): void
    {
        $settings = State::settings();
        echo '<h2>' . esc_html__('Protection settings', 'site-defense') . '</h2>';
        $html = '<p>' . esc_html__('WordPress can expose public authors through REST. Hiding profiles reduces account discovery. Login throttling applies independently.', 'site-defense') . '</p>';
        $html .= '<p><label>' . esc_html__('Trusted reverse proxy IP', 'site-defense') . ' <input name="proxy" value="' . esc_attr($settings['proxy']) . '"></label>';
        $html .= ' ' . esc_html__('Only set this for a proxy that overwrites X-Real-IP on every request.', 'site-defense') . '</p>';
        self::settingsForm('protection', __('Save protection settings', 'site-defense'), $html);
        echo '<h3>' . esc_html__('Plugin update channel', 'site-defense') . '</h3>';
        $channel = '<p><label for="sd-plugin-channel">' . esc_html__('Show updates for', 'site-defense') . ' </label>' .
            '<select id="sd-plugin-channel" name="channel">' .
            '<option value="stable"' . selected(PluginUpdates::includesCandidates(), false, false) . '>' . esc_html__('Stable releases', 'site-defense') . '</option>' .
            '<option value="rc"' . selected(PluginUpdates::includesCandidates(), true, false) . '>' . esc_html__('Stable releases and release candidates', 'site-defense') . '</option></select></p>';
        self::form('plugin_channel', $channel, __('Save update channel', 'site-defense'));
        echo '<h3>' . esc_html__('Configuration checks', 'site-defense') . '</h3><ul>';
        $checks = [
            __('PHP editor available to this account', 'site-defense') => current_user_can('edit_plugins') || current_user_can('edit_themes'),
            __('HTTPS detected for the dashboard', 'site-defense') => is_ssl(),
            __('HTTPS enforced for dashboard and login', 'site-defense') => force_ssl_admin(),
            __('Debugging enabled', 'site-defense') => defined('WP_DEBUG') && WP_DEBUG,
            __('PHP displays errors', 'site-defense') => filter_var(ini_get('display_errors'), FILTER_VALIDATE_BOOLEAN),
        ];
        foreach ($checks as $label => $enabled) {
            echo '<li>' . esc_html($label) . ' — ' . ($enabled ? esc_html__('Yes', 'site-defense') : esc_html__('No', 'site-defense')) . '</li>';
        }
        $debug = (array) get_option('sd_debug_probe', []);
        echo '<li>' . esc_html__('Debug log HTTP check', 'site-defense') . ' — ' . esc_html(translate($debug['result'] ?? 'Not checked', 'site-defense')) . '</li></ul>';
        echo '<p>' . esc_html__('For HTTPS enforcement and PHP error display, check the hosting configuration and wp-config.php.', 'site-defense') . '</p>';
        self::form('debug', '', __('Check debug log access', 'site-defense'));
    }

    private static function settingsForm(string $group, string $submit, string $extra = ''): void
    {
        $settings = State::settings();
        $html = '<input type="hidden" name="settings_group" value="' . esc_attr($group) . '">';
        foreach (self::SETTINGS_GROUPS[$group] as $name) {
            $html .= '<p class="sd-setting"><label><input type="checkbox" name="' . esc_attr($name) . '"' .
                checked($settings[$name], true, false) . '> ' . esc_html(translate(self::OPTIONS[$name], 'site-defense')) . '</label></p>';
        }
        self::form('settings', $html . $extra, $submit, primary: true);
    }

    private static function notifications(): void
    {
        $email = State::settings();
        echo '<h2>' . esc_html__('Email', 'site-defense') . '</h2>';
        $html = '<p><label>' . esc_html__('Notification email', 'site-defense') . ' <input type="email" name="email" value="' . esc_attr($email['email']) . '"></label></p>';
        $html .= '<fieldset class="sd-email-events"><legend>' . esc_html__('Email events', 'site-defense') . '</legend>';
        foreach (self::MAIL_EVENTS as $kind => $label) {
            $html .= '<label><input type="checkbox" name="notify_types[]" value="' . esc_attr($kind) . '"' .
                checked(in_array($kind, $email['notify_types'], true), true, false) . '> ' . esc_html(translate($label, 'site-defense')) . '</label>';
        }
        self::settingsForm('notifications', __('Save email settings', 'site-defense'), $html . '</fieldset>');
        $settings = Alerts::config();
        echo '<h2>' . esc_html__('Notification channels', 'site-defense') . '</h2>';
        echo '<p>' . esc_html__('Email uses the event selection above. New vulnerabilities are sent through email and Telegram. Blocked attempts are grouped into five-minute summaries.', 'site-defense') . '</p>';
        $html = '<p><label><input type="checkbox" name="telegram"' . checked($settings['telegram'], true, false) . '> ' . esc_html__('Send to Telegram', 'site-defense') . '</label></p>';
        $html .= '<p><label>' . esc_html__('Telegram bot token', 'site-defense') . ' <input type="password" name="telegram_token" autocomplete="new-password" value=""></label> ';
        $html .= esc_html($settings['token'] !== '' ? __('A token is stored. Leave blank to keep it.', 'site-defense') : __('Enter the bot token from BotFather.', 'site-defense')) . '</p>';
        $html .= '<p><label><input type="checkbox" name="clear_token"> ' . esc_html__('Remove stored Telegram token', 'site-defense') . '</label></p>';
        $html .= '<p><label>' . esc_html__('Telegram chat ID', 'site-defense') . ' <input name="telegram_chat" value="' . esc_attr($settings['chat']) . '"></label></p>';
        $html .= '<p><label><input type="checkbox" name="webhook"' . checked($settings['webhook'], true, false) . '> ' . esc_html__('Send to a signed webhook', 'site-defense') . '</label></p>';
        $html .= '<p><label>' . esc_html__('Webhook HTTPS URL', 'site-defense') . ' <input type="url" name="webhook_url" value="' . esc_attr($settings['url']) . '"></label></p>';
        $html .= '<p><label>' . esc_html__('Webhook signing secret', 'site-defense') . ' <input type="password" name="webhook_secret" autocomplete="new-password" value=""></label> ';
        $html .= esc_html($settings['secret'] !== '' ? __('A secret is stored. Leave blank to keep it.', 'site-defense') : __('Set a signing secret shared with your receiver.', 'site-defense')) . '</p>';
        $html .= '<p><label><input type="checkbox" name="clear_secret"> ' . esc_html__('Remove stored webhook secret', 'site-defense') . '</label></p>';
        self::form('channels', $html, __('Save notification channels', 'site-defense'));
        self::form('test_channels', '', __('Send test notification', 'site-defense'));
        echo '<p>' . esc_html__('Delivery runs in the background with retries. Use a system scheduler every minute for predictable response time.', 'site-defense') . '</p>';
        echo '<p><code>wp cron event run --due-now --path=/path/to/wordpress</code></p>';
        $last = (int) get_option('sd_alert_worker', 0);
        echo '<p>' . esc_html__('Last notification worker run', 'site-defense') . ' — ' . esc_html(self::time($last)) . '</p>';
    }

    private static function fileMonitoring(): void
    {
        echo '<h2>' . esc_html__('File monitoring', 'site-defense') . '</h2>';
        self::settingsForm('files', __('Save file monitoring settings', 'site-defense'));
        $watch = (array) get_option('sd_watch', []);
        echo '<p>' . esc_html__('Last completed file change check', 'site-defense') . ' — ' . esc_html(self::time((int) ($watch['completed'] ?? 0))) . '</p>';
        if (!empty($watch['started']) && ($watch['status'] ?? '') === 'running' && time() - $watch['started'] > 300) {
            echo '<p>' . esc_html__('The file check is taking longer than five minutes. Review scheduler activity and site size.', 'site-defense') . '</p>';
        }
        self::form('watch_now', '', __('Check file changes now', 'site-defense'));
    }

    private static function responseAction(string $task, int $user): string
    {
        if (!current_user_can('promote_users')) {
            return __('Permission denied.', 'site-defense');
        }
        $key = 'sd_response_plan_' . $user;
        if ($task === 'response_stop') {
            $result = ResponseMode::stop();
            return is_wp_error($result) ? $result->get_error_message() : __('Incident mode disabled', 'site-defense');
        }
        if ($task === 'response_cancel') {
            delete_transient($key);
            return __('Incident plan cancelled.', 'site-defense');
        }
        if ($task === 'response_preview') {
            delete_transient($key);
            $plan = ResponseMode::plan(State::field($_POST, 'minutes'), State::field($_POST, 'sessions'),
                State::field($_POST, 'passwords'), true);
            if (is_wp_error($plan)) {
                return $plan->get_error_message();
            }
            set_transient($key, ['token' => wp_generate_uuid4(), 'plan' => $plan], 10 * MINUTE_IN_SECONDS);
            return __('Review the incident plan before applying it.', 'site-defense');
        }
        $preview = get_transient($key);
        if (!$preview || !hash_equals($preview['token'], State::field($_POST, 'plan_token'))) {
            return __('This incident plan expired or changed. Preview it again.', 'site-defense');
        }
        delete_transient($key);
        $result = ResponseMode::start($preview['plan'], true);
        if (is_wp_error($result)) {
            return $result->get_error_message();
        }
        $message = __('Incident mode enabled', 'site-defense') . '.';
        if ($result['sessions_failed']) {
            $message .= ' ' . sprintf(__('Unable to revoke browser sessions for these user IDs: %s', 'site-defense'),
                implode(', ', $result['sessions_failed']));
        }
        if ($result['passwords_failed']) {
            $message .= ' ' . sprintf(__('Check these application passwords: %s', 'site-defense'), implode(', ', $result['passwords_failed']));
        }
        return $message;
    }

    private static function responseMode(): void
    {
        echo '<h2>' . esc_html__('Incident mode', 'site-defense') . '</h2>';
        echo '<p>' . esc_html__('Temporarily blocks plugin and theme installation, uploads and file editing through WordPress. Use WP-CLI for emergency maintenance.', 'site-defense') . '</p>';
        $status = ResponseMode::status();
        if ($status['active']) {
            echo '<p>' . esc_html(sprintf(__('Active until %s.', 'site-defense'), self::time($status['until']))) . '</p>';
        }
        if (!current_user_can('promote_users')) {
            return;
        }
        if ($status['active']) {
            self::fileConfirmation('response_stop', '', __('Allow plugin and theme installation and file editing again?', 'site-defense'),
                __('Disable incident mode', 'site-defense'));
            return;
        }
        $preview = get_transient('sd_response_plan_' . get_current_user_id());
        if ($preview) {
            $plan = $preview['plan'];
            echo '<h3>' . esc_html__('Incident plan', 'site-defense') . '</h3>';
            echo '<p>' . esc_html(sprintf(__('Duration: %d minutes', 'site-defense'), $plan['minutes'])) . '</p>';
            if ($plan['sessions'] || $plan['passwords']) {
                echo '<ul class="ul-disc">';
                foreach ($plan['sessions'] as $id => $count) {
                    $user = get_userdata($id);
                    echo '<li>' . esc_html(sprintf(__('User %1$s (#%2$d) · Browser sessions: %3$d', 'site-defense'),
                        $user ? $user->user_login : '', $id, $count)) . '</li>';
                }
                foreach ($plan['passwords'] as $item) {
                    echo '<li>' . esc_html(sprintf(__('User #%1$d · Application password: %2$s', 'site-defense'),
                        $item['user_id'], $item['name'])) . ' <code>' . esc_html($item['uuid']) . '</code></li>';
                }
                echo '</ul><p>' . esc_html__('Revoked sessions and application passwords cannot be restored.', 'site-defense') . '</p>';
            }
            $field = '<input type="hidden" name="plan_token" value="' . esc_attr($preview['token']) . '">';
            self::fileConfirmation('response_start', '', __('Apply this plan and enable incident mode?', 'site-defense'),
                __('Enable incident mode', 'site-defense'), $field);
            self::form('response_cancel', '', __('Discard plan', 'site-defense'));
            return;
        }
        $fields = '<p><label>' . esc_html__('Duration in minutes', 'site-defense') . ' <input type="number" name="minutes" value="60" min="5" max="1440" required></label></p>';
        $fields .= '<p><label>' . esc_html__('Browser sessions · User IDs separated by commas', 'site-defense') .
            '<br><input type="text" name="sessions" class="regular-text" maxlength="1024"></label></p>';
        $fields .= '<p><label>' . esc_html__('Application passwords · user ID:UUID pairs separated by commas', 'site-defense') .
            '<br><input type="text" name="passwords" class="regular-text" maxlength="4096"></label></p>';
        $fields .= '<p><a href="' . esc_url(self::url('login') . '#sd-privileged-access') . '">' .
            esc_html__('Find privileged accounts and application password IDs', 'site-defense') . '</a></p>';
        self::form('response_preview', $fields, __('Preview incident plan', 'site-defense'), primary: true);
    }

    private static function heartbeat(): void
    {
        $config = Heartbeat::config();
        $status = Heartbeat::status();
        echo '<h2>' . esc_html__('External heartbeat', 'site-defense') . '</h2>';
        echo '<p>' . esc_html__('Send a signed signal about WordPress task health every five minutes. Run the receiver separately so it can report missed signals.', 'site-defense') . '</p>';
        $fields = '<p><label><input type="checkbox" name="heartbeat_enabled"' . checked($config['enabled'], true, false) .
            '> ' . esc_html__('Enable external heartbeat', 'site-defense') . '</label></p>';
        $fields .= '<p><label>' . esc_html__('Receiver HTTPS address', 'site-defense') . '<br><input type="url" name="heartbeat_url" class="regular-text" value="' .
            esc_attr($config['url']) . '"></label></p>';
        $fields .= '<p><label>' . esc_html__('Heartbeat signing secret', 'site-defense') .
            '<br><input type="password" name="heartbeat_secret" class="regular-text" autocomplete="new-password" maxlength="128"></label></p>';
        if ($config['secret'] !== '') {
            $fields .= '<p>' . esc_html__('A secret is stored. Leave blank to keep it.', 'site-defense') . '</p>';
            $fields .= '<p><label><input type="checkbox" name="heartbeat_clear"> ' . esc_html__('Remove stored heartbeat secret', 'site-defense') . '</label></p>';
        }
        self::form('heartbeat_save', $fields, __('Save heartbeat settings', 'site-defense'));
        if ($config['enabled']) {
            echo '<p>' . esc_html__('Last successful heartbeat', 'site-defense') . ' — ' . esc_html(self::time((int) ($status['success'] ?? 0))) . '</p>';
            if (isset($status['attempt']) && empty($status['delivered'])) {
                echo '<p>' . esc_html__('Heartbeat delivery failed.', 'site-defense') . '</p>';
            }
            self::form('heartbeat_send', '', __('Send heartbeat now', 'site-defense'));
        }
    }

    private static function timeline(): void
    {
        $rows = Timeline::read(24, 50);
        echo '<h2>' . esc_html__('Incident timeline', 'site-defense') . '</h2>';
        echo '<p>' . esc_html__('Latest 50 relevant events in the past 24 hours.', 'site-defense') . ' <code>wp site-defense timeline</code></p>';
        if (!$rows) {
            echo '<p>' . esc_html__('No timeline events recorded.', 'site-defense') . '</p>';
            return;
        }
        echo '<div class="sd-table" tabindex="0" role="region" aria-label="' . esc_attr__('Incident timeline', 'site-defense') . '"><table class="widefat striped"><thead><tr>';
        foreach ([__('When', 'site-defense'), __('Event', 'site-defense'), __('Details', 'site-defense')] as $label) {
            echo '<th scope="col">' . esc_html($label) . '</th>';
        }
        echo '</tr></thead><tbody>';
        foreach ($rows as $row) {
            $actor = $row['context']['actor_id'] ?? 0;
            echo '<tr><td>' . esc_html(self::time($row['occurred'])) . '</td><td>' . esc_html(State::eventLabel($row['kind'])) . '</td><td>';
            echo esc_html(State::eventDetail($row['detail']));
            if ($actor) {
                echo '<br>' . esc_html(sprintf(__('Action performed by user ID: %d', 'site-defense'), $actor));
            }
            echo '</td></tr>';
        }
        echo '</tbody></table></div>';
    }

    private static function incidents(): void
    {
        echo '<h2 id="sd-incidents">' . esc_html__('Security incidents', 'site-defense') . '</h2>';
        $selected = absint(State::field($_GET, 'incident'));
        $page = max(1, min(100000, absint(State::field($_GET, 'incidents_page'))));
        $entry = $selected ? Incidents::get($selected) : null;
        $entries = $entry ? [$entry] : Incidents::recent($page);
        if (!$entries) {
            echo '<p>' . esc_html__('No security incidents recorded.', 'site-defense') . '</p>';
            return;
        }
        foreach (array_slice($entries, 0, 25) as $incident) {
            $context = json_decode($incident['context'], true) ?: [];
            $vulnerability = $context['vulnerability'] ?? null;
            $severity = match ($incident['severity']) {
                'blocked' => __('Attempt blocked', 'site-defense'),
                'review' => $vulnerability ? __('Update review needed', 'site-defense') : __('Review possible intrusion', 'site-defense'),
                default => __('Information', 'site-defense'),
            };
            echo '<section><h3>#' . esc_html($incident['id']) . ' ' . esc_html(State::eventLabel($incident['kind'])) . '</h3>';
            echo '<p>' . esc_html($severity) . ' · ' . esc_html(self::time((int) $incident['last_seen'])) . ' · ';
            echo esc_html(sprintf(__('Occurrences: %d', 'site-defense'), $incident['hits'])) . '</p>';
            if ($vulnerability) {
                echo '<p>' . nl2br(esc_html(Vulnerabilities::describe($vulnerability, false))) . '</p>';
                echo '<p><a href="' . esc_url(self::url('vulnerabilities')) . '">' . esc_html__('Known vulnerabilities', 'site-defense') . '</a></p>';
            } else {
                echo '<p>' . esc_html(State::eventDetail($incident['detail'])) . '</p>';
            }
            if ($incident['resolved']) {
                echo '<p>' . esc_html__('Reviewed', 'site-defense') . '</p>';
            }
            $delivery = json_decode($incident['delivery'], true) ?: [];
            foreach ($delivery as $channel => $status) {
                $label = ($status['sent'] ?? 0) >= (int) $incident['hits']
                    ? __('Delivered', 'site-defense') : __('Retry scheduled', 'site-defense');
                echo '<p>' . esc_html($channel . ' — ' . $label) . '</p>';
            }
            if (!empty($context['source_ip'])) {
                echo '<p>' . esc_html__('Latest source IP', 'site-defense') . ' — ' . esc_html($context['source_ip']) . '</p>';
            }
            if (!empty($context['user_id'])) {
                echo '<p>' . esc_html(sprintf(__('Affected user ID: %d', 'site-defense'), $context['user_id'])) . '</p>';
            }
            if (!empty($context['actor_id'])) {
                echo '<p>' . esc_html(sprintf(__('Action performed by user ID: %d', 'site-defense'), $context['actor_id'])) . '</p>';
            }
            if (Quarantine::available()) {
                if (!empty($context['user_id']) && current_user_can('edit_user', $context['user_id'])) {
                    self::fileConfirmation('incident_sessions', (string) $incident['id'],
                        __('Confirm signing this user out on every device', 'site-defense'), __('Revoke browser sessions', 'site-defense'));
                    if (!empty($context['application_uuid'])) {
                        self::fileConfirmation('incident_password', (string) $incident['id'],
                            __('Confirm revoking this application password', 'site-defense'), __('Revoke application password', 'site-defense'));
                    }
                }
                if (!empty($context['path']) && !empty($context['finding']) && Quarantine::canOffer($context['path'])) {
                    self::fileConfirmation('incident_quarantine', (string) $incident['id'],
                        __('Confirm removing the file from its original location', 'site-defense'), __('Move to quarantine', 'site-defense'));
                }
                if (!$vulnerability) {
                    self::fileConfirmation('incident_scan', (string) $incident['id'],
                        __('Confirm starting a full file scan', 'site-defense'), __('Start scan', 'site-defense'));
                }
                self::fileConfirmation('incident_resolve', (string) $incident['id'],
                    __('Confirm that you reviewed this incident', 'site-defense'), __('Mark as reviewed', 'site-defense'));
            }
            echo '</section>';
        }
        if (!$selected && $page > 1) {
            echo '<p><a href="' . esc_url(add_query_arg('incidents_page', $page - 1) . '#sd-incidents') . '">' . esc_html__('Newer events', 'site-defense') . '</a></p>';
        }
        if (!$selected && count($entries) > 25) {
            echo '<p><a href="' . esc_url(add_query_arg('incidents_page', $page + 1) . '#sd-incidents') . '">' . esc_html__('Older events', 'site-defense') . '</a></p>';
        }
    }

    private static function earlyProtection(): void
    {
        echo '<h2>' . esc_html__('Early protection', 'site-defense') . '</h2>';
        echo '<p>' . esc_html__('The early loader checks requests before WordPress starts and blocks PHP execution in uploads. It uses .user.ini on CGI/FastCGI hosting.', 'site-defense') . '</p>';
        $verified = (array) get_option('sd_early_verified', []);
        echo '<p>' . esc_html(!empty($verified['ok']) ? __('Early protection verified.', 'site-defense') : __('Early protection has not been verified.', 'site-defense')) . '</p>';
        if (Quarantine::available()) {
            $task = get_option('sd_early_enabled') ? 'early_disable' : 'early_install';
            $label = $task === 'early_install' ? __('Configure early protection', 'site-defense') : __('Disable early protection', 'site-defense');
            self::fileConfirmation($task, '', __('Confirm changing the managed .user.ini and uploads .htaccess blocks', 'site-defense'), $label);
            self::form('early_verify', '', __('Verify early protection', 'site-defense'));
        }
        echo '<details><summary>' . esc_html__('Nginx configuration', 'site-defense') . '</summary><p>';
        echo esc_html__('For Nginx, apply this rule before the general PHP location and reload the server configuration.', 'site-defense') . '</p>';
        echo '<pre><code>' . esc_html(EarlyProtection::nginxSnippet()) . '</code></pre></details>';
    }

    private static function firewallRules(): void
    {
        $status = Firewall::status();
        echo '<h2>' . esc_html__('Firewall settings', 'site-defense') . '</h2>';
        self::settingsForm('firewall', __('Save firewall settings', 'site-defense'));
        echo '<h2 id="sd-firewall-rules">' . esc_html__('Targeted firewall rules', 'site-defense') . '</h2>';
        echo '<p>' . esc_html__('Firewall rule version', 'site-defense') . ' — ' . esc_html((string) $status['version']) . '</p>';
        if (!$status['enabled']) {
            echo '<p>' . esc_html__('Firewall rules are disabled.', 'site-defense') . '</p>';
        }
        $manage = Quarantine::available();
        if ($manage) {
            self::form('rules_import', '<label>' . esc_html__('Signed firewall rule package', 'site-defense') .
                ' <input type="file" name="rules" accept=".pack" required></label>', __('Import firewall rules', 'site-defense'), true);
            if ($status['previous_version'] !== null) {
                self::fileConfirmation('rules_rollback', '', sprintf(__('Restore firewall package %d', 'site-defense'), $status['previous_version']),
                    __('Roll back firewall package', 'site-defense'));
            }
        }
        $modes = [
            'observe' => __('Observe', 'site-defense'),
            'block' => __('Block', 'site-defense'),
            'off' => __('Off', 'site-defense'),
        ];
        echo '<p>' . esc_html__('Observe records matches and allows the request to continue. Block returns HTTP 403.', 'site-defense') . '</p>';
        echo '<div class="sd-table" tabindex="0" role="region" aria-label="' . esc_attr__('Targeted firewall rules', 'site-defense') . '">';
        echo '<table class="widefat striped"><thead><tr><th scope="col">' . esc_html__('Rule', 'site-defense') . '</th>';
        echo '<th scope="col">' . esc_html__('Component', 'site-defense') . '</th><th scope="col">' . esc_html__('Route', 'site-defense') . '</th>';
        echo '<th scope="col">' . esc_html__('Mode', 'site-defense') . '</th></tr></thead><tbody>';
        foreach ($status['rules'] as $rule) {
            $applicability = $rule['affected'] ? __('Affected version', 'site-defense')
                : ($rule['version'] === '' ? __('Version unavailable', 'site-defense') : __('Outside affected versions', 'site-defense'));
            echo '<tr><td><a href="' . esc_url($rule['source']) . '">' . esc_html($rule['id']) . '</a></td>';
            echo '<td><code>' . esc_html($rule['component'] . ' ' . $rule['version']) . '</code><br>' . esc_html($applicability) . '</td>';
            echo '<td><code>' . esc_html($rule['route']) . '</code></td><td>';
            if ($manage) {
                $fields = '<input type="hidden" name="rule_id" value="' . esc_attr($rule['id']) .
                    '"><label><span class="screen-reader-text">' . esc_html(__('Mode', 'site-defense') . ' ' . $rule['id']) . '</span><select name="mode">';
                foreach ($modes as $value => $label) {
                    $fields .= '<option value="' . esc_attr($value) . '"' . selected($rule['mode'], $value, false) . '>' . esc_html($label) . '</option>';
                }
                self::form('rules_mode', $fields . '</select></label>', __('Save rule mode', 'site-defense'));
            } else {
                echo esc_html($modes[$rule['mode']]);
            }
            echo '</td></tr>';
        }
        echo '</tbody></table></div>';
    }

    private static function login(): void
    {
        echo '<h2>' . esc_html__('Login', 'site-defense') . '</h2>';
        $hint = '<p>' . esc_html__('Mandatory two-factor protection is off by default. When enabled, privileged users must enroll at their next sign-in. Existing sessions without a second factor lose privileged access.', 'site-defense') . '</p>';
        self::settingsForm('login', __('Save login settings', 'site-defense'), $hint);
        self::form('clear_limits', '', __('Reset login limits', 'site-defense'));
        $active = get_option('sd_login_route', '');
        $pending = get_option('sd_pending_route', []);
        if ($active) {
            echo '<p>' . esc_html__('Active address', 'site-defense') . ' <code>' . esc_html(LoginRoute::url($active)) . '</code></p>';
            self::form('clear_route', '', __('Restore standard address', 'site-defense'));
        }
        if (!empty($pending['slug']) && ($pending['expires'] ?? 0) > time()) {
            echo '<p>' . esc_html__('Test in a private window', 'site-defense') . ' <code>' . esc_html(LoginRoute::url($pending['slug'])) . '</code></p>';
            self::form('cancel_route', '', __('Cancel pending address', 'site-defense'));
        }
        echo '<p>' . esc_html__('If you lose access, deactivate Site Defense via WP-CLI or rename its plugin directory in your hosting file manager.', 'site-defense') . '</p>';
        self::form('route', '<label>' . esc_html__('New login path', 'site-defense') . ' <input name="slug" pattern="[a-z0-9][a-z0-9\-]{3,59}" required></label>', __('Test new address', 'site-defense'));
        echo '<h3>' . esc_html__('Two-factor authentication', 'site-defense') . '</h3>';
        $id = get_current_user_id();
        $enrollment = get_transient('sd_enroll_' . $id);
        if (get_user_meta($id, '_sd_totp', true)) {
            self::form('disable_totp', '<label>' . esc_html__('Current password', 'site-defense') . ' <input name="password" type="password" autocomplete="current-password" required></label>', __('Disable for my account', 'site-defense'));
        } elseif (!is_ssl() || !function_exists('sodium_crypto_secretbox')) {
            echo '<p>' . esc_html__('Two-factor enrollment requires HTTPS and PHP Sodium.', 'site-defense') . '</p>';
        } elseif ($enrollment) {
            echo '<p>' . esc_html__('Use time-based codes. Setup key', 'site-defense') . ' <code>' . esc_html(TwoFactor::base32($enrollment)) . '</code></p>';
            self::form('confirm_totp', '<label>' . esc_html__('Authenticator code', 'site-defense') . ' <input name="code" inputmode="numeric" pattern="[0-9]{6}" required></label>', __('Verify and enable for my account', 'site-defense'));
        } else {
            self::form('setup_totp', '', __('Set up for my account', 'site-defense'));
        }
    }

    private static function vulnerabilities(): void
    {
        global $wp_version;
        $findings = (array) get_option('sd_findings', []);
        $feed = (array) get_option('sd_feed_status', []);
        echo '<h2>' . esc_html__('Known vulnerabilities', 'site-defense') . '</h2>';
        echo '<p>' . esc_html__('Database published', 'site-defense') . ' — ' . esc_html(self::time(Vulnerabilities::version())) . '<br>';
        echo esc_html__('Last completed comparison', 'site-defense') . ' — ' . esc_html(self::time((int) ($findings['checked'] ?? 0))) . '<br>';
        echo esc_html__('Last successful update check', 'site-defense') . ' — ' . esc_html(self::time((int) ($feed['success'] ?? 0))) . '</p>';
        if (!empty($feed['message'])) {
            echo '<p>' . esc_html(translate($feed['message'], 'site-defense')) . '</p>';
        }
        if (isset($findings['covered'], $findings['components'])) {
            /* translators: 1: Components with records, 2: Total installed components. */
            $coverage = __('Installed components with advisory records — %1$s of %2$s', 'site-defense');
            echo '<p>' . esc_html(sprintf($coverage, number_format_i18n($findings['covered']), number_format_i18n($findings['components']))) . '</p>';
        }
        if (!Vulnerabilities::version()) {
            echo '<p>' . esc_html__('No database is installed. Import a signed database package to enable version matching.', 'site-defense') . '</p>';
        }
        if (!Vulnerabilities::hasUpdateEndpoint()) {
            echo '<p>' . esc_html__('Use a signed package to update the database manually.', 'site-defense') . '</p>';
        }
        self::form('check', '', __('Check installed versions', 'site-defense'));
        self::form('update', '', __('Update database now', 'site-defense'));
        self::form('import', '<label>' . esc_html__('Signed database package', 'site-defense') . ' <input type="file" name="package" accept=".pack" required></label>', __('Import database', 'site-defense'), true);
        $hint = '<p>' . esc_html__('WPVulnerability requests use plugin and theme identifiers. Version comparison runs locally and keeps the last successful API response.', 'site-defense') . '</p>';
        self::settingsForm('vulnerabilities', __('Save update settings', 'site-defense'), $hint);
        if (State::enabled('wpvulnerability')) {
            $cache = $findings['wpvulnerability'] ?? [];
            if ($cache) {
                /* translators: 1: Cached component count, 2: Eligible component count, 3: Stale entries. */
                $status = __('WPVulnerability cache: %1$d of %2$d components. Entries older than one day: %3$d.', 'site-defense');
                echo '<p>' . esc_html(sprintf($status, $cache['cached'], $cache['components'], $cache['stale'])) . '</p>';
            } else {
                echo '<p>' . esc_html__('Waiting for the first WPVulnerability check.', 'site-defense') . '</p>';
            }
        }
        if (State::enabled('kev_auto')) {
            $kev = Kev::cache();
            echo '<p><a href="https://github.com/cisagov/kev-data">' . esc_html__('CISA Known Exploited Vulnerabilities', 'site-defense') . '</a> · ';
            echo esc_html__('Last successful update check', 'site-defense') . ' — ' . esc_html(self::time($kev['success'])) . '</p>';
            if ($kev['error']) {
                echo '<p>' . esc_html__('Unable to refresh CISA KEV.', 'site-defense') . '</p>';
            }
            self::form('kev_refresh', '', __('Update CISA KEV now', 'site-defense'));
        }
        if (!empty($findings['items'])) {
            echo '<div class="sd-table" tabindex="0" role="region" aria-label="' . esc_attr__('Known vulnerabilities', 'site-defense') . '">';
            echo '<table class="widefat striped"><thead><tr>';
            echo '<th>' . esc_html__('Component', 'site-defense') . '</th><th>' . esc_html__('Advisory', 'site-defense') . '</th>';
            echo '<th>' . esc_html__('Affected range', 'site-defense') . '</th><th>' . esc_html__('Fixed in', 'site-defense') . '</th>';
            echo '<th>' . esc_html__('Rule', 'site-defense') . '</th></tr></thead><tbody>';
            foreach ($findings['items'] as $row) {
                echo '<tr><td>' . esc_html($row['key'] . ' ' . $row['version'] . ($row['active'] ? '' : ' ' . __('(inactive)', 'site-defense'))) . '</td>';
                $label = ($row['cve'] ?: $row['id']) . ' · ' . $row['title'];
                if (!empty($row['informational'])) {
                    $label .= ' · ' . __('Informational', 'site-defense');
                }
                if ($row['score'] !== null) {
                    $label .= ' · CVSS ' . $row['score'];
                }
                echo '<td>' . ($row['link'] ? '<a href="' . esc_url($row['link']) . '">' . esc_html($label) . '</a>' : esc_html($label));
                echo '<br><small>' . esc_html($row['source'] ?? 'Wordfence') . '</small>';
                if (!empty($row['kev']) && State::enabled('kev_auto')) {
                    echo '<br><strong>' . esc_html__('Known exploitation · CISA KEV', 'site-defense') . '</strong>';
                }
                echo '</td>';
                if (isset($row['bounds'])) {
                    $range = implode(' · ', array_map(static fn ($bound) => $bound[1] . ' ' . $bound[0], $row['bounds']));
                } else {
                    [$low, $includeLow, $high, $includeHigh] = $row['range'];
                    $range = ($includeLow ? '[' : '(') . $low . ', ' . $high . ($includeHigh ? ']' : ')');
                }
                echo '<td>' . esc_html($range) . '</td>';
                echo '<td>' . esc_html(implode(', ', $row['fixed']) ?: __('Unknown', 'site-defense')) . '</td>';
                echo '<td>' . esc_html($row['key'] === 'core:wordpress' && $row['cve'] === 'CVE-2026-87902' && Vulnerabilities::coreRuleActive($wp_version)
                    ? __('Active on WordPress page routing', 'site-defense') : __('No active rule', 'site-defense')) . '</td></tr>';
            }
            echo '</tbody></table></div>';
        } elseif (!empty($findings['version'])) {
            echo '<p>' . esc_html__('No matching advisories in the last comparison.', 'site-defense') . '</p>';
        }
    }

    private static function repairAction(string $task, string $selection, int $user): string
    {
        $pointer = 'sd_repair_active_' . $user;
        if ($task === 'repair_preview') {
            $previous = (string) get_transient($pointer);
            $plan = FileRepair::preview($selection, false);
            if (is_wp_error($plan)) {
                return $plan->get_error_message();
            }
            if (!set_transient($pointer, $plan['id'], 15 * MINUTE_IN_SECONDS)) {
                FileRepair::discard($plan['id'], false);
                return __('Unable to save the repair preview.', 'site-defense');
            }
            FileRepair::discard($previous, false);
            return __('The official file was verified. Review the repair preview.', 'site-defense');
        }
        if ($task === 'repair_discard') {
            FileRepair::discard($selection, false);
            if (get_transient($pointer) === $selection) {
                delete_transient($pointer);
            }
            return __('Repair preview discarded.', 'site-defense');
        }
        $result = $task === 'repair_apply' ? FileRepair::apply($selection, false) : FileRepair::undo(absint($selection));
        if (is_wp_error($result)) {
            $id = $result->get_error_data()['quarantine_id'] ?? 0;
            return $result->get_error_message() . ($id ? ' ' . sprintf(__('Quarantine entry: #%d.', 'site-defense'), $id) : '');
        }
        if ($task === 'repair_apply') {
            if (get_transient($pointer) === $selection) {
                delete_transient($pointer);
            }
            return sprintf(__('The file was replaced and verified. Quarantine entry: #%d.', 'site-defense'), $result['quarantine_id']);
        }
        return __('The original was returned from quarantine.', 'site-defense');
    }

    private static function repairPreview(): void
    {
        $plan = FileRepair::plan((string) get_transient('sd_repair_active_' . get_current_user_id()), false);
        if (!$plan) {
            return;
        }
        echo '<h2>' . esc_html__('File repair preview', 'site-defense') . '</h2>';
        echo '<p><code>' . esc_html($plan['path']) . '</code></p>';
        echo '<p>' . esc_html(sprintf(__('Installed component: %1$s %2$s', 'site-defense'), $plan['component'], $plan['version']));
        echo $plan['locale'] !== '' ? ' · ' . esc_html($plan['locale']) . '</p>' : '</p>';
        echo '<p><a href="' . esc_url($plan['archive']) . '">' . esc_html__('Official package from WordPress.org', 'site-defense') . '</a></p>';
        echo '<ul class="ul-disc">';
        foreach ([
            __('Current SHA-256', 'site-defense') => $plan['original_sha256'],
            __('Replacement SHA-256', 'site-defense') => $plan['replacement_sha256'],
            (strlen($plan['official_checksum']) === 64 ? __('Verified official SHA-256', 'site-defense') :
                __('Verified official MD5', 'site-defense')) => $plan['official_checksum'],
        ] as $label => $hash) {
            echo '<li>' . esc_html($label) . ' <code>' . esc_html($hash) . '</code></li>';
        }
        echo '</ul>';
        self::fileConfirmation('repair_apply', $plan['id'], __('Keep the original in quarantine and replace this file with the verified copy?', 'site-defense'),
            __('Replace with verified file', 'site-defense'));
        self::form('repair_discard', '', __('Discard repair preview', 'site-defense'), selection: $plan['id']);
    }

    private static function scanner(bool $quarantine): void
    {
        $scan = (array) get_option('sd_scan', []);
        $status = $scan['status'] ?? 'idle';
        $statusLabel = match ($status) {
            'running' => __('Running', 'site-defense'),
            'paused' => __('Paused', 'site-defense'),
            'complete' => __('Complete', 'site-defense'),
            default => __('Not started', 'site-defense'),
        };
        echo '<h2 id="sd-scanner">' . esc_html__('File scan', 'site-defense') . '</h2>';
        echo '<p>' . esc_html__('The full scan covers the site directory and configured external WordPress directories. Content checks apply to every file extension.', 'site-defense') . '</p>';
        echo '<p>' . esc_html__('Status', 'site-defense') . ' — ' . esc_html($statusLabel) . '<br>' . esc_html__('Last completed scan', 'site-defense') . ' — ' . esc_html(self::time((int) ($scan['last_success'] ?? 0))) . '<br>';
        echo esc_html__('Files inspected', 'site-defense') . ' — ' . esc_html(number_format_i18n((int) ($scan['files'] ?? 0))) . ' · ';
        echo esc_html__('Findings', 'site-defense') . ' — ' . esc_html(number_format_i18n((int) ($scan['finding_count'] ?? 0))) . '</p>';
        echo '<p>' . esc_html__('Skipped or partially checked items', 'site-defense') . ' — ' . esc_html(number_format_i18n((int) ($scan['skipped_count'] ?? 0))) . ' · ';
        echo esc_html__('Excluded by hash', 'site-defense') . ' — ' . esc_html(number_format_i18n((int) ($scan['excluded_count'] ?? 0))) . '<br>';
        echo esc_html__('Scan worker time, seconds', 'site-defense') . ' — ' . esc_html(number_format_i18n((float) ($scan['duration'] ?? 0), 2)) . ' · ';
        echo esc_html__('Peak process memory', 'site-defense') . ' — ' . esc_html(size_format((int) ($scan['peak_memory'] ?? 0))) . '<br>';
        echo esc_html__('Bytes read', 'site-defense') . ' — ' . esc_html(size_format((int) ($scan['bytes'] ?? 0))) . '</p>';
        if (!empty($scan['report_error'])) {
            echo '<p>' . esc_html__('Some skipped items could not be saved. The coverage report is incomplete.', 'site-defense') . '</p>';
        }
        if (($scan['finding_count'] ?? 0) > count($scan['findings'] ?? [])) {
            echo '<p>' . esc_html__('The results list contains the first 500 findings. The total count includes all recorded findings.', 'site-defense') . '</p>';
        }
        echo '<p>' . esc_html__('Malware signature version', 'site-defense') . ' — ' . esc_html((string) Malware::rules()['version']) . '</p>';
        echo '<p>' . esc_html__('Signatures used by this scan', 'site-defense') . ' — ' . esc_html((string) ($scan['signature_version'] ?? 0)) . '</p>';
        if (current_user_can('update_plugins')) {
            self::form('malware_import', '<label>' . esc_html__('Signed malware signature package', 'site-defense') . ' <input type="file" name="malware_package" accept=".pack" required></label>', __('Import malware signatures', 'site-defense'), true);
        }
        if ($status === 'running' && time() - max($scan['last_run'] ?? 0, $scan['started'] ?? 0) > 300) {
            echo '<p>' . esc_html__('Waiting for WP-Cron. Check the site scheduler if progress stays paused.', 'site-defense') . '</p>';
        }
        if ($status === 'running') {
            self::form('cancel', '', __('Pause scan', 'site-defense'));
        } else {
            self::form('start', '', __('Start scan', 'site-defense'));
            if ($status === 'paused') {
                self::form('resume', '', __('Resume scan', 'site-defense'));
            }
        }
        if (!empty($scan['findings'])) {
            echo '<div class="sd-table sd-findings" tabindex="0" role="region" aria-label="' . esc_attr__('File scan findings', 'site-defense') . '">';
            echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Finding', 'site-defense') . '</th>';
            echo '<th>' . esc_html__('File or component', 'site-defense') . '</th>';
            if ($quarantine) {
                echo '<th>' . esc_html__('Actions', 'site-defense') . '</th>';
            }
            echo '</tr></thead><tbody>';
            $offered = [];
            foreach ($scan['findings'] as $row) {
                [$finding, $path] = $row;
                $details = $row[3] ?? [];
                echo '<tr><td>' . esc_html(translate($finding, 'site-defense'));
                if (!empty($details['reason'])) {
                    echo '<p>' . esc_html(translate($details['reason'], 'site-defense')) . '</p>';
                }
                if (!empty($details['confidence'])) {
                    echo '<p>' . esc_html__('Confidence', 'site-defense') . ' — ' . esc_html(translate(ucfirst($details['confidence']), 'site-defense')) . '</p>';
                }
                if (!empty($details['rule_id'])) {
                    echo '<code>' . esc_html($details['rule_id']) . '</code>';
                }
                echo '</td><td><code>' . esc_html($path) . '</code>';
                if (!empty($details['line'])) {
                    echo '<p>' . esc_html__('Line', 'site-defense') . ' ' . esc_html((string) $details['line']) . '</p>';
                }
                if (!empty($details['snippet'])) {
                    echo '<pre><code>' . esc_html($details['snippet']) . '</code></pre>';
                }
                echo '</td>';
                if ($quarantine) {
                    echo '<td>';
                    if (FileRepair::canPreview($row)) {
                        self::form('repair_preview', '', __('Preview file repair', 'site-defense'), selection: Quarantine::selector($row));
                    }
                    if (!isset($offered[$path]) && in_array($finding, Scanner::QUARANTINE_FINDINGS, true) && Quarantine::canOffer($path)) {
                        $offered[$path] = true;
                        self::fileConfirmation('quarantine_file', Quarantine::selector($row),
                            __('Confirm removing the file from its original location', 'site-defense'),
                            __('Move to quarantine', 'site-defense'));
                    }
                    if (!empty($row[2])) {
                        self::fileConfirmation('exclude_file', Quarantine::selector($row), __('Confirm trusting this exact file hash', 'site-defense'), __('Exclude this hash', 'site-defense'));
                    }
                    echo '</td>';
                }
                echo '</tr>';
            }
            echo '</tbody></table></div>';
        }
        self::scanCoverage($scan);
    }

    private static function scanCoverage(array $scan): void
    {
        echo '<h3 id="sd-skipped">' . esc_html__('Skipped or partially checked items', 'site-defense') . '</h3>';
        echo '<p>' . esc_html__('Files larger than 64 MiB and symbolic links are skipped. PHP token analysis may be partial when memory or complexity limits are reached. Archives are checked as raw files.', 'site-defense') . '</p>';
        $page = max(1, min(100000, absint(State::field($_GET, 'skip_page'))));
        $rows = ScanReport::skippedPage($scan, $page);
        if ($rows) {
            echo '<div class="sd-table" tabindex="0" role="region" aria-label="' . esc_attr__('Skipped or partially checked items', 'site-defense') . '"><table class="widefat striped"><thead><tr>';
            foreach (['Path', 'Reason', 'Scope', 'Content bytes read'] as $label) {
                echo '<th>' . esc_html(translate($label, 'site-defense')) . '</th>';
            }
            echo '</tr></thead><tbody>';
            foreach (array_slice($rows, 0, ScanReport::PAGE_SIZE) as $row) {
                echo '<tr><td><code>' . esc_html($row['path']) . '</code></td><td>' . esc_html(translate($row['reason'], 'site-defense')) . '</td>';
                echo '<td>' . esc_html(translate($row['scope'] === 'directory' ? 'Directory subtree' : ($row['partial'] ? 'Partial file check' : 'File'), 'site-defense')) . '</td>';
                echo '<td>' . esc_html(size_format((int) $row['bytes'])) . '</td></tr>';
            }
            echo '</tbody></table></div><p>';
            if ($page > 1) {
                echo '<a href="' . esc_url(add_query_arg('skip_page', $page - 1)) . '#sd-skipped">' . esc_html__('Previous page', 'site-defense') . '</a> ';
            }
            if (count($rows) > ScanReport::PAGE_SIZE) {
                echo '<a href="' . esc_url(add_query_arg('skip_page', $page + 1)) . '#sd-skipped">' . esc_html__('Next page', 'site-defense') . '</a>';
            }
            echo '</p>';
        } else {
            echo '<p>' . esc_html__('No skipped items recorded on this page.', 'site-defense') . '</p>';
        }
        echo '<h3>' . esc_html__('Hash exclusions', 'site-defense') . '</h3><p>' . esc_html__('An exclusion applies only while the file SHA-256 matches. Changed files are analyzed again.', 'site-defense') . '</p>';
        foreach (ScanReport::exclusions() as $key => $entry) {
            echo '<p><code>' . esc_html($entry['path']) . '</code><br><code>' . esc_html($entry['sha256']) . '</code></p>';
            if (Quarantine::available()) {
                self::fileConfirmation('remove_exclusion', $key, __('Confirm removing this hash exclusion', 'site-defense'), __('Remove exclusion', 'site-defense'));
            }
        }
    }

    private static function quarantine(): void
    {
        $page = max(1, min(100000, absint(State::field($_GET, 'quarantine_page'))));
        $entries = Quarantine::entries($page);
        echo '<h2 id="sd-quarantine">' . esc_html__('Quarantine', 'site-defense') . '</h2>';
        if (!$entries) {
            echo '<p>' . esc_html__('No files in quarantine.', 'site-defense') . '</p>';
        } else {
            echo '<p>' . esc_html__('Quarantined copies are stored in the database. Restore a file only if you trust it.', 'site-defense') . '</p>';
            echo '<div class="sd-table" tabindex="0" role="region" aria-label="' . esc_attr__('Quarantine', 'site-defense') . '">';
            echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Original file', 'site-defense') . '</th>';
            echo '<th>' . esc_html__('Quarantined on', 'site-defense') . '</th><th>' . esc_html__('Actions', 'site-defense') . '</th></tr></thead><tbody>';
            foreach (array_slice($entries, 0, Quarantine::PAGE_SIZE) as $entry) {
                echo '<tr><td><code>' . esc_html($entry['path']) . '</code><br>' . esc_html(size_format((int) $entry['bytes'])) . '</td>';
                echo '<td>' . esc_html(self::time((int) $entry['created'])) . '</td><td>';
                if ($entry['state'] === 'repaired') {
                    echo '<p>' . esc_html(sprintf(__('Copy made before repair · #%d', 'site-defense'), $entry['id'])) . '</p>';
                    self::fileConfirmation('repair_undo', (string) $entry['id'],
                        __('Return the previous file? It may contain the suspicious code found during the scan.', 'site-defense'),
                        __('Undo file repair', 'site-defense'));
                } elseif ($entry['state'] === 'repair_undone') {
                    echo '<p>' . esc_html__('File repair undone', 'site-defense') . '</p>';
                } else {
                    self::fileConfirmation('restore_file', (string) $entry['id'],
                        __('Confirm restoring the file to its original location', 'site-defense'), __('Restore file', 'site-defense'));
                }
                echo '</td></tr>';
            }
            echo '</tbody></table></div>';
        }
        if ($page > 1) {
            echo '<p><a href="' . esc_url(add_query_arg('quarantine_page', $page - 1) . '#sd-quarantine') . '">' . esc_html__('Newer quarantined files', 'site-defense') . '</a></p>';
        }
        if (count($entries) > Quarantine::PAGE_SIZE) {
            echo '<p><a href="' . esc_url(add_query_arg('quarantine_page', $page + 1) . '#sd-quarantine') . '">' . esc_html__('Older quarantined files', 'site-defense') . '</a></p>';
        }
    }

    private static function fileConfirmation(string $task, string $selection, string $confirmation, string $label, string $fields = ''): void
    {
        echo '<details class="sd-confirmation" name="sd-confirmation"><summary class="button">';
        echo '<span class="sd-confirm-open">' . esc_html($label) . '</span>';
        echo '<span class="sd-confirm-close">' . esc_html__('Cancel', 'site-defense') . '</span></summary>';
        echo '<div class="sd-confirm-body"><p>' . esc_html($confirmation) . '</p>';
        $fields .= '<input type="hidden" name="confirm" value="yes">';
        self::form($task, $fields, __('Confirm', 'site-defense'), primary: true, selection: $selection);
        echo '</div></details>';
    }

    private static function access(): void
    {
        echo '<h2 id="sd-privileged-access">' . esc_html__('Privileged access', 'site-defense') . '</h2>';
        $page = max(1, absint(State::field($_GET, 'accounts_page')));
        $candidateRoles = [];
        foreach (wp_roles()->roles as $name => $role) {
            foreach (['manage_options', 'install_plugins', 'activate_plugins', 'update_plugins', 'edit_users', 'promote_users', 'update_core', 'edit_themes'] as $cap) {
                if (!empty($role['capabilities'][$cap])) {
                    $candidateRoles[] = $name;
                    break;
                }
            }
        }
        global $wpdb;
        $metaQuery = ['relation' => 'OR'];
        foreach (array_unique(array_merge($candidateRoles, ['manage_options', 'install_plugins', 'activate_plugins', 'update_plugins', 'edit_users', 'promote_users', 'update_core', 'edit_themes'])) as $candidate) {
            $metaQuery[] = ['key' => $wpdb->prefix . 'capabilities', 'value' => '"' . $candidate . '";b:1', 'compare' => 'LIKE'];
        }
        $query = new \WP_User_Query(['meta_query' => $metaQuery, 'number' => 30, 'paged' => $page, 'orderby' => 'ID']);
        foreach ($query->get_results() as $user) {
            if (!Hardening::privileged($user)) {
                continue;
            }
            echo '<h3>' . esc_html($user->display_name . ' (#' . $user->ID . ')') . '</h3>';
            echo '<p>' . esc_html(implode(', ', array_map([State::class, 'roleLabel'], $user->roles))) . '</p>';
            foreach (\WP_Application_Passwords::get_user_application_passwords($user->ID) as $item) {
                echo '<p>' . esc_html($item['name'] . ' · ' . __('Last used', 'site-defense') . ' ' . self::time((int) $item['last_used'])) . '</p>';
                if (current_user_can('edit_user', $user->ID)) {
                    echo '<p><code>' . esc_html($user->ID . ':' . $item['uuid']) . '</code></p>';
                    $fields = '<input type="hidden" name="user_id" value="' . esc_attr($user->ID) . '">';
                    $fields .= '<input type="hidden" name="uuid" value="' . esc_attr($item['uuid']) . '">';
                    self::fileConfirmation('revoke', '', __('Confirm revocation', 'site-defense'), __('Revoke application password', 'site-defense'), $fields);
                }
            }
        }
        if ($page > 1) {
            echo '<p><a href="' . esc_url(add_query_arg('accounts_page', $page - 1)) . '">' . esc_html__('Previous accounts', 'site-defense') . '</a></p>';
        }
        if ($query->get_total() > $page * 30) {
            echo '<p><a href="' . esc_url(add_query_arg('accounts_page', $page + 1)) . '">' . esc_html__('Next accounts', 'site-defense') . '</a></p>';
        }
    }

    private static function journal(): void
    {
        global $wpdb;
        $table = State::table('events');
        $page = max(1, min(200, absint(State::field($_GET, 'journal_page'))));
        $rows = $wpdb->get_results($wpdb->prepare("SELECT occurred, kind, detail FROM $table ORDER BY id DESC LIMIT 51 OFFSET %d", ($page - 1) * 50), ARRAY_A);
        echo '<h2>' . esc_html__('Recent security events', 'site-defense') . '</h2>';
        echo '<div class="sd-table" tabindex="0" role="region" aria-label="' . esc_attr__('Recent security events', 'site-defense') . '">';
        echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('When', 'site-defense') . '</th>';
        echo '<th>' . esc_html__('Event', 'site-defense') . '</th><th>' . esc_html__('Details', 'site-defense') . '</th></tr></thead><tbody>';
        foreach (array_slice($rows ?: [], 0, 50) as $row) {
            echo '<tr><td>' . esc_html(self::time((int) $row['occurred'])) . '</td><td>' . esc_html(State::eventLabel($row['kind'])) . '</td><td>' . esc_html(State::eventDetail($row['detail'])) . '</td></tr>';
        }
        echo '</tbody></table></div>';
        if ($page > 1) {
            echo '<p><a href="' . esc_url(add_query_arg('journal_page', $page - 1)) . '">' . esc_html__('Newer events', 'site-defense') . '</a></p>';
        }
        if (count($rows ?: []) > 50) {
            echo '<p><a href="' . esc_url(add_query_arg('journal_page', $page + 1)) . '">' . esc_html__('Older events', 'site-defense') . '</a></p>';
        }
    }
}

