<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

/** Runs Site Defense checks and recovery operations from the local console. */
final class Cli
{
    /**
     * Show protection and worker status without making HTTP requests.
     *
     * ## OPTIONS
     * [--format=<format>]
     * : Output format: json or table. Default: json.
     */
    public function status(array $args, array $options): void
    {
        self::validateFormat($options);
        global $wp_version;
        self::output([
            'plugin_version' => get_file_data(SITE_DEFENSE_DIR . '/site-defense.php', ['version' => 'Version'])['version'],
            'wordpress_version' => $wp_version,
            'site' => home_url('/'),
            'protection' => array_intersect_key(State::settings(), array_flip([
                'limit', 'privacy', 'xml_login', 'xml_pingback', 'file_editor', 'waf',
                'observe', 'scan_auto', 'fast_watch', 'require_2fa',
            ])),
            'database_version' => Vulnerabilities::version(),
            'plugin_update_channel' => PluginUpdates::includesCandidates() ? 'stable_and_rc' : 'stable',
            'update_endpoint_configured' => Vulnerabilities::hasUpdateEndpoint(),
            'firewall_rule_version' => EarlyProtection::rules()['version'] ?? 0,
            'early_enabled' => (bool) get_option('sd_early_enabled'),
            'early_last_verification' => get_option('sd_early_verified', []),
            'scan' => self::scanStatus(),
            'db_audit' => DbAudit::report()['status'] ?? 'idle',
            'watch' => self::watchStatus(),
            'notification_worker' => (int) get_option('sd_alert_worker', 0),
        ], $options);
    }

    /**
     * Run a full scan in this process, inspect results, pause or resume.
     *
     * ## OPTIONS
     * <action>
     * : run, resume, pause, status, results, skipped, exclusions, exclude, or unexclude.
     * [<selection>]
     * : Finding selector for exclude, exclusion key for unexclude.
     * [--page=<page>]
     * : Page of skipped items, starting at 1.
     * [--yes]
     * : Skip exclusion change confirmation.
     * [--timeout=<seconds>]
     * : Maximum foreground runtime. Default: 300. Zero means unlimited.
     * [--fail-on-findings]
     * : Exit with code 2 when a completed scan has findings.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function scan(array $args, array $options): void
    {
        self::validateFormat($options);
        $action = self::action($args, ['run', 'resume', 'pause', 'status', 'results', 'skipped', 'exclusions', 'exclude', 'unexclude']);
        if ($action === 'exclusions') {
            self::output(ScanReport::exclusions(), $options);
            return;
        }
        if ($action === 'exclude' || $action === 'unexclude') {
            $selection = $args[1] ?? '';
            if (!preg_match('/^[a-f0-9]{64}$/D', $selection)) {
                \WP_CLI::error(__('Use a finding selector from scan results.', 'site-defense'));
            }
            \WP_CLI::confirm(__('Change this hash exclusion?', 'site-defense'), $options);
            $message = $action === 'exclude' ? ScanReport::exclude($selection) : ScanReport::remove($selection);
            self::expect($message, $action === 'exclude' ? __('Hash exclusion saved.', 'site-defense') : __('Hash exclusion removed.', 'site-defense'), $options);
            return;
        }
        if ($action === 'pause') {
            self::expect(Scanner::command('cancel'), __('Scan paused.', 'site-defense'), $options);
            return;
        }
        if ($action === 'run' || $action === 'resume') {
            $timeout = self::timeout($options);
            $result = Scanner::locked(static function () use ($action, $timeout): string {
                $scan = (array) get_option('sd_scan', []);
                if ($action === 'run' && ($scan['status'] ?? '') === 'paused') {
                    return __('The scan is paused. Use scan resume to continue it.', 'site-defense');
                }
                $message = Scanner::command($action === 'resume' ? 'resume' : 'start');
                if ($message !== __('Scan is queued.', 'site-defense')) {
                    return $message;
                }
                return self::finish('sd_scan', [Scanner::class, 'slice'], $timeout);
            });
            if ($result !== '') {
                \WP_CLI::error($result);
            }
        }
        $scan = (array) get_option('sd_scan', []);
        if ($action === 'skipped') {
            $page = self::positiveId($options['page'] ?? '1');
            $rows = ScanReport::skippedPage($scan, $page);
            self::output(['page' => $page, 'total' => $scan['skipped_count'] ?? 0,
                'has_more' => count($rows) > ScanReport::PAGE_SIZE,
                'report_error' => !empty($scan['report_error']),
                'items' => array_slice($rows, 0, ScanReport::PAGE_SIZE)], $options);
            return;
        }
        if ($action === 'results') {
            $rows = [];
            foreach ($scan['findings'] ?? [] as $finding) {
                $rows[] = [
                    'finding' => $finding[0], 'path' => $finding[1], 'sha256' => $finding[2] ?? null,
                    'selector' => Quarantine::selector($finding),
                    'quarantine_available' => in_array($finding[0], Scanner::QUARANTINE_FINDINGS, true) &&
                        Quarantine::canOffer($finding[1]),
                    'details' => $finding[3] ?? [],
                ];
            }
            self::output($rows, $options);
        } else {
            self::output(self::scanStatus(), $options);
        }
        if (isset($options['fail-on-findings']) && ($scan['status'] ?? '') === 'complete' &&
            ($scan['finding_count'] ?? count($scan['findings'] ?? [])) > 0) {
            \WP_CLI::halt(2);
        }
    }

    /**
     * Check critical file changes synchronously or show the latest status.
     *
     * ## OPTIONS
     * <action>
     * : run or status. The fast_watch setting must be enabled for run.
     * [--timeout=<seconds>]
     * : Default: 300. Zero means unlimited.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function watch(array $args, array $options): void
    {
        self::validateFormat($options);
        if (self::action($args, ['run', 'status']) === 'run') {
            if (!State::enabled('fast_watch')) {
                \WP_CLI::error(__('Critical file monitoring is disabled in settings.', 'site-defense'));
            }
            $timeout = self::timeout($options);
            global $wpdb;
            $lock = 'sd-watch-' . md5($wpdb->options);
            if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s,0)', $lock)) !== 1) {
                \WP_CLI::error(__('A file monitoring operation is already running.', 'site-defense'));
            }
            try {
                FileWatch::start();
                $result = self::finish('sd_watch', [FileWatch::class, 'slice'], $timeout);
            } finally {
                $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
            }
            if ($result !== '') {
                \WP_CLI::error($result);
            }
        }
        self::output(self::watchStatus(), $options);
    }

    /**
     * Check installed component versions against the local vulnerability database.
     *
     * ## OPTIONS
     * [--fail-on-findings]
     * : Exit with code 2 if an affected component is found.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function vulnerabilities(array $args, array $options): void
    {
        self::validateFormat($options);
        Vulnerabilities::check();
        $report = (array) get_option('sd_findings', []);
        self::output($report, $options);
        if (isset($options['fail-on-findings']) && !empty($report['items'])) {
            \WP_CLI::halt(2);
        }
    }

    /**
     * Show database status or import a signed local database package.
     *
     * ## OPTIONS
     * <action>
     * : status or import.
     * [<file>]
     * : Local signed .pack file for import.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function database(array $args, array $options): void
    {
        self::validateFormat($options);
        if (self::action($args, ['status', 'import']) === 'import') {
            self::expect(Vulnerabilities::import(self::package($args, 70 * 1024 * 1024)),
                __('Vulnerability database updated.', 'site-defense'), $options);
            return;
        }
        self::output(['version' => Vulnerabilities::version(), 'status' => get_option('sd_feed_status', [])], $options);
    }

    /**
     * Show firewall rules, change a mode, import or roll back a signed package.
     *
     * ## OPTIONS
     * <action>
     * : status, import, mode, or rollback.
     * [<file-or-id>]
     * : Local signed .pack file for import, or rule ID for mode.
     * [<mode>]
     * : observe, block, or off.
     * [--yes]
     * : Skip rollback confirmation.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function rules(array $args, array $options): void
    {
        self::validateFormat($options);
        switch (self::action($args, ['status', 'import', 'mode', 'rollback'])) {
            case 'import':
                self::expect(Firewall::import(self::package($args, 1024 * 1024)),
                    __('Firewall rules updated.', 'site-defense'), $options);
                break;
            case 'mode':
                self::expect(Firewall::setMode($args[1] ?? '', $args[2] ?? ''),
                    __('Firewall rule mode saved.', 'site-defense'), $options);
                break;
            case 'rollback':
                \WP_CLI::confirm(__('Roll back firewall package', 'site-defense') . '?', $options);
                self::expect(Firewall::rollback(), __('Previous firewall package restored.', 'site-defense'), $options);
                break;
            default:
                self::output(Firewall::status(), $options);
        }
    }

    /**
     * Show malware signature metadata or import a separately signed local package.
     *
     * ## OPTIONS
     * <action>
     * : status or import.
     * [<file>]
     * : Local signed .pack file for import.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function malware(array $args, array $options): void
    {
        self::validateFormat($options);
        if (self::action($args, ['status', 'import']) === 'import') {
            self::expect(Malware::import(self::package($args, 1024 * 1024)), __('Malware signatures updated.', 'site-defense'), $options);
            return;
        }
        $database = Malware::rules();
        self::output(['schema' => $database['schema'], 'version' => $database['version'], 'rules' => $database['rules']], $options);
    }

    /**
     * List quarantined files, move a scan finding, or restore a stored copy.
     *
     * ## OPTIONS
     * <action>
     * : list, move, or restore.
     * [<selection>]
     * : Finding selector from scan results for move, quarantine entry ID for restore.
     * [--page=<page>]
     * : List page, starting at 1.
     * [--yes]
     * : Skip confirmation for move or restore.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function quarantine(array $args, array $options): void
    {
        self::validateFormat($options);
        $action = self::action($args, ['list', 'move', 'restore']);
        if (!Quarantine::install()) {
            \WP_CLI::error(__('Quarantine storage is unavailable.', 'site-defense'));
        }
        if ($action === 'list') {
            $page = self::positiveId($options['page'] ?? '1');
            self::output(array_slice(Quarantine::entries($page), 0, Quarantine::PAGE_SIZE), $options);
            return;
        }
        $selection = $args[1] ?? '';
        if ($action === 'move') {
            if (!preg_match('/^[a-f0-9]{64}$/D', $selection)) {
                \WP_CLI::error(__('Use a finding selector from scan results.', 'site-defense'));
            }
            \WP_CLI::confirm(__('Move this scan finding to quarantine?', 'site-defense'), $options);
            self::expect(Quarantine::move($selection), __('File moved to quarantine.', 'site-defense'), $options);
            return;
        }
        $id = self::positiveId($selection);
        \WP_CLI::confirm(__('Restore this quarantined file to its original path?', 'site-defense'), $options);
        self::expect(Quarantine::restore($id), __('File restored to its original location.', 'site-defense'), $options);
    }

    /**
     * Preview or apply a verified file repair, or undo it using quarantine.
     *
     * ## OPTIONS
     * <action>
     * : preview, apply, or undo.
     * <selection>
     * : Finding selector for preview, preview ID for apply, or quarantine entry ID for undo.
     * [--yes]
     * : Skip confirmation for apply or undo.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function repair(array $args, array $options): void
    {
        self::validateFormat($options);
        $action = self::action($args, ['preview', 'apply', 'undo']);
        $selection = $args[1];
        if ($action === 'preview') {
            $result = FileRepair::preview($selection, true);
        } elseif ($action === 'apply') {
            $plan = FileRepair::plan($selection, true);
            if (!$plan) {
                \WP_CLI::error(__('The repair preview expired. Create a new preview.', 'site-defense'));
            }
            \WP_CLI::confirm(sprintf(__('Replace %s with the verified file and quarantine the original?', 'site-defense'), $plan['path']), $options);
            $result = FileRepair::apply($selection, true);
        } else {
            $id = self::positiveId($selection);
            \WP_CLI::confirm(__('Return the previous file? It may contain the suspicious code found during the scan.', 'site-defense'), $options);
            $result = FileRepair::undo($id);
        }
        if (is_wp_error($result)) {
            $id = $result->get_error_data()['quarantine_id'] ?? 0;
            \WP_CLI::error($result->get_error_message() . ($id ? ' ' . sprintf(__('Quarantine entry: #%d.', 'site-defense'), $id) : ''));
        }
        unset($result['owner']);
        self::output($result, $options);
    }

    /**
     * List incidents or run a confirmed incident response action.
     *
     * ## OPTIONS
     * <action>
     * : list or respond.
     * [<id>]
     * : Incident ID for respond.
     * [<response>]
     * : sessions, password, scan, quarantine, or resolve.
     * [--page=<page>]
     * : List page, starting at 1.
     * [--yes]
     * : Skip response confirmation.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function incidents(array $args, array $options): void
    {
        self::validateFormat($options);
        if (self::action($args, ['list', 'respond']) === 'list') {
            self::output(array_slice(Incidents::recent(self::positiveId($options['page'] ?? '1')), 0, 25), $options);
            return;
        }
        $id = self::positiveId($args[1] ?? '');
        $response = $args[2] ?? '';
        $success = [
            'sessions' => __('Browser sessions revoked.', 'site-defense'),
            'password' => __('Application password revoked.', 'site-defense'),
            'scan' => __('Scan is queued.', 'site-defense'),
            'quarantine' => __('File moved to quarantine.', 'site-defense'),
            'resolve' => __('Incident marked as reviewed.', 'site-defense'),
        ];
        if (!isset($success[$response])) {
            \WP_CLI::error(__('Invalid incident response action.', 'site-defense'));
        }
        \WP_CLI::confirm(__('Apply this incident response action?', 'site-defense'), $options);
        self::expect(Incidents::respond($id, 'incident_' . $response), $success[$response], $options);
    }

    /**
     * Preview or change the site's temporary incident mode.
     *
     * ## OPTIONS
     * <action>
     * : status, preview, start, or stop.
     * [--minutes=<minutes>]
     * : Duration between 5 and 1440 minutes. Default: 60.
     * [--sessions=<ids>]
     * : Comma-separated user IDs whose browser sessions will be revoked.
     * [--passwords=<targets>]
     * : Comma-separated user-id:uuid pairs for application passwords.
     * [--yes]
     * : Confirm a change without prompting.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function response(array $args, array $options): void
    {
        self::validateFormat($options);
        $action = self::action($args, ['status', 'preview', 'start', 'stop']);
        if ($action === 'status') {
            self::output(ResponseMode::status(), $options);
            return;
        }
        if ($action === 'stop') {
            \WP_CLI::confirm(__('Disable incident mode?', 'site-defense'), $options);
            $result = ResponseMode::stop();
        } else {
            $plan = ResponseMode::plan($options['minutes'] ?? '60', $options['sessions'] ?? '', $options['passwords'] ?? '', false);
            if (is_wp_error($plan)) {
                \WP_CLI::error($plan->get_error_message());
            }
            if ($action === 'preview') {
                self::output($plan, $options);
                return;
            }
            \WP_CLI::confirm(__('Enable incident mode and apply the selected revocations?', 'site-defense'), $options);
            $result = ResponseMode::start($plan, false);
        }
        if (is_wp_error($result)) {
            \WP_CLI::error($result->get_error_message());
        }
        self::output($result, $options);
        if (!empty($result['sessions_failed']) || !empty($result['passwords_failed'])) {
            \WP_CLI::halt(1);
        }
    }

    /**
     * Export the incident timeline to standard output.
     *
     * ## OPTIONS
     * [--hours=<hours>]
     * : Lookback from 1 to 336 hours. Default: 24.
     * [--limit=<limit>]
     * : Maximum rows from 1 to 10000. Default: 1000.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function timeline(array $args, array $options): void
    {
        self::validateFormat($options);
        $hours = self::positiveId($options['hours'] ?? '24');
        $limit = self::positiveId($options['limit'] ?? '1000');
        if ($hours > 336 || $limit > 10000) {
            \WP_CLI::error(__('Use up to 336 hours and 10000 timeline entries.', 'site-defense'));
        }
        self::output(Timeline::read($hours, $limit), $options);
    }

    /**
     * Start the local Site Defense MCP server over stdin/stdout.
     *
     * ## OPTIONS
     * [--access-log=<path>]
     * : Local site-specific proxy log (Site Defense JSON lines or combined).
     */
    public function mcp(array $args, array $options): void
    {
        self::investigator();
        require_once SITE_DEFENSE_DIR . '/includes/LocalMcp.php';
        LocalMcp::serve(self::accessLog($options));
    }

    /**
     * Export an incident investigation to standard output.
     *
     * ## OPTIONS
     * [--hours=<hours>]
     * : Lookback from 1 to 168 hours, default 24.
     * [--limit=<limit>]
     * : Maximum items per source from 1 to 200, default 80.
     * [--access-log=<path>]
     * : Local site-specific proxy log (Site Defense JSON lines or combined).
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function investigate(array $args, array $options): void
    {
        self::investigator();
        self::validateFormat($options);
        $hours = self::positiveId($options['hours'] ?? '24');
        $limit = self::positiveId($options['limit'] ?? '80');
        if ($hours > 168 || $limit > 200) {
            \WP_CLI::error(__('Use up to 168 hours and 200 entries per source.', 'site-defense'));
        }
        self::output(Investigation::report($hours, $limit, self::accessLog($options)), $options);
    }

    /**
     * Prepare, inspect, verify, apply or undo a cleanup plan.
     *
     * ## OPTIONS
     * <action>
     * : prepare, show, preview, verify, apply, or undo.
     * <selection>
     * : Comma-separated target IDs for prepare, or a plan ID.
     * [<step>]
     * : Exact step ID for preview, apply or undo. Preview displays a database content step.
     * [--repair-preview=<id>]
     * : Verified repair preview ID for a repair step.
     * [--yes]
     * : Apply or undo the selected step without an interactive prompt.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function cleanup(array $args, array $options): void
    {
        self::investigator();
        self::validateFormat($options);
        $action = self::action($args, ['prepare', 'show', 'preview', 'verify', 'apply', 'undo']);
        $id = $args[1];
        if ($action === 'prepare') {
            $result = CleanupPlan::create(explode(',', $id));
        } elseif ($action === 'preview') {
            $result = CleanupPlan::preview($id, $args[2] ?? '');
        } elseif ($action === 'verify') {
            $result = CleanupVerification::verify($id);
        } else {
            $plan = CleanupPlan::show($id);
            if (!$plan) {
                \WP_CLI::error(__('Cleanup plan or step was not found.', 'site-defense'));
            }
            $result = $plan;
            if (in_array($action, ['apply', 'undo'], true)) {
                $stepId = $args[2] ?? '';
                $step = $plan['steps'][$stepId] ?? null;
                if (!$step || !current_user_can('manage_options')) {
                    \WP_CLI::error(__('Cleanup step unavailable or permission denied.', 'site-defense'));
                }
                if ($action === 'undo') {
                    $prompt = $step['type'] === 'db_content'
                        ? __('Restore the original database field %s? The selected script or redirect may return.', 'site-defense')
                        : __('Return the original target %s? Suspicious code or scheduled actions may return.', 'site-defense');
                    \WP_CLI::confirm(sprintf($prompt, $step['target']), $options);
                } else {
                    \WP_CLI::confirm(sprintf(__('Apply the selected cleanup step to %s?', 'site-defense'), $step['target']), $options);
                }
                $result = CleanupPlan::change($id, $stepId, $action === 'undo', $options['repair-preview'] ?? '');
            }
        }
        if (is_wp_error($result)) {
            \WP_CLI::error($result->get_error_message());
        }
        self::output($result, $options);
    }

    private static function investigator(): void
    {
        if (!Investigation::allowed()) {
            \WP_CLI::error(__('Select a WordPress user with Site Defense investigation access using --user.', 'site-defense'));
        }
    }

    private static function accessLog(array $options): string
    {
        if (!isset($options['access-log'])) {
            return '';
        }
        $path = realpath($options['access-log']);
        if (!$path || !is_file($path) || !is_readable($path)) {
            \WP_CLI::error(__('The selected web access log is unavailable.', 'site-defense'));
        }
        return $path;
    }

    /**
     * Show heartbeat status or send a test to the configured receiver.
     *
     * ## OPTIONS
     * <action>
     * : status or send.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function heartbeat(array $args, array $options): void
    {
        self::validateFormat($options);
        if (self::action($args, ['status', 'send']) === 'send') {
            self::expect(Heartbeat::send(), __('Heartbeat delivered.', 'site-defense'), $options);
            return;
        }
        self::output(Heartbeat::status(), $options);
    }

    /**
     * Revoke all browser sessions belonging to a WordPress user.
     *
     * @subcommand revoke-sessions
     *
     * ## OPTIONS
     * <user-id>
     * : Numeric WordPress user ID.
     * [--yes]
     * : Skip confirmation.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function revoke_sessions(array $args, array $options): void
    {
        self::validateFormat($options);
        $id = self::positiveId($args[0]);
        if (!get_userdata($id)) {
            \WP_CLI::error(__('User not found.', 'site-defense'));
        }
        \WP_CLI::confirm(__('Revoke all browser sessions for this user?', 'site-defense'), $options);
        \WP_Session_Tokens::get_instance($id)->destroy_all();
        State::log('session_revoked', 'Browser sessions revoked for user #' . $id, context: ['user_id' => $id]);
        self::output(['success' => true, 'user_id' => $id], $options);
    }

    /**
     * Deliver pending alerts, send a test, or inspect channel status.
     *
     * ## OPTIONS
     * <action>
     * : deliver, test, or status. Deliver and test contact configured receivers.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function notifications(array $args, array $options): void
    {
        self::validateFormat($options);
        $action = self::action($args, ['deliver', 'test', 'status']);
        if ($action === 'test') {
            self::expect(Alerts::test(), __('Test notification sent.', 'site-defense'), $options);
            return;
        }
        if ($action === 'deliver') {
            EarlyProtection::drain();
            Alerts::deliver();
        }
        global $wpdb;
        $table = State::table('incidents');
        $extra = Alerts::config();
        self::output([
            'pending' => (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE pending=1"),
            'last_worker' => (int) get_option('sd_alert_worker', 0),
            'email_enabled' => State::enabled('notify'),
            'telegram_enabled' => (bool) $extra['telegram'], 'webhook_enabled' => (bool) $extra['webhook'],
        ], $options);
    }

    /**
     * Inspect or explicitly enable/disable mandatory privileged-account 2FA.
     *
     * ## OPTIONS
     * <action>
     * : status, enable, or disable. The policy is disabled by default.
     * [--yes]
     * : Skip policy change confirmation.
     * [--format=<format>]
     * : json or table. Default: json.
     */
    public function policy(array $args, array $options): void
    {
        self::validateFormat($options);
        $action = self::action($args, ['status', 'enable', 'disable']);
        if ($action !== 'status') {
            if ($action === 'enable' && (!function_exists('sodium_crypto_secretbox') ||
                wp_parse_url(wp_login_url(), PHP_URL_SCHEME) !== 'https')) {
                \WP_CLI::error(__('Two-factor enrollment requires HTTPS and PHP Sodium.', 'site-defense'));
            }
            \WP_CLI::confirm(__('Change the mandatory two-factor policy?', 'site-defense'), $options);
            $settings = State::settings();
            $settings['require_2fa'] = $action === 'enable';
            update_option('sd_settings', $settings);
            State::log('protection_changed', 'Protection settings changed', true);
        }
        self::output(['require_2fa' => State::enabled('require_2fa')], $options);
    }

    /**
     * Audit stored privileges, WP-Cron, scripts and redirects.
     *
     * ## OPTIONS
     * <action>
     * : run, status, findings, trusted, trust, or untrust.
     * [<user-id>]
     * : Account ID for trust or untrust.
     * [<fingerprint>]
     * : Privileges fingerprint from findings for trust.
     * [--timeout=<seconds>]
     * : Run timeout. Zero means unlimited. Default: 300.
     * [--fail-on-findings]
     * : Exit with code 2 when a completed report contains findings.
     * [--yes]
     * : Confirm changes to trusted accounts.
     * [--format=<format>]
     * : json or table. Default: json.
     *
     * @subcommand db-audit
     */
    public function dbAudit(array $args, array $options): void
    {
        self::validateFormat($options);
        $action = self::action($args, ['run', 'status', 'findings', 'trusted', 'trust', 'untrust']);
        if ($action === 'trust' || $action === 'untrust') {
            $id = self::positiveId($args[1] ?? '');
            $fingerprint = $args[2] ?? '';
            if ($action === 'trust' && !preg_match('/^[a-f0-9]{64}$/D', $fingerprint)) {
                \WP_CLI::error(__('Use the account fingerprint from the database findings.', 'site-defense'));
            }
            \WP_CLI::confirm(__('Change the account confirmation?', 'site-defense'), $options);
            $message = $action === 'trust' ? DbAudit::trust($id, $fingerprint) : DbAudit::untrust($id);
            self::expect($message, $action === 'trust' ? __('Account privileges confirmed.', 'site-defense')
                : __('Account confirmation removed.', 'site-defense'), $options);
            return;
        }
        if ($action === 'trusted') {
            self::output(DbAudit::trusted(), $options);
            return;
        }
        if ($action === 'run') {
            $timeout = self::timeout($options);
            $error = DbAudit::locked(static function () use ($timeout): string {
                $message = DbAudit::start();
                return $message === __('Database audit queued.', 'site-defense')
                    ? self::finish('sd_db_audit', [DbAudit::class, 'slice'], $timeout) : $message;
            });
            if ($error !== '') {
                \WP_CLI::error($error);
            }
        }
        $report = DbAudit::report();
        $findings = $report['findings'] ?? [];
        if ($action === 'findings') {
            if (($options['format'] ?? 'json') === 'table') {
                \WP_CLI\Utils\format_items('table', $findings, ['type', 'source', 'id', 'location', 'object_id']);
            } else {
                self::output($findings, $options);
            }
        } else {
            $report['status'] ??= 'idle';
            $report['finding_count'] = array_sum($report['counts'] ?? []);
            $report['listed_findings'] = count($findings);
            unset($report['findings'], $report['phase'], $report['cursor']);
            self::output($report, $options);
        }
        if (isset($options['fail-on-findings']) && ($report['status'] ?? '') === 'complete' && array_sum($report['counts'] ?? []) > 0) {
            \WP_CLI::halt(2);
        }
    }

    private static function action(array $args, array $allowed): string
    {
        $action = $args[0] ?? '';
        if (!in_array($action, $allowed, true)) {
            \WP_CLI::error(sprintf(__('Choose an action: %s', 'site-defense'), implode(', ', $allowed)));
        }
        return $action;
    }

    private static function positiveId(string $value): int
    {
        $id = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        if ($id === false) {
            \WP_CLI::error(__('Enter a positive numeric ID or page number.', 'site-defense'));
        }
        return $id;
    }

    private static function timeout(array $options): int
    {
        $timeout = filter_var($options['timeout'] ?? '300', FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
        if ($timeout === false) {
            \WP_CLI::error(__('Timeout must be a nonnegative number of seconds.', 'site-defense'));
        }
        return $timeout;
    }

    private static function finish(string $option, callable $slice, int $timeout): string
    {
        $started = microtime(true);
        while ((get_option($option, [])['status'] ?? '') === 'running') {
            $slice();
            if ($timeout && microtime(true) - $started >= $timeout &&
                (get_option($option, [])['status'] ?? '') === 'running') {
                return __('Time limit reached. Progress is saved. Run the command again to continue.', 'site-defense');
            }
        }
        return (get_option($option, [])['status'] ?? '') === 'complete' ? ''
            : __('The operation stopped before completion. Check its status.', 'site-defense');
    }

    private static function scanStatus(): array
    {
        $scan = (array) get_option('sd_scan', []);
        return [
            'status' => $scan['status'] ?? 'idle', 'files' => $scan['files'] ?? 0,
            'finding_count' => $scan['finding_count'] ?? count($scan['findings'] ?? []),
            'stored_findings' => count($scan['findings'] ?? []),
            'started' => $scan['started'] ?? 0, 'last_run' => $scan['last_run'] ?? 0,
            'last_success' => $scan['last_success'] ?? 0,
            'scope_version' => $scan['scope_version'] ?? 0,
            'signature_version' => $scan['signature_version'] ?? 0,
            'skipped_count' => $scan['skipped_count'] ?? 0,
            'skip_reasons' => $scan['skip_reasons'] ?? [], 'report_error' => !empty($scan['report_error']),
            'excluded_count' => $scan['excluded_count'] ?? 0, 'bytes_read' => $scan['bytes'] ?? 0,
            'duration_seconds' => round($scan['duration'] ?? 0, 3), 'peak_memory_bytes' => $scan['peak_memory'] ?? 0,
        ];
    }

    private static function watchStatus(): array
    {
        return array_intersect_key((array) get_option('sd_watch', []), array_flip([
            'status', 'started', 'completed', 'last_run', 'checked',
        ]));
    }

    private static function package(array $args, int $limit): string
    {
        $path = $args[1] ?? '';
        if ($path === '' || str_contains($path, '://') || !is_file($path) || !is_readable($path)) {
            \WP_CLI::error(__('Choose a readable local signed package.', 'site-defense'));
        }
        $size = filesize($path);
        if ($size === false || $size <= 64 || $size > $limit) {
            \WP_CLI::error(__('Invalid database package size.', 'site-defense'));
        }
        $data = file_get_contents($path, false, null, 0, $limit + 1);
        if ($data === false || strlen($data) !== $size) {
            \WP_CLI::error(__('Unable to read the complete signed package.', 'site-defense'));
        }
        return $data;
    }

    private static function expect(string $message, string $expected, array $options): void
    {
        if ($message !== $expected) {
            \WP_CLI::error($message);
        }
        self::output(['success' => true, 'message' => $message], $options);
    }

    private static function validateFormat(array $options): void
    {
        if (!in_array($options['format'] ?? 'json', ['json', 'table'], true)) {
            \WP_CLI::error(__('Output format must be json or table.', 'site-defense'));
        }
    }

    private static function output(array $data, array $options): void
    {
        $format = $options['format'] ?? 'json';
        if ($format === 'json') {
            \WP_CLI::line(wp_json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            return;
        }
        $rows = [];
        foreach ($data as $key => $value) {
            $rows[] = ['key' => (string) $key, 'value' => is_string($value) ? $value : wp_json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)];
        }
        \WP_CLI\Utils\format_items('table', $rows, ['key', 'value']);
    }
}
