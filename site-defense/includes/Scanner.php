<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Scanner
{
    private const LIMIT = 500;
    public const MAX_FILE_SIZE = 64 * 1024 * 1024;

    public const QUARANTINE_FINDINGS = [
        'Executable file in uploads',
        'Differs from official checksum',
        'Suspicious code signature: obfuscated execution',
        'Suspicious code signature: request passed to shell',
        'Suspicious PHP data flow', 'Possible PHP loader write',
        'Encoded JavaScript execution', 'Malware signature matched',
    ];

    public static function register(): void
    {
        add_action('sd_daily', static function (): void {
            if (State::enabled('scan_auto') && (get_option('sd_scan', [])['status'] ?? '') !== 'paused') {
                self::command('start');
            }
        });
        add_action('sd_scan_slice', [self::class, 'slice']);
    }

    public static function locked(callable $operation): string
    {
        global $wpdb;
        $lock = 'sd-scan-' . md5($wpdb->options);
        if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $lock)) !== 1) {
            return __('A scan operation is already running.', 'site-defense');
        }
        try {
            return $operation();
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }

    public static function roots(): array
    {
        $candidates = [['site', ABSPATH], ['content', WP_CONTENT_DIR], ['plugins', WP_PLUGIN_DIR], ['plugins', WPMU_PLUGIN_DIR]];
        foreach (array_unique(array_merge([get_theme_root()], (array) ($GLOBALS['wp_theme_directories'] ?? []))) as $directory) {
            $candidates[] = ['themes', $directory];
        }
        $uploads = wp_get_upload_dir();
        if (!empty($uploads['basedir'])) {
            $candidates[] = ['uploads', $uploads['basedir']];
        }
        $roots = [];
        foreach ($candidates as [$type, $directory]) {
            $covered = false;
            foreach ($roots as $root) {
                $covered = $covered || self::within($directory, $root[1]);
            }
            if (!$covered) {
                $roots[] = [$type, $directory];
            }
        }
        return $roots;
    }

    private static function within(string $path, string $root): bool
    {
        $path = trailingslashit(wp_normalize_path($path));
        $root = trailingslashit(wp_normalize_path($root));
        return PHP_OS_FAMILY === 'Windows' ? str_starts_with(strtolower($path), strtolower($root)) : str_starts_with($path, $root);
    }

    public static function typeFor(string $file): string
    {
        $uploads = wp_get_upload_dir();
        if (!empty($uploads['basedir']) && self::within($file, $uploads['basedir'])) {
            return 'uploads';
        }
        if (self::within($file, WP_PLUGIN_DIR)) {
            return 'plugins';
        }
        if (self::within($file, ABSPATH . 'wp-admin') || self::within($file, ABSPATH . WPINC) ||
            (wp_normalize_path(dirname($file)) === untrailingslashit(wp_normalize_path(ABSPATH)) &&
                basename($file) !== 'wp-config.php' && str_ends_with($file, '.php'))) {
            return 'core';
        }
        return 'site';
    }

    public static function relativePath(string $path): string
    {
        $path = wp_normalize_path($path);
        $root = wp_normalize_path(ABSPATH);
        return str_starts_with($path, $root) ? substr($path, strlen($root)) : $path;
    }

    public static function linked(string $path): bool
    {
        $path = untrailingslashit($path);
        if (is_link($path)) {
            return true;
        }
        // PHP on Windows does not consistently identify NTFS junctions with is_link().
        $parent = realpath(dirname($path));
        $actual = realpath($path);
        if ($parent === false || $actual === false) {
            return false;
        }
        $expected = wp_normalize_path($parent . '/' . basename($path));
        $actual = wp_normalize_path($actual);
        return PHP_OS_FAMILY === 'Windows' ? strcasecmp($actual, $expected) !== 0 : $actual !== $expected;
    }

    public static function command(string $action): string
    {
        return self::locked(static function () use ($action): string {
            $scan = (array) get_option('sd_scan', []);
            if (in_array($action, ['start', 'resume'], true) && ($scan['scope_version'] ?? 0) !== 2) {
                $action = 'start';
                $scan['status'] = 'outdated';
            }
            if ($action === 'cancel' && ($scan['status'] ?? '') === 'running') {
                $scan['status'] = 'paused';
                update_option('sd_scan', $scan, false);
                wp_clear_scheduled_hook('sd_scan_slice');
                return __('Scan paused.', 'site-defense');
            }
            if ($action === 'resume' && ($scan['status'] ?? '') === 'paused') {
                $scan['status'] = 'running';
            }
            if ($action === 'start' && ($scan['status'] ?? '') !== 'running') {
                if (!ScanReport::start()) {
                    return __('Scan report storage is unavailable.', 'site-defense');
                }
                $database = Malware::rules();
                $scan = [
                    'status' => 'running', 'files' => 0, 'findings' => [], 'started' => time(),
                    'last_success' => $scan['last_success'] ?? 0, 'last_run' => 0, 'references' => [],
                    'id' => wp_generate_uuid4(), 'scope_version' => 2,
                    'malware_rules' => $database, 'signature_version' => $database['version'],
                    'skipped_count' => 0, 'skip_reasons' => [], 'excluded_count' => 0,
                    'bytes' => 0, 'duration' => 0, 'peak_memory' => 0,
                    'queue' => array_map(static fn ($root) => [$root[0], $root[1], ''], self::roots()),
                ];
            }
            if (($scan['status'] ?? '') === 'running') {
                update_option('sd_scan', $scan, false);
                self::schedule();
                return __('Scan is queued.', 'site-defense');
            }
            return __('No scan to resume or pause.', 'site-defense');
        });
    }

    private static function schedule(): void
    {
        if (!wp_next_scheduled('sd_scan_slice')) {
            wp_schedule_single_event(time() + 5, 'sd_scan_slice');
        }
    }

    public static function slice(): void
    {
        self::locked(static function (): string {
            $scan = (array) get_option('sd_scan', []);
            if (($scan['status'] ?? '') !== 'running') {
                return '';
            }
            if (($scan['scope_version'] ?? 0) !== 2) {
                return self::command('start');
            }
            // Schedule the next slice first so a PHP timeout can recover from the last saved cursor.
            self::schedule();
            $sliceStarted = microtime(true);
            $deadline = $sliceStarted + 3;
            $walked = 0;
            $references = [];
            while ($walked < 150 && microtime(true) < $deadline) {
                if (empty($scan['queue'])) {
                    $scan['status'] = 'complete';
                    $scan['last_success'] = time();
                    wp_clear_scheduled_hook('sd_scan_slice');
                    break;
                }
                [$type, $dir, $cursor] = $scan['queue'][0];
                if (self::linked($dir) || !is_dir($dir) || !is_readable($dir)) {
                    array_shift($scan['queue']);
                    ScanReport::skipped($scan, $dir, self::linked($dir) ? 'Symbolic link is not followed' : 'Directory could not be read', 0, false, 'directory');
                    $walked++;
                    continue;
                }
                $list = @scandir($dir);
                if ($list === false) {
                    array_shift($scan['queue']);
                    ScanReport::skipped($scan, $dir, 'Directory could not be read', 0, false, 'directory');
                    $walked++;
                    continue;
                }
                foreach ($list as $name) {
                    if ($name === '.' || $name === '..' || strcmp($name, $cursor) <= 0) {
                        continue;
                    }
                    $scan['queue'][0][2] = $name;
                    $file = trailingslashit($dir) . $name;
                    if (self::linked($file)) {
                        ScanReport::skipped($scan, $file, 'Symbolic link is not followed', 0, false, is_dir($file) ? 'directory' : 'file');
                    } elseif (is_dir($file)) {
                        $scan['queue'][] = [$type, $file, ''];
                    } else {
                        self::inspect($scan, self::typeFor($file), $file, $references);
                    }
                    $walked++;
                    if ($walked >= 150 || microtime(true) >= $deadline) {
                        break 2;
                    }
                }
                array_shift($scan['queue']);
            }
            $scan['last_run'] = time();
            $scan['duration'] += microtime(true) - $sliceStarted;
            $scan['peak_memory'] = max($scan['peak_memory'], memory_get_peak_usage(true));
            update_option('sd_scan', $scan, false);
            return '';
        });
    }

    public static function executable(string $name): bool
    {
        return (bool) preg_match('/\.(?:php[0-9]?|phtml|phar|pht|cgi|pl)(?:\.|$)/i', $name);
    }

    private static function finding(array &$scan, string $status, string $path, ?string $digest = null, array $details = []): void
    {
        $scan['finding_count'] = ($scan['finding_count'] ?? 0) + 1;
        if (count($scan['findings']) < self::LIMIT) {
            $scan['findings'][] = [$status, self::relativePath($path), $digest, $details];
        }
    }

    private static function inspect(array &$scan, string $type, string $file, array &$references): void
    {
        if (self::linked($file) || !is_file($file) || !is_readable($file)) {
            ScanReport::skipped($scan, $file, self::linked($file) ? 'Symbolic link is not followed' : 'File could not be read');
            return;
        }
        $scan['files']++;
        $analysis = Malware::inspect($file, $scan['malware_rules'], ScanReport::excludedDigest($file));
        $scan['bytes'] += $analysis['bytes'];
        foreach ($analysis['skips'] as $reason) {
            ScanReport::skipped($scan, $file, $reason, $analysis['bytes'], $analysis['bytes'] > 0);
        }
        if (in_array('Excluded by matching SHA-256', $analysis['skips'], true)) {
            $scan['excluded_count']++;
            return;
        }
        $findings = self::classify($type, $file, $scan, $references, $analysis);
        $digest = $analysis['digest'];
        foreach ($findings as $finding) {
            self::finding($scan, $finding['finding'], $file, $digest, $finding);
        }
        $actionableFindings = array_filter($findings, static fn ($finding) => ($finding['confidence'] ?? 'medium') !== 'low');
        $labels = array_column($actionableFindings, 'finding');
        if ($digest && array_intersect($labels, self::QUARANTINE_FINDINGS)) {
            $fingerprint = 'sd_seen_' . hash('sha256', $file . $digest);
            if (!get_transient($fingerprint)) {
                set_transient($fingerprint, true, DAY_IN_SECONDS);
                $path = wp_normalize_path($file);
                $root = wp_normalize_path(ABSPATH);
                $path = str_starts_with($path, $root) ? substr($path, strlen($root)) : $path;
                $actionable = array_values(array_intersect($labels, self::QUARANTINE_FINDINGS));
                State::log('file_detected', $path, true, ['path' => $path, 'digest' => $digest, 'finding' => $actionable[0]]);
            }
        }
    }

    public static function recheck(string $type, string $file, string $finding): bool
    {
        $scan = ['findings' => [], 'references' => []];
        $references = [];
        return in_array($finding, array_column(self::classify($type, $file, $scan, $references), 'finding'), true);
    }

    private static function classify(string $type, string $file, array &$scan, array &$references, ?array $analysis = null): array
    {
        $findings = [];
        $exec = self::executable(basename($file));
        if ($type === 'uploads' && $exec) {
            $findings[] = ['finding' => 'Executable file in uploads', 'reason' => 'Executable extension in the upload directory', 'confidence' => 'medium'];
        }
        $analysis ??= Malware::inspect($file, Malware::rules());
        if ($analysis['digest'] !== null) {
            $checksum = self::checksum($type, $file, $scan, $references);
            $actual = is_string($checksum) && strlen($checksum) !== 64 ? @hash_file('md5', $file) : $analysis['digest'];
            if (is_string($checksum) && !hash_equals($checksum, (string) $actual)) {
                $findings[] = ['finding' => 'Differs from official checksum', 'reason' => 'Official checksum mismatch', 'confidence' => 'medium'];
            }
        }
        return array_merge($findings, $analysis['hits']);
    }

    private static function checksum(string $type, string $file, array &$scan, array &$references): ?string
    {
        $reference = OfficialFiles::reference($type, $file);
        if (!$reference) {
            return null;
        }
        $key = $reference['key'];
        $references[$key] ??= OfficialFiles::checksums($reference);
        if (!empty($references[$key]['_unavailable']) && !isset($scan['references'][$key])) {
            $scan['references'][$key] = false;
            self::finding($scan, 'Official checksums unavailable', $key);
        }
        return OfficialFiles::expected($reference, $references[$key]);
    }
}

