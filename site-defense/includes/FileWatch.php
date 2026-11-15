<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class FileWatch
{
    public static function register(): void
    {
        add_action('sd_watch_tick', [self::class, 'start']);
        add_action('sd_watch_slice', [self::class, 'slice']);
        if (!wp_next_scheduled('sd_watch_tick')) {
            wp_schedule_event(time() + 60, 'sd_five_minutes', 'sd_watch_tick');
        }
    }

    private static function install(): void
    {
        if (get_option('sd_watch_schema') === '2') {
            return;
        }
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $table = State::table('watched');
        $charset = $wpdb->get_charset_collate();
        dbDelta("CREATE TABLE $table (
            path_key char(64) NOT NULL,
            digest char(64) NOT NULL,
            path text NOT NULL,
            generation bigint unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (path_key)
        ) $charset;");
        update_option('sd_watch_schema', '2');
    }

    public static function start(): void
    {
        if (!State::enabled('fast_watch')) {
            return;
        }
        self::install();
        $watch = (array) get_option('sd_watch', []);
        if (($watch['status'] ?? '') !== 'running') {
            $uploads = wp_get_upload_dir();
            $content = WP_CONTENT_DIR;
            $files = [];
            foreach (['advanced-cache.php', 'object-cache.php', 'db.php', 'sunrise.php'] as $dropin) {
                $files[] = $content . '/' . $dropin;
            }
            $files = array_merge($files, [ABSPATH . 'wp-config.php', ABSPATH . '.user.ini', ABSPATH . '.htaccess']);
            $directories = [WPMU_PLUGIN_DIR];
            if (!empty($uploads['basedir'])) {
                $directories[] = $uploads['basedir'];
            }
            $watch = [
                'status' => 'running', 'started' => time(), 'baseline' => !empty($watch['completed']),
                'generation' => max(time(), (int) ($watch['generation'] ?? 0) + 1),
                'completed' => $watch['completed'] ?? 0, 'files' => $files,
                'queue' => array_map(static fn ($dir) => [$dir, ''], $directories), 'checked' => 0,
            ];
            update_option('sd_watch', $watch, false);
        }
        self::schedule();
        if (wp_doing_cron()) {
            self::slice();
        }
    }

    private static function schedule(): void
    {
        if (!wp_next_scheduled('sd_watch_slice')) {
            wp_schedule_single_event(time() + 1, 'sd_watch_slice');
        }
    }

    public static function slice(): void
    {
        if (!State::enabled('fast_watch')) {
            return;
        }
        global $wpdb;
        $lock = 'sd-watch-' . md5($wpdb->options);
        if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s,0)', $lock)) !== 1) {
            return;
        }
        try {
            $watch = (array) get_option('sd_watch', []);
            if (($watch['status'] ?? '') !== 'running') {
                return;
            }
            self::schedule();
            $deadline = microtime(true) + 2;
            $walked = 0;
            while ($walked < 200 && microtime(true) < $deadline) {
                if ($watch['files']) {
                    self::inspect(array_shift($watch['files']), $watch);
                    $walked++;
                    continue;
                }
                if (!$watch['queue']) {
                    $table = State::table('watched');
                    $missing = $wpdb->get_results($wpdb->prepare(
                        "SELECT path,digest FROM $table WHERE generation<>%d LIMIT 1000", $watch['generation']
                    ), ARRAY_A) ?: [];
                    foreach ($missing as $row) {
                        if ($row['path'] !== '') {
                            State::log('file_changed', $row['path'], true, ['path' => $row['path'], 'digest' => $row['digest']]);
                        }
                    }
                    $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE generation<>%d", $watch['generation']));
                    $watch['status'] = 'complete';
                    $watch['completed'] = time();
                    wp_clear_scheduled_hook('sd_watch_slice');
                    break;
                }
                [$dir, $cursor] = $watch['queue'][0];
                if (is_link($dir) || !is_dir($dir) || !is_readable($dir)) {
                    array_shift($watch['queue']);
                    $walked++;
                    continue;
                }
                $names = @scandir($dir);
                if ($names === false) {
                    array_shift($watch['queue']);
                    $walked++;
                    continue;
                }
                foreach ($names as $name) {
                    if ($name === '.' || $name === '..' || strcmp($name, $cursor) <= 0) {
                        continue;
                    }
                    $watch['queue'][0][1] = $name;
                    $file = trailingslashit($dir) . $name;
                    if (!is_link($file)) {
                        if (is_dir($file)) {
                            $watch['queue'][] = [$file, ''];
                        } elseif (Scanner::executable($name) || in_array($name, ['.user.ini', '.htaccess'], true)) {
                            self::inspect($file, $watch);
                        }
                    }
                    $walked++;
                    if ($walked >= 200 || microtime(true) >= $deadline) {
                        break 2;
                    }
                }
                array_shift($watch['queue']);
            }
            $watch['last_run'] = time();
            update_option('sd_watch', $watch, false);
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
        Alerts::deliver();
    }

    private static function inspect(string $file, array &$watch): void
    {
        if (is_link($file) || !is_file($file) || !is_readable($file)) {
            return;
        }
        $size = filesize($file);
        if ($size === false || $size > Scanner::MAX_FILE_SIZE) {
            return;
        }
        $digest = @hash_file('sha256', $file);
        if (!$digest) {
            return;
        }
        global $wpdb;
        $table = State::table('watched');
        $key = hash('sha256', wp_normalize_path($file));
        $previous = $wpdb->get_var($wpdb->prepare("SELECT digest FROM $table WHERE path_key=%s", $key));
        $watch['checked']++;
        $path = wp_normalize_path($file);
        $root = wp_normalize_path(ABSPATH);
        $path = str_starts_with($path, $root) ? substr($path, strlen($root)) : $path;
        $wpdb->replace($table, [
            'path_key' => $key, 'digest' => $digest, 'path' => $path, 'generation' => $watch['generation'],
        ], ['%s', '%s', '%s', '%d']);
        if ($previous === $digest) {
            return;
        }
        $excluded = ScanReport::excludedDigest($file);
        if ($excluded !== null && hash_equals($excluded, $digest)) {
            return;
        }
        $uploads = wp_get_upload_dir();
        $executableUpload = !empty($uploads['basedir']) && Scanner::executable($file) &&
            str_starts_with(wp_normalize_path($file), trailingslashit(wp_normalize_path($uploads['basedir'])));
        $finding = $executableUpload ? 'Executable file in uploads' : '';
        if ($finding === '' && Scanner::executable($file)) {
            foreach (['Suspicious code signature: obfuscated execution', 'Suspicious code signature: request passed to shell'] as $signature) {
                if (Scanner::recheck('watch', $file, $signature)) {
                    $finding = $signature;
                    break;
                }
            }
        }
        if ($watch['baseline'] || $finding !== '') {
            $kind = $finding !== '' ? 'file_detected' : 'file_changed';
            $context = ['path' => $path, 'digest' => $digest];
            if ($finding !== '') {
                $context['finding'] = $finding;
            }
            State::log($kind, $path, true, $context);
        }
    }
}

