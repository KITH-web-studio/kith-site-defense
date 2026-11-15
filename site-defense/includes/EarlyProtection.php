<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class EarlyProtection
{
    private const START = '# BEGIN Site Defense';
    private const END = '# END Site Defense';
    private const MARKER = '{"uploads":"/__sd-runtime-moved__","waf":false}';
    private const CONFIG_HEADER = "<?php exit; // Site Defense early runtime\n?>\n";

    public static function register(): void
    {
        add_action('update_option_sd_settings', [self::class, 'sync']);
        add_action('upgrader_process_complete', [self::class, 'sync']);
        add_action('sd_daily', [self::class, 'sync']);
        add_action('admin_init', [self::class, 'sync']);
        add_action('update_option_WPLANG', [self::class, 'sync']);
        add_action('update_option_home', [self::class, 'sync']);
        add_action('update_option_siteurl', [self::class, 'sync']);
        add_action('init', [self::class, 'syncOnUpgrade']);
        add_action('sd_alert_tick', [self::class, 'drain'], 5);
        add_action('admin_post_sd_early_probe', [self::class, 'probe']);
        add_action('admin_post_nopriv_sd_early_probe', [self::class, 'probe']);
    }

    public static function probe(): void
    {
        $token = State::field($_GET, 'probe');
        $expected = get_transient('sd_early_probe');
        if (!is_string($expected) || !hash_equals($expected, $token)) {
            status_header(404);
            exit;
        }
        wp_send_json(['early' => defined('SD_EARLY_LOADED') && SD_EARLY_LOADED]);
    }

    public static function verify(): string
    {
        $token = bin2hex(random_bytes(24));
        set_transient('sd_early_probe', $token, 60);
        $response = wp_remote_get(add_query_arg(['action' => 'sd_early_probe', 'probe' => $token], admin_url('admin-post.php')), [
            'timeout' => 8, 'redirection' => 0, 'limit_response_size' => 1024,
        ]);
        delete_transient('sd_early_probe');
        $body = json_decode(wp_remote_retrieve_body($response), true);
        $verified = wp_remote_retrieve_response_code($response) === 200 && ($body['early'] ?? false) === true;
        update_option('sd_early_verified', ['time' => time(), 'ok' => $verified], false);
        return $verified ? __('Early protection verified.', 'site-defense')
            : __('Early protection is not active yet. Check hosting settings and the PHP INI cache delay.', 'site-defense');
    }

    public static function install(): string
    {
        $uploads = wp_get_upload_dir();
        if (!empty($uploads['error']) || empty($uploads['basedir']) || !is_dir($uploads['basedir'])) {
            return __('The uploads directory is unavailable.', 'site-defense');
        }
        $loader = ABSPATH . 'sd-prepend.php';
        if (file_exists($loader) && !str_contains((string) file_get_contents($loader), 'Site Defense stable loader')) {
            return __('The early loader path is occupied by another file.', 'site-defense');
        }
        $ini = ABSPATH . '.user.ini';
        $existing = is_file($ini) ? file_get_contents($ini) : '';
        if (!is_string($existing) || (preg_match('/^\s*auto_prepend_file\s*=/mi', self::withoutBlock($existing)))) {
            return __('Another auto_prepend_file setting exists. Configure the early loader in your hosting panel.', 'site-defense');
        }
        $engine = wp_normalize_path(SITE_DEFENSE_DIR . '/early-firewall.php');
        $marker = wp_normalize_path(ABSPATH . '.sd-early.json');
        $contents = "<?php\n// Site Defense stable loader. Keep this file while PHP caches auto_prepend_file.\n" .
            '$sdMarker = ' . var_export($marker, true) . ";\n" .
            'if (is_file($sdMarker) && is_readable(' . var_export($engine, true) . ')) { require ' . var_export($engine, true) . "; }\n";
        if (!self::write($loader, $contents)) {
            return __('Unable to write the early loader.', 'site-defense');
        }
        $prepend = wp_normalize_path($loader);
        $new = rtrim(self::withoutBlock($existing)) . "\n" . self::START . "\nauto_prepend_file = \"" .
            addcslashes($prepend, "\\\"") . "\"\n" . self::END . "\n";
        if (!self::write($ini, $new)) {
            return __('Unable to update .user.ini. Configure the early loader in your hosting panel.', 'site-defense');
        }
        update_option('sd_early_enabled', true);
        if (!self::sync()) {
            return __('Unable to update the early firewall configuration.', 'site-defense');
        }
        self::uploadsGuard(true);
        return __('Early protection configured. Verify it after the PHP INI cache expires.', 'site-defense');
    }

    public static function disable(): void
    {
        delete_option('sd_early_enabled');
        delete_option('sd_early_verified');
        delete_option('sd_early_schema');
        $marker = ABSPATH . '.sd-early.json';
        if (is_file($marker)) {
            @unlink($marker);
        }
        $config = ABSPATH . 'sd-early-config.php';
        if (is_file($config) && @file_get_contents($config, false, null, 0, strlen(self::CONFIG_HEADER)) === self::CONFIG_HEADER) {
            @unlink($config);
        }
        $ini = ABSPATH . '.user.ini';
        if (is_readable($ini)) {
            self::write($ini, self::withoutBlock((string) file_get_contents($ini)));
        }
        self::uploadsGuard(false);
    }

    public static function drain(): void
    {
        $path = ABSPATH . 'sd-early-events.php';
        if (is_link($path) || !is_file($path)) {
            return;
        }
        $handle = @fopen($path, 'r+b');
        if (!$handle) {
            return;
        }
        try {
            if (!flock($handle, LOCK_EX | LOCK_NB)) {
                return;
            }
            fgets($handle);
            $lines = [];
            while (($line = fgets($handle, 1024)) !== false && count($lines) < 1000) {
                $event = json_decode($line, true);
                if (is_array($event) && in_array($event['kind'] ?? '', ['waf_block', 'waf_observe', 'file_detected'], true)) {
                    $lines[] = $event;
                }
            }
            rewind($handle);
            ftruncate($handle, 0);
            fwrite($handle, "<?php exit; // Site Defense early events\n");
            fflush($handle);
            flock($handle, LOCK_UN);
        } finally {
            fclose($handle);
        }
        foreach ($lines ?? [] as $event) {
            $id = $event['id'] ?? '';
            $route = $event['route'] ?? '';
            $detail = 'Early protection blocked a request';
            if (is_string($id) && preg_match('/^[A-Z0-9][A-Z0-9_-]{2,63}$/D', $id)) {
                $detail = $id;
                if (is_string($route) && preg_match('~^(?:\*|/[A-Za-z0-9_./-]{1,180})$~D', $route)) {
                    $detail .= ' · ' . $route;
                }
            }
            $timestamp = $event['time'] ?? 0;
            $observed = is_int($timestamp) && $timestamp >= time() - 14 * DAY_IN_SECONDS && $timestamp <= time() ? $timestamp : null;
            $context = RequestEvidence::wafContext(['route' => $event['path'] ?? null, 'layer' => 'early',
                'method' => $event['method'] ?? null, 'request_id' => $event['request_id'] ?? null]);
            State::log($event['kind'], $detail, context: $context, observed: $observed);
        }
    }

    private static function uploadsGuard(bool $enable): void
    {
        $uploads = wp_get_upload_dir();
        if (empty($uploads['basedir'])) {
            return;
        }
        $path = $uploads['basedir'] . '/.htaccess';
        $content = is_readable($path) ? (string) file_get_contents($path) : '';
        $content = self::withoutBlock($content);
        if ($enable) {
            $content = rtrim($content) . "\n" . self::START . "\n" .
                "<FilesMatch \"(?i)\\.(php[0-9]?|phtml|phar|pht|cgi|pl)(\\.|$)\">\nRequire all denied\n</FilesMatch>\n" .
                self::END . "\n";
        }
        self::write($path, $content);
    }

    private static function withoutBlock(string $content): string
    {
        return preg_replace('/^# BEGIN Site Defense\r?\n.*?^# END Site Defense\r?\n?/ms', '', $content);
    }

    private static function write(string $path, string $content): bool
    {
        if (is_link($path)) {
            return false;
        }
        $temporary = @tempnam(dirname($path), '.sd-');
        if (!$temporary) {
            return false;
        }
        $written = @file_put_contents($temporary, $content, LOCK_EX) === strlen($content);
        $saved = $written && @rename($temporary, $path);
        if (!$saved) {
            @unlink($temporary);
        }
        return $saved;
    }

    public static function rules(): array
    {
        return Firewall::package();
    }

    public static function import(string $package): string
    {
        return Firewall::import($package);
    }

    public static function sync(): bool
    {
        return !get_option('sd_early_enabled') || Firewall::locked(static fn () => self::publish(Firewall::runtime())) === true;
    }

    public static function syncOnUpgrade(): void
    {
        if (get_option('sd_early_enabled') && (int) get_option('sd_early_schema') !== 3 && self::sync()) {
            update_option('sd_early_schema', 3);
        }
    }

    public static function publish(array $rules): bool
    {
        if (!get_option('sd_early_enabled')) {
            return true;
        }
        $uploads = wp_get_upload_dir();
        $data = [
            'firewall_schema' => 2,
            'uploads' => wp_normalize_path($uploads['basedir'] ?? ''),
            'waf' => State::enabled('waf'), 'rules' => $rules,
            'blocked' => __('Request blocked.', 'site-defense'),
            'uploads_blocked' => __('PHP execution in uploads is disabled.', 'site-defense'),
        ];
        $json = wp_json_encode($data);
        if (!is_string($json)) {
            return false;
        }
        $path = ABSPATH . 'sd-early-config.php';
        $current = file_exists($path) ? @file_get_contents($path) : '';
        if (is_link($path) || !is_string($current) || ($current !== '' && !str_starts_with($current, self::CONFIG_HEADER))) {
            return false;
        }
        $marker = ABSPATH . '.sd-early.json';
        // Keep the old loader's activation marker without publishing local paths.
        if ((!is_file($marker) || @file_get_contents($marker) !== self::MARKER) && !self::write($marker, self::MARKER)) {
            return false;
        }
        $contents = self::CONFIG_HEADER . $json;
        return $current === $contents || self::write($path, $contents);
    }

    public static function nginxSnippet(): string
    {
        $uploads = wp_get_upload_dir();
        $path = wp_parse_url($uploads['baseurl'] ?? '', PHP_URL_PATH) ?: '/wp-content/uploads';
        return "# Place before the general PHP location in this site's server block.\n" .
            'location ~* ^' . preg_quote(rtrim($path, '/') . '/', '~') . '.*\.(?:php[0-9]?|phtml|phar|pht|cgi|pl)(?:\.|$) { return 403; }';
    }
}

