<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

require_once __DIR__ . '/FirewallMatcher.php';

final class Firewall
{
    public const MODES = ['observe', 'block', 'off'];

    public static function register(): void
    {
        if (State::enabled('waf')) {
            self::inspect();
            add_action('parse_request', [self::class, 'inspectPage'], -1001);
        }
    }

    private static function seed(): array
    {
        static $seed;
        return $seed ??= json_decode(file_get_contents(SITE_DEFENSE_DIR . '/data/waf-rules.json'), true);
    }

    private static function state(): array
    {
        $stored = get_option('sd_firewall', []);
        if ($stored) {
            return $stored;
        }
        $legacy = (array) get_option('sd_waf_rules', []);
        $active = self::seed();
        if (($legacy['schema'] ?? 0) === 1 && ($legacy['version'] ?? 0) >= $active['version']) {
            $active['version'] = $legacy['version'];
            foreach ($legacy['rules'] ?? [] as $rule) {
                if (($rule['id'] ?? '') !== 'CVE-2026-87902') {
                    continue;
                }
                $active['rules'][0]['ranges'] = [];
                foreach ($rule['fixed'] as $branch => $fixed) {
                    $active['rules'][0]['ranges'][] = [$branch, true, $fixed, false];
                }
                break;
            }
            if (empty($legacy['rules'])) {
                array_shift($active['rules']);
            }
        }
        return ['active' => $active, 'previous' => null, 'highest' => $active['version'], 'modes' => []];
    }

    public static function package(): array
    {
        return self::state()['active'];
    }

    public static function status(): array
    {
        $state = self::state();
        $rules = [];
        foreach (self::runtime($state) as $rule) {
            $version = FirewallMatcher::version($rule['version_file'], $rule['component'] === 'core');
            $rules[] = [
                'id' => $rule['id'], 'component' => $rule['component'], 'version' => $version,
                'affected' => FirewallMatcher::affected($rule['ranges'], $version),
                'mode' => $rule['mode'], 'route' => $rule['label'], 'source' => $rule['source'],
            ];
        }
        return [
            'version' => $state['active']['version'], 'previous_version' => $state['previous']['version'] ?? null,
            'highest_version' => $state['highest'], 'enabled' => State::enabled('waf'),
            'early_configured' => (bool) get_option('sd_early_enabled'), 'rules' => $rules,
        ];
    }

    public static function runtime(?array $state = null): array
    {
        $state ??= self::state();
        $exception = State::settings()['waf_exception'];
        $rules = [];
        foreach ($state['active']['rules'] as $rule) {
            $rule['mode'] = $state['modes'][$rule['id']] ?? ($exception === $rule['id'] ? 'off' : $rule['mode']);
            $rule['version_file'] = wp_normalize_path($rule['component'] === 'core'
                ? ABSPATH . WPINC . '/version.php' : WP_PLUGIN_DIR . '/' . $rule['component']);
            $rule['label'] = match ($rule['route']) {
                'front' => '/index.php',
                'plugin' => '/' . $rule['endpoint'],
                'rest' => $rule['endpoint'],
                default => '*',
            };
            if ($rule['route'] === 'plugin') {
                $rule['endpoint_file'] = wp_normalize_path(WP_PLUGIN_DIR . '/' . $rule['endpoint']);
                // This is a configured URL. Avoid loading raw request paths into the journal.
                $rule['path'] = wp_parse_url(WP_PLUGIN_URL . '/' . $rule['endpoint'], PHP_URL_PATH);
            } elseif ($rule['route'] === 'front') {
                $rule['endpoint_file'] = wp_normalize_path(ABSPATH . 'index.php');
            } elseif ($rule['route'] === 'rest') {
                $prefix = wp_parse_url(home_url('/' . rest_get_url_prefix()), PHP_URL_PATH);
                $rule['path'] = rtrim((string) $prefix, '/') . $rule['endpoint'];
            }
            $rules[] = $rule;
        }
        return $rules;
    }

    public static function inspect(): void
    {
        if (defined('SD_EARLY_WAF_READY') || (defined('WP_CLI') && WP_CLI)) {
            return;
        }
        self::evaluate(null);
    }

    public static function inspectPage(\WP $wp): void
    {
        $page = $wp->query_vars['pagename'] ?? '';
        if (is_string($page) && $page !== '') {
            self::evaluate($page);
        }
    }

    private static function evaluate(?string $page): void
    {
        static $logged = [];
        foreach (self::runtime() as $rule) {
            if (isset($logged[$rule['id']]) || isset($GLOBALS['sd_early_matches'][$rule['id']]) ||
                ($page !== null && $rule['route'] !== 'front') ||
                !FirewallMatcher::matches($rule, $_SERVER, $_GET, $_POST, $page, true)) {
                continue;
            }
            $logged[$rule['id']] = true;
            $block = $rule['mode'] === 'block';
            State::log($block ? 'waf_block' : 'waf_observe', $rule['id'] . ' · ' . $rule['label'],
                context: RequestEvidence::capture($_SERVER, 'wordpress'));
            if ($block) {
                wp_die(esc_html__('Request blocked.', 'site-defense'), '', ['response' => 403]);
            }
        }
    }

    public static function coreRuleActive(string $version): bool
    {
        if (!State::enabled('waf')) {
            return false;
        }
        foreach (self::runtime() as $rule) {
            if ($rule['id'] === 'CVE-2026-87902' && $rule['mode'] === 'block') {
                return FirewallMatcher::affected($rule['ranges'], $version);
            }
        }
        return false;
    }

    public static function import(string $package): string
    {
        $config = json_decode(file_get_contents(SITE_DEFENSE_DIR . '/data/update.json'), true);
        $key = base64_decode($config['public_key'] ?? '', true);
        if (strlen($package) < 65 || strlen($package) > 1024 * 1024 || !is_string($key) || strlen($key) !== 32 ||
            !function_exists('sodium_crypto_sign_verify_detached') ||
            !sodium_crypto_sign_verify_detached(substr($package, 0, 64), substr($package, 64), $key)) {
            return __('Firewall package signature verification failed.', 'site-defense');
        }
        $data = json_decode(substr($package, 64), true);
        if (!self::valid($data)) {
            return __('Invalid or older firewall rule package.', 'site-defense');
        }
        return self::change(static function (array $state) use ($data): array|string {
            if ($data['version'] <= $state['highest']) {
                return __('Invalid or older firewall rule package.', 'site-defense');
            }
            $state['previous'] = $state['active'];
            $state['active'] = $data;
            $state['highest'] = $data['version'];
            return $state;
        }, 'Firewall rules updated.');
    }

    public static function rollback(): string
    {
        return self::change(static function (array $state): array|string {
            if ($state['previous'] === null) {
                return __('No previous firewall package is available.', 'site-defense');
            }
            $state['active'] = $state['previous'];
            $state['previous'] = null;
            return $state;
        }, 'Previous firewall package restored.');
    }

    public static function setMode(string $id, string $mode): string
    {
        return self::change(static function (array $state) use ($id, $mode): array|string {
            if (!in_array($mode, self::MODES, true) || !in_array($id, array_column($state['active']['rules'], 'id'), true)) {
                return __('Unknown firewall rule or mode.', 'site-defense');
            }
            $state['modes'][$id] = $mode;
            return $state;
        }, 'Firewall rule mode saved.');
    }

    public static function locked(callable $operation): bool|string
    {
        global $wpdb;
        $lock = 'sd-rules-' . md5($wpdb->options);
        if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s,2)', $lock)) !== 1) {
            return false;
        }
        try {
            wp_cache_delete('sd_firewall', 'options');
            return $operation();
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }

    private static function change(callable $operation, string $message): string
    {
        $result = self::locked(static function () use ($operation, $message): string {
            $stored = get_option('sd_firewall', []);
            $before = self::state();
            $after = $operation($before);
            if (is_string($after)) {
                return $after;
            }
            if ($after !== $before) {
                if (!update_option('sd_firewall', $after, false)) {
                    return __('Unable to save firewall rules.', 'site-defense');
                }
                if (!EarlyProtection::publish(self::runtime($after))) {
                    if ($stored) {
                        update_option('sd_firewall', $stored, false);
                    } else {
                        delete_option('sd_firewall');
                    }
                    return __('Unable to update the early firewall configuration.', 'site-defense');
                }
                State::log('protection_changed', $message);
            }
            return translate($message, 'site-defense');
        });
        return $result === false ? __('A firewall rule update is already running.', 'site-defense') : $result;
    }

    private static function valid($data): bool
    {
        if (!is_array($data) || ($data['schema'] ?? null) !== 2 || !is_int($data['version'] ?? null) ||
            $data['version'] < 2 || !is_array($data['rules'] ?? null) || !array_is_list($data['rules']) ||
            count($data['rules']) > 100) {
            return false;
        }
        $seen = [];
        foreach ($data['rules'] as $rule) {
            if (!is_array($rule) || !is_string($rule['id'] ?? null) || !preg_match('/^[A-Z0-9][A-Z0-9_-]{2,63}$/D', $rule['id']) ||
                isset($seen[$rule['id']]) || !in_array($rule['mode'] ?? '', self::MODES, true) ||
                !is_string($rule['component'] ?? null) || ($rule['component'] !== 'core' && !self::pluginPath($rule['component'])) ||
                !in_array($rule['route'] ?? '', ['any', 'front', 'plugin', 'rest'], true) ||
                !is_array($rule['methods'] ?? null) || !array_is_list($rule['methods']) ||
                !is_string($rule['source'] ?? null) || strlen($rule['source']) > 400 || wp_parse_url($rule['source'], PHP_URL_SCHEME) !== 'https' ||
                !self::validRanges($rule['ranges'] ?? null) || !self::validConditions($rule['conditions'] ?? null, $rule['route'])) {
                return false;
            }
            if ($rule['route'] === 'plugin' && (!is_string($rule['endpoint'] ?? null) ||
                !self::pluginPath($rule['endpoint']) || !str_contains($rule['component'], '/') ||
                !str_starts_with($rule['endpoint'], dirname($rule['component']) . '/'))) {
                return false;
            }
            if ($rule['route'] === 'rest' && (!is_string($rule['endpoint'] ?? null) || strlen($rule['endpoint']) > 180 ||
                !preg_match('~^(?:/[A-Za-z0-9_.-]+){2,12}$~D', $rule['endpoint']))) {
                return false;
            }
            foreach ($rule['methods'] as $method) {
                if (!in_array($method, ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], true)) {
                    return false;
                }
            }
            $seen[$rule['id']] = true;
        }
        return true;
    }

    private static function pluginPath(string $path): bool
    {
        return strlen($path) <= 180 && preg_match('~^(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.php$~D', $path);
    }

    private static function validRanges($ranges): bool
    {
        if (!is_array($ranges) || !array_is_list($ranges) || !$ranges || count($ranges) > 40) {
            return false;
        }
        foreach ($ranges as $range) {
            if (!is_array($range) || !array_is_list($range) || count($range) !== 4 ||
                !is_bool($range[1]) || !is_bool($range[3])) {
                return false;
            }
            foreach ([$range[0], $range[2]] as $version) {
                if (!is_string($version) || !preg_match('/^(?:\*|[0-9]{1,6}(?:\.[0-9]{1,6}){0,4})$/D', $version)) {
                    return false;
                }
            }
            if ($range[0] !== '*' && $range[2] !== '*' && version_compare($range[0], $range[2], '>')) {
                return false;
            }
        }
        return true;
    }

    private static function validConditions($conditions, string $route): bool
    {
        if (!is_array($conditions) || !array_is_list($conditions) || !$conditions || count($conditions) > 8) {
            return false;
        }
        foreach ($conditions as $condition) {
            if (!is_array($condition) || !in_array($condition['source'] ?? '', ['header', 'get', 'post', 'page'], true) ||
                !is_string($condition['key'] ?? null) || !preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $condition['key']) ||
                !in_array($condition['op'] ?? '', ['present', 'traversal', 'equals'], true) ||
                ($condition['source'] === 'page' && ($route !== 'front' || $condition['key'] !== 'pagename'))) {
                return false;
            }
            if ($condition['op'] === 'equals' && (!is_string($condition['value'] ?? null) || strlen($condition['value']) > 128)) {
                return false;
            }
        }
        return true;
    }
}
