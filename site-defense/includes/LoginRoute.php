<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class LoginRoute
{
    private static string $route = '';

    public static function register(): void
    {
        add_action('init', [self::class, 'guard'], -1000);
        add_action('wp_loaded', [self::class, 'serve'], 1000);
        add_filter('site_url', [self::class, 'siteUrl'], 100, 4);
        add_filter('network_site_url', [self::class, 'siteUrl'], 100, 3);
        add_action('wp_login', [self::class, 'activatePending'], 10, 2);
    }

    public static function propose(string $slug, int $user): string
    {
        if (!preg_match('/^[a-z0-9][a-z0-9-]{3,59}$/D', $slug) ||
            in_array($slug, ['wp-admin', 'wp-json', 'wp-content', 'wp-includes', 'wp-login', 'index'], true) ||
            get_page_by_path($slug, OBJECT, get_post_types(['public' => true])) ||
            url_to_postid(site_url('/' . $slug . '/')) ||
            file_exists(ABSPATH . $slug) || is_dir(ABSPATH . $slug)) {
            return __('Choose an unused path of 4–60 lowercase letters, digits or hyphens.', 'site-defense');
        }
        if ($slug === get_option('sd_login_route', '')) {
            return __('This is already the active login path.', 'site-defense');
        }
        update_option('sd_pending_route', ['slug' => $slug, 'owner' => $user, 'expires' => time() + 900], false);
        return __('Open the test address in a private window and sign in as the same administrator within 15 minutes.', 'site-defense');
    }

    public static function url(string $slug): string
    {
        return site_url('/' . $slug . '/', 'login');
    }

    public static function siteUrl(string $url, string $path, ?string $scheme = null): string
    {
        $slug = self::$route ?: get_option('sd_login_route', '');
        if ($slug && preg_match('~^/?wp-login\.php([?#].*)?$~D', $path, $match) &&
            !str_contains($path, 'action=postpass') && ($offset = strpos($url, '/wp-login.php')) !== false) {
            $base = substr($url, 0, $offset);
            return $base . '/' . $slug . '/' . ($match[1] ?? '');
        }
        return $url;
    }

    public static function activatePending(string $login, \WP_User $user): void
    {
        $pending = (array) get_option('sd_pending_route', []);
        if (self::$route && self::$route === ($pending['slug'] ?? '') &&
            $user->ID === ($pending['owner'] ?? 0) && ($pending['expires'] ?? 0) >= time() &&
            $user->has_cap('manage_options')) {
            update_option('sd_login_route', self::$route);
            delete_option('sd_pending_route');
            State::log('login_route', 'Custom login address verified and activated.');
        }
    }

    public static function guard(): void
    {
        if (defined('WP_CLI') && WP_CLI) {
            return;
        }
        $active = get_option('sd_login_route', '');
        $pending = (array) get_option('sd_pending_route', []);
        $candidate = ($pending['expires'] ?? 0) >= time() ? $pending['slug'] : '';
        if (!$active && !$candidate) {
            return;
        }
        $path = wp_parse_url(State::field($_SERVER, 'REQUEST_URI'), PHP_URL_PATH);
        $prefix = rtrim((string) wp_parse_url(site_url('/'), PHP_URL_PATH), '/');
        $path = is_string($path) ? rawurldecode($path) : '';
        $path = str_starts_with($path, $prefix . '/') ? substr($path, strlen($prefix)) : $path;
        $slug = trim($path, '/');
        if ($slug !== '' && ($slug === $active || $slug === $candidate)) {
            self::$route = $slug;
            return;
        }

        $script = basename(State::field($_SERVER, 'SCRIPT_FILENAME'));
        if (!$active) {
            return;
        }
        if ($script === 'wp-login.php' || $slug === 'wp-login.php') {
            $action = State::field($_GET, 'action');
            $method = State::field($_SERVER, 'REQUEST_METHOD');
            if ($method === 'GET' && in_array($action, ['rp', 'resetpass'], true) &&
                !is_wp_error(check_password_reset_key(State::field($_GET, 'key'), State::field($_GET, 'login')))) {
                wp_safe_redirect(add_query_arg([
                    'action' => $action, 'key' => State::field($_GET, 'key'), 'login' => State::field($_GET, 'login'),
                ], self::url($active)));
                exit;
            }
            if ($method === 'GET' && $action === 'enter_recovery_mode' && !empty($_GET['rm_token']) && !empty($_GET['rm_key'])) {
                // Core validates the token and issues its own redirect only after validation.
                return;
            }
            if ($method === 'GET' && $action === 'entered_recovery_mode' && wp_is_recovery_mode()) {
                wp_safe_redirect(add_query_arg('action', $action, self::url($active)));
                exit;
            }
            if ($method === 'POST' && State::field($_POST, 'action') === 'postpass' &&
                State::field($_REQUEST, 'action') === 'postpass') {
                return;
            }
            self::notFound();
        }
        if (is_admin() && !in_array($script, ['admin-ajax.php', 'admin-post.php'], true) && !is_user_logged_in()) {
            self::notFound();
        }
    }

    public static function serve(): void
    {
        if (self::$route !== '') {
            self::coreLogin();
        }
    }

    private static function coreLogin(): void
    {
        global $pagenow, $user_login, $error, $interim_login, $action;
        $pagenow = 'wp-login.php';
        if (State::field($_GET, 'action') === 'enter_recovery_mode') {
            $rate = (int) apply_filters('recovery_mode_email_rate_limit', DAY_IN_SECONDS);
            $ttl = max($rate, (int) apply_filters('recovery_mode_email_link_ttl', $rate));
            $service = new \WP_Recovery_Mode_Link_Service(
                new \WP_Recovery_Mode_Cookie_Service(), new \WP_Recovery_Mode_Key_Service()
            );
            $service->handle_begin_link($ttl);
        }
        require ABSPATH . 'wp-login.php';
        exit;
    }

    private static function notFound(): void
    {
        nocache_headers();
        wp_die(esc_html__('Not found.', 'site-defense'), '', ['response' => 404]);
    }
}

