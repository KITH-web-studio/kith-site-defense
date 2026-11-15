<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Hardening
{
    public const PRIVILEGED_CAPS = [
        'manage_options', 'install_plugins', 'activate_plugins', 'update_plugins',
        'edit_users', 'promote_users', 'update_core', 'edit_themes',
    ];

    public static function register(): void
    {
        if (State::enabled('privacy')) {
            add_filter('rest_pre_dispatch', [self::class, 'privateUsers'], 10, 3);
        }
        if (State::enabled('xml_login')) {
            add_filter('xmlrpc_enabled', '__return_false', PHP_INT_MAX);
        }
        if (State::enabled('xml_pingback')) {
            add_filter('xmlrpc_methods', static function (array $methods): array {
                unset($methods['pingback.ping']);
                return $methods;
            }, PHP_INT_MAX);
        }
        if (State::enabled('file_editor')) {
            add_filter('map_meta_cap', static function (array $required, string $capability): array {
                return in_array($capability, ['edit_files', 'edit_plugins', 'edit_themes'], true)
                    ? ['do_not_allow'] : $required;
            }, PHP_INT_MAX, 2);
        }
        add_action('set_user_role', [self::class, 'roleChanged'], 10, 3);
        add_action('add_user_role', [self::class, 'roleChanged'], 10, 2);
        add_action('remove_user_role', [self::class, 'roleChanged'], 10, 2);
        add_action('user_register', static function (int $id): void {
            $user = get_userdata($id);
            if ($user && self::privileged($user)) {
                State::log('privileged_user', 'New privileged user #' . $id, true, ['user_id' => $id]);
            }
        });
        add_action('added_user_meta', [self::class, 'capabilityChanged'], 10, 3);
        add_action('updated_user_meta', [self::class, 'capabilityChanged'], 10, 3);
        add_action('deleted_user_meta', [self::class, 'capabilityChanged'], 10, 3);
        foreach (['wp_create_application_password' => 'created', 'wp_delete_application_password' => 'revoked'] as $hook => $verb) {
            add_action($hook, static function (int $id, array $item) use ($verb): void {
                $user = get_userdata($id);
                if ($user && self::privileged($user)) {
                    State::log('application_password', 'Application password ' . $verb . ' for user #' . $id, true,
                        ['user_id' => $id, 'application_uuid' => $item['uuid'] ?? '']);
                }
            }, 10, 2);
        }
        add_action('wp_login', static function (string $login, \WP_User $user): void {
            if (self::privileged($user)) {
                State::log('login_success', 'Privileged user signed in #' . $user->ID, context: ['user_id' => $user->ID]);
            }
        }, 10, 2);
    }

    public static function privateUsers($response, \WP_REST_Server $server, \WP_REST_Request $request)
    {
        if ($response === null && !is_user_logged_in() &&
            preg_match('~^/wp/v2/users(?:/|$)~i', $request->get_route())) {
            return new \WP_Error('sd_private_profiles', __('User profiles require authentication.', 'site-defense'), ['status' => 401]);
        }
        return $response;
    }

    public static function privileged(\WP_User $user): bool
    {
        foreach (self::PRIVILEGED_CAPS as $cap) {
            if ($user->has_cap($cap)) {
                return true;
            }
        }
        return false;
    }

    public static function roleChanged(int $id, string $role, array $old = []): void
    {
        $role = sanitize_key($role);
        State::log('user_role', 'Role change for user #' . $id . ' (' . $role . ')', true, ['user_id' => $id]);
    }

    public static function capabilityChanged($metaId, int $id, string $key): void
    {
        global $wpdb;
        if ($key === $wpdb->prefix . 'capabilities') {
            State::log('user_capabilities', 'Capability metadata changed for user #' . $id, true, ['user_id' => $id]);
        }
    }

    public static function debugLog(): string
    {
        if (!defined('WP_DEBUG') || !WP_DEBUG || !defined('WP_DEBUG_LOG') || !WP_DEBUG_LOG) {
            return 'Unable to verify';
        }
        $file = in_array(WP_DEBUG_LOG, [true, 1, 'true', '1'], true)
            ? WP_CONTENT_DIR . '/debug.log' : (string) WP_DEBUG_LOG;
        if (!is_file($file)) {
            return 'Unable to verify';
        }
        $content = realpath(WP_CONTENT_DIR);
        $resolved = realpath($file);
        if (!$content || !$resolved) {
            return 'Unable to verify';
        }
        $prefix = trailingslashit(wp_normalize_path($content));
        $resolved = wp_normalize_path($resolved);
        if (!str_starts_with($resolved, $prefix)) {
            return 'Unable to verify';
        }
        $relative = implode('/', array_map('rawurlencode', explode('/', substr($resolved, strlen($prefix)))));
        $response = wp_safe_remote_head(content_url($relative), ['timeout' => 4, 'redirection' => 0]);
        $status = wp_remote_retrieve_response_code($response);
        if ($status === 200 || $status === 206) {
            return 'Accessible over HTTP';
        }
        return in_array($status, [401, 403, 404, 410], true) ? 'Access denied' : 'Unable to verify';
    }
}

