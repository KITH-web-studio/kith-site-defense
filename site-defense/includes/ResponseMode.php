<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class ResponseMode
{
    public const OPTION = 'sd_response_mode';

    public static function register(): void
    {
        if (defined('WP_CLI') && WP_CLI) {
            return;
        }
        add_filter('map_meta_cap', static function (array $required, string $cap): array {
            if (in_array($cap, ['install_plugins', 'upload_plugins', 'install_themes', 'upload_themes',
                'edit_plugins', 'edit_themes', 'edit_files'], true) && self::status()['active']) {
                return ['do_not_allow'];
            }
            return $required;
        }, PHP_INT_MAX, 2);
    }

    public static function status(): array
    {
        $mode = (array) get_option(self::OPTION, []);
        $until = (int) ($mode['until'] ?? 0);
        return ['active' => $until > time(), 'until' => $until, 'started' => (int) ($mode['started'] ?? 0),
            'actor_id' => (int) ($mode['actor_id'] ?? 0)];
    }

    public static function plan(string $minutes, string $sessions, string $passwords, bool $web): array|\WP_Error
    {
        $duration = filter_var($minutes, FILTER_VALIDATE_INT, ['options' => ['min_range' => 5, 'max_range' => 1440]]);
        if ($duration === false || strlen($sessions) > 1024 || strlen($passwords) > 4096) {
            return new \WP_Error('sd_response_inputs', __('Use a duration from 5 to 1440 minutes and at most 50 targets per action.', 'site-defense'));
        }
        $targets = static fn (string $list): array => trim($list) === '' ? [] : array_unique(array_map('trim', explode(',', $list)));
        $sessionTargets = $targets($sessions);
        $passwordTargets = $targets($passwords);
        if (count($sessionTargets) > 50 || count($passwordTargets) > 50) {
            return new \WP_Error('sd_response_inputs', __('Use a duration from 5 to 1440 minutes and at most 50 targets per action.', 'site-defense'));
        }
        $plan = ['minutes' => $duration, 'sessions' => [], 'passwords' => []];
        foreach ($sessionTargets as $target) {
            $id = self::target($target, $web);
            if (!$id || ($web && $id === get_current_user_id())) {
                return new \WP_Error('sd_response_target', __('Invalid session target. Use WP-CLI to revoke your own browser sessions.', 'site-defense'));
            }
            $plan['sessions'][$id] = count(\WP_Session_Tokens::get_instance($id)->get_all());
        }
        foreach ($passwordTargets as $target) {
            [$user, $uuid] = array_pad(explode(':', $target, 2), 2, '');
            $id = self::target($user, $web);
            $item = $id && wp_is_uuid($uuid) ? \WP_Application_Passwords::get_user_application_password($id, $uuid) : null;
            if (!$item) {
                return new \WP_Error('sd_response_target', __('An application password target is invalid or unavailable.', 'site-defense'));
            }
            $plan['passwords'][$id . ':' . $uuid] = ['user_id' => $id, 'uuid' => $uuid, 'name' => $item['name']];
        }
        return $plan;
    }

    private static function target(string $value, bool $web): int
    {
        $id = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        return $id && get_userdata($id) && (!$web || current_user_can('edit_user', $id)) ? $id : 0;
    }

    public static function start(array $plan, bool $web): array|\WP_Error
    {
        return self::locked(static function () use ($plan, $web) {
            if (self::status()['active']) {
                return new \WP_Error('sd_response_active', __('Incident mode is already active.', 'site-defense'));
            }
            $verified = self::plan((string) $plan['minutes'], implode(',', array_keys($plan['sessions'])),
                implode(',', array_keys($plan['passwords'])), $web);
            if (is_wp_error($verified)) {
                return $verified;
            }
            $now = time();
            if (!update_option(self::OPTION, ['started' => $now, 'until' => $now + $verified['minutes'] * MINUTE_IN_SECONDS,
                'actor_id' => get_current_user_id()], false)) {
                return new \WP_Error('sd_response_save', __('Unable to save incident mode.', 'site-defense'));
            }
            State::log('response_started', 'Incident mode enabled', true);
            $result = ['status' => self::status(), 'session_users' => [], 'sessions_failed' => [], 'passwords_revoked' => [], 'passwords_failed' => []];
            foreach (array_keys($verified['sessions']) as $id) {
                $sessions = \WP_Session_Tokens::get_instance($id);
                $sessions->destroy_all();
                if ($sessions->get_all()) {
                    $result['sessions_failed'][] = $id;
                    continue;
                }
                $result['session_users'][] = $id;
                State::log('session_revoked', 'Browser sessions revoked for user #' . $id, context: ['user_id' => $id]);
            }
            foreach ($verified['passwords'] as $key => $item) {
                $revoked = \WP_Application_Passwords::delete_application_password($item['user_id'], $item['uuid']);
                $result[$revoked === true ? 'passwords_revoked' : 'passwords_failed'][] = $key;
            }
            return $result;
        });
    }

    public static function stop(): array|\WP_Error
    {
        return self::locked(static function () {
            if (get_option(self::OPTION, false) !== false) {
                if (!delete_option(self::OPTION)) {
                    return new \WP_Error('sd_response_save', __('Unable to save incident mode.', 'site-defense'));
                }
                State::log('response_stopped', 'Incident mode disabled', true);
            }
            return self::status();
        });
    }

    private static function locked(callable $action): array|\WP_Error
    {
        global $wpdb;
        $lock = 'sd-response-' . md5($wpdb->options);
        if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 1)', $lock)) !== 1) {
            return new \WP_Error('sd_response_busy', __('Incident mode is being updated. Try again.', 'site-defense'));
        }
        try {
            wp_cache_delete(self::OPTION, 'options');
            wp_cache_delete('notoptions', 'options');
            return $action();
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }
}
