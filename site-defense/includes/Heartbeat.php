<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Heartbeat
{
    public const HOOK = 'sd_heartbeat_tick';
    private const SETTINGS = 'sd_heartbeat';
    private const STATUS = 'sd_heartbeat_status';

    public static function register(): void
    {
        add_action(self::HOOK, [self::class, 'send']);
        if (self::config()['enabled']) {
            self::schedule();
        }
    }

    private static function schedule(): void
    {
        if (!wp_next_scheduled(self::HOOK)) {
            wp_schedule_event(time() + 15, 'sd_five_minutes', self::HOOK);
        }
    }

    public static function config(): array
    {
        return array_replace(['enabled' => false, 'url' => '', 'secret' => '', 'enabled_at' => 0],
            (array) get_option(self::SETTINGS, []));
    }

    public static function status(): array
    {
        return ['enabled' => self::config()['enabled']] + (array) get_option(self::STATUS, []);
    }

    public static function save(array $input): string
    {
        $old = self::config();
        $enabled = isset($input['heartbeat_enabled']);
        $url = trim(State::field($input, 'heartbeat_url'));
        $newSecret = trim(State::field($input, 'heartbeat_secret'));
        $remove = isset($input['heartbeat_clear']);
        if ($url !== '' && !self::validUrl($url)) {
            return __('The heartbeat receiver must use a public HTTPS address.', 'site-defense');
        }
        if ($newSecret !== '' && (!preg_match('/^[A-Za-z0-9_-]{32,128}$/D', $newSecret) || !function_exists('sodium_crypto_secretbox'))) {
            return __('Use a heartbeat secret of 32 to 128 URL-safe characters and enable PHP Sodium.', 'site-defense');
        }
        $secret = $remove ? '' : ($newSecret === '' ? $old['secret'] : Alerts::encrypt($newSecret));
        if ($enabled && ($url === '' || Alerts::decrypt($secret) === '')) {
            return __('Set the receiver address and secret before enabling heartbeat.', 'site-defense');
        }
        $changed = $url !== $old['url'] || $secret !== $old['secret'] || $enabled !== $old['enabled'];
        if ($changed && !update_option(self::SETTINGS, [
            'enabled' => $enabled, 'url' => $url, 'secret' => $secret, 'enabled_at' => $enabled ? time() : 0,
        ], false)) {
            return __('Unable to save heartbeat settings.', 'site-defense');
        }
        if ($changed) {
            delete_option(self::STATUS);
            State::log('protection_changed', 'Heartbeat settings changed', true);
        }
        if ($enabled) {
            self::schedule();
        } else {
            wp_clear_scheduled_hook(self::HOOK);
        }
        return __('Heartbeat settings saved.', 'site-defense');
    }

    private static function validUrl(string $url): bool
    {
        $parts = wp_parse_url($url);
        return ($parts['scheme'] ?? '') === 'https' && !isset($parts['user']) && !isset($parts['pass']) &&
            !isset($parts['query']) && !isset($parts['fragment']) &&
            (bool) wp_http_validate_url($url);
    }

    public static function send(): string
    {
        $config = self::config();
        if (!$config['enabled']) {
            return __('Heartbeat is disabled.', 'site-defense');
        }
        $secret = Alerts::decrypt($config['secret']);
        $now = time();
        $state = self::status();
        $state['attempt'] = $now;
        $state['delivered'] = false;
        if ($secret !== '' && self::validUrl($config['url'])) {
            $issues = [];
            if ($now - $config['enabled_at'] >= 10 * MINUTE_IN_SECONDS &&
                $now - (int) get_option('sd_alert_worker', 0) >= 10 * MINUTE_IN_SECONDS) {
                $issues[] = 'alert_worker_stale';
            }
            if (State::enabled('fast_watch') && $now - $config['enabled_at'] >= 20 * MINUTE_IN_SECONDS &&
                $now - (int) (((array) get_option('sd_watch', []))['completed'] ?? 0) >= 20 * MINUTE_IN_SECONDS) {
                $issues[] = 'file_watch_stale';
            }
            $body = wp_json_encode(['version' => 1, 'healthy' => !$issues, 'issues' => $issues]);
            $response = wp_safe_remote_post($config['url'], [
                'timeout' => 5, 'redirection' => 0, 'limit_response_size' => 1024,
                'user-agent' => 'Site Defense heartbeat',
                'headers' => ['Content-Type' => 'application/json', 'X-Site-Defense-Time' => (string) $now,
                    'X-Site-Defense-Signature' => hash_hmac('sha256', $now . '.' . $body, $secret)],
                'body' => $body,
            ]);
            $code = wp_remote_retrieve_response_code($response);
            $state['delivered'] = $code >= 200 && $code < 300;
        }
        if ($state['delivered']) {
            $state['success'] = $now;
        }
        unset($state['enabled']);
        update_option(self::STATUS, $state, false);
        return $state['delivered'] ? __('Heartbeat delivered.', 'site-defense') : __('Heartbeat delivery failed.', 'site-defense');
    }
}
