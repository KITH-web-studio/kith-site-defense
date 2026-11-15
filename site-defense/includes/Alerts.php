<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Alerts
{
    public static function register(): void
    {
        add_filter('cron_schedules', static function (array $schedules): array {
            $schedules['sd_minute'] = ['interval' => 60, 'display' => 'Site Defense'];
            $schedules['sd_five_minutes'] = ['interval' => 300, 'display' => 'Site Defense'];
            return $schedules;
        });
        if (!wp_next_scheduled('sd_alert_tick')) {
            wp_schedule_event(time() + 60, 'sd_minute', 'sd_alert_tick');
        }
        add_action('sd_alert_tick', [self::class, 'deliver']);
    }

    public static function config(): array
    {
        return array_replace([
            'telegram' => false, 'chat' => '', 'token' => '', 'webhook' => false,
            'url' => '', 'secret' => '',
        ], (array) get_option('sd_alerts', []));
    }

    private static function key(): string
    {
        return hash('sha256', wp_salt('secure_auth') . '|sd-notifications', true);
    }

    public static function encrypt(string $secret): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return base64_encode($nonce . sodium_crypto_secretbox($secret, $nonce, self::key()));
    }

    public static function decrypt(string $secret): string
    {
        $data = base64_decode($secret, true);
        if (!function_exists('sodium_crypto_secretbox_open') || !is_string($data) || strlen($data) <= 40) {
            return '';
        }
        return sodium_crypto_secretbox_open(substr($data, 24), substr($data, 0, 24), self::key()) ?: '';
    }

    public static function save(array $input): string
    {
        $settings = self::config();
        $token = trim(State::field($input, 'telegram_token'));
        $secret = trim(State::field($input, 'webhook_secret'));
        if (($token !== '' || $secret !== '') && !function_exists('sodium_crypto_secretbox')) {
            return __('PHP Sodium is required to save notification secrets.', 'site-defense');
        }
        if ($token !== '' && !preg_match('/^[0-9]{5,20}:[A-Za-z0-9_-]{20,100}$/D', $token)) {
            return __('Invalid Telegram bot token.', 'site-defense');
        }
        $chat = trim(State::field($input, 'telegram_chat'));
        $url = trim(State::field($input, 'webhook_url'));
        if (isset($input['telegram']) && !preg_match('/^(?:-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$/D', $chat)) {
            return __('Invalid Telegram chat ID.', 'site-defense');
        }
        if (isset($input['webhook']) && (wp_parse_url($url, PHP_URL_SCHEME) !== 'https' ||
            !wp_http_validate_url($url) || wp_parse_url($url, PHP_URL_USER) || wp_parse_url($url, PHP_URL_PASS))) {
            return __('The webhook must use a public HTTPS address.', 'site-defense');
        }
        foreach (['token' => $token, 'secret' => $secret] as $name => $value) {
            if (!empty($input['clear_' . $name])) {
                $settings[$name] = '';
            } elseif ($value !== '') {
                $settings[$name] = self::encrypt($value);
            }
        }
        if (isset($input['telegram']) && self::decrypt($settings['token']) === '') {
            return __('Enter a Telegram bot token before enabling this channel.', 'site-defense');
        }
        if (isset($input['webhook']) && self::decrypt($settings['secret']) === '') {
            return __('Enter a signing secret before enabling the webhook.', 'site-defense');
        }
        $settings['telegram'] = isset($input['telegram']);
        $settings['webhook'] = isset($input['webhook']);
        $settings['chat'] = $chat;
        $settings['url'] = esc_url_raw($url);
        update_option('sd_alerts', $settings, false);
        State::log('protection_changed', 'Notification channel settings changed', true, ['user_id' => get_current_user_id()]);
        return __('Notification channels saved.', 'site-defense');
    }

    private static function enabledChannels(string $kind): array
    {
        $kind = $kind === 'vulnerability_escalated' ? 'vulnerability_found' : $kind;
        $channels = [];
        $settings = State::settings();
        if ($settings['notify'] && is_email($settings['email']) &&
            ($kind === 'notification_test' || in_array($kind, $settings['notify_types'], true))) {
            $channels[] = 'email';
        }
        $extra = self::config();
        foreach (['telegram', 'webhook'] as $channel) {
            if ($extra[$channel] && ($kind !== 'vulnerability_found' || $channel === 'telegram')) {
                $channels[] = $channel;
            }
        }
        return $channels;
    }

    public static function test(): string
    {
        $incident = [
            'id' => 0, 'kind' => 'notification_test', 'severity' => 'info',
            'detail' => 'Notification delivery test', 'hits' => 1, 'last_seen' => time(),
        ];
        $channels = self::enabledChannels('notification_test');
        if (!$channels) {
            return __('Enable a notification channel first.', 'site-defense');
        }
        $failed = [];
        foreach ($channels as $channel) {
            if (!self::send($channel, $incident)) {
                $failed[] = $channel;
            }
        }
        return $failed
            ? sprintf(__('Delivery failed for %s. Check channel settings.', 'site-defense'), implode(', ', $failed))
            : __('Test notification sent.', 'site-defense');
    }

    public static function deliver(): void
    {
        global $wpdb;
        $lock = 'sd-alerts-' . md5($wpdb->options);
        if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s,0)', $lock)) !== 1) {
            return;
        }
        $switched = switch_to_locale(get_locale());
        try {
            $table = State::table('incidents');
            $rows = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM $table WHERE pending=1 AND due<=%d ORDER BY due,id LIMIT 10", time()
            ), ARRAY_A) ?: [];
            $deadline = microtime(true) + 18;
            foreach ($rows as $row) {
                if (microtime(true) > $deadline) {
                    break;
                }
                $delivery = json_decode($row['delivery'], true) ?: [];
                $next = time() + 3600;
                $pending = false;
                foreach (self::enabledChannels($row['kind']) as $channel) {
                    $state = $delivery[$channel] ?? ['sent' => 0, 'attempts' => 0, 'retry' => 0];
                    if ($state['sent'] >= (int) $row['hits']) {
                        continue;
                    }
                    if ($state['retry'] <= time()) {
                        if (self::send($channel, $row)) {
                            $state = ['sent' => (int) $row['hits'], 'attempts' => 0, 'retry' => 0];
                        } else {
                            $state['attempts']++;
                            $state['retry'] = time() + min(3600, 60 * (2 ** min(6, $state['attempts'])));
                        }
                    }
                    if ($state['sent'] < (int) $row['hits']) {
                        $pending = true;
                        $next = min($next, $state['retry']);
                    }
                    $delivery[$channel] = $state;
                }
                // A simultaneous new event remains pending for the next delivery cycle.
                $wpdb->query($wpdb->prepare(
                    "UPDATE $table SET delivery=%s,pending=IF(hits>%d,1,%d),due=IF(hits>%d,%d,%d) WHERE id=%d",
                    wp_json_encode($delivery), $row['hits'], (int) $pending, $row['hits'], time() + 60, $next, $row['id']
                ));
            }
            $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE last_seen<%d AND pending=0", time() - 30 * DAY_IN_SECONDS));
            update_option('sd_alert_worker', time(), false);
        } finally {
            if ($switched) {
                restore_previous_locale();
            }
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }

    private static function send(string $channel, array $incident): bool
    {
        $settings = self::config();
        $url = admin_url('admin.php?page=site-defense&tab=incidents&incident=' . (int) $incident['id'] . '#sd-incidents');
        $title = State::eventLabel($incident['kind']);
        $context = json_decode($incident['context'] ?? '{}', true) ?: [];
        $detail = isset($context['vulnerability']) ? Vulnerabilities::describe($context['vulnerability']) : State::eventDetail($incident['detail']);
        $text = '[Site Defense] ' . $title . "\n" . home_url('/') . "\n" .
            wp_date('c', (int) $incident['last_seen']) . "\n" . $detail . "\n" .
            sprintf(__('Occurrences: %d', 'site-defense'), $incident['hits']) . "\n" . $url;
        if ($channel === 'email') {
            return wp_mail(State::settings()['email'], '[Site Defense] ' . $title, $text);
        }
        if ($channel === 'telegram') {
            $token = self::decrypt($settings['token']);
            if ($token === '') {
                return false;
            }
            $response = wp_remote_post('https://api.telegram.org/bot' . $token . '/sendMessage', [
                'timeout' => 6, 'redirection' => 0, 'limit_response_size' => 16384,
                'body' => ['chat_id' => $settings['chat'], 'text' => $text, 'disable_web_page_preview' => 'true'],
            ]);
            $result = json_decode(wp_remote_retrieve_body($response), true);
            return wp_remote_retrieve_response_code($response) === 200 && ($result['ok'] ?? false) === true;
        }
        $secret = self::decrypt($settings['secret']);
        if ($secret === '' || wp_parse_url($settings['url'], PHP_URL_SCHEME) !== 'https') {
            return false;
        }
        $payload = wp_json_encode([
            'id' => (int) $incident['id'], 'event' => $incident['kind'], 'severity' => $incident['severity'],
            'detail' => $incident['detail'], 'occurrences' => (int) $incident['hits'],
            'last_seen' => (int) $incident['last_seen'], 'site' => home_url('/'), 'url' => $url,
        ]);
        $timestamp = (string) time();
        $response = wp_safe_remote_post($settings['url'], [
            'timeout' => 6, 'redirection' => 0, 'limit_response_size' => 4096,
            'headers' => [
                'Content-Type' => 'application/json', 'X-Site-Defense-Time' => $timestamp,
                'X-Site-Defense-Signature' => hash_hmac('sha256', $timestamp . '.' . $payload, $secret),
            ], 'body' => $payload,
        ]);
        $status = wp_remote_retrieve_response_code($response);
        return $status >= 200 && $status < 300;
    }
}

