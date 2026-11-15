<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Login
{
    private const CREDENTIAL_ERRORS = ['invalid_username', 'invalid_email', 'incorrect_password', 'invalidcombo', 'authentication_failed'];

    public static function register(): void
    {
        if (!State::enabled('limit') || (defined('WP_CLI') && WP_CLI)) {
            return;
        }
        add_filter('authenticate', [self::class, 'guard'], PHP_INT_MIN, 3);
        add_filter('authenticate', [self::class, 'result'], 9000, 3);
    }

    public static function ip(): string
    {
        $remote = State::field($_SERVER, 'REMOTE_ADDR');
        $proxy = State::settings()['proxy'];
        if ($proxy !== '' && $remote === $proxy) {
            $forwarded = State::field($_SERVER, 'HTTP_X_REAL_IP');
            if (filter_var($forwarded, FILTER_VALIDATE_IP)) {
                $remote = $forwarded;
            }
        }
        return filter_var($remote, FILTER_VALIDATE_IP) ? inet_ntop(inet_pton($remote)) : 'unknown';
    }

    public static function key(string $value): string
    {
        return hash_hmac('sha256', $value, wp_salt('auth'));
    }

    private static function buckets(string $username): array
    {
        $ip = self::ip();
        $username = strtolower(substr(trim($username), 0, 254));
        return [
            'pair' => self::key("pair|$ip|$username"),
            'ip' => self::key("ip|$ip"),
            'name' => self::key("name|$username"),
        ];
    }

    public static function count(string $bucket, int $seconds): int
    {
        global $wpdb;
        $table = State::table('limits');
        $now = time();
        $wpdb->query($wpdb->prepare(
            "INSERT INTO $table (bucket, hits, expires) VALUES (%s, LAST_INSERT_ID(1), %d)
             ON DUPLICATE KEY UPDATE hits = LAST_INSERT_ID(IF(expires <= %d, 1, hits + 1)),
             expires = IF(expires <= %d, VALUES(expires), expires)",
            $bucket, $now + $seconds, $now, $now
        ));
        return (int) $wpdb->insert_id;
    }

    public static function hits(string $bucket): int
    {
        global $wpdb;
        $table = State::table('limits');
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT hits FROM $table WHERE bucket = %s AND expires > %d", $bucket, time()
        ));
    }

    private static function lock(string $bucket, int $seconds): void
    {
        self::count(self::key('lock|' . $bucket), $seconds);
    }

    public static function clear(string $bucket): void
    {
        global $wpdb;
        $wpdb->delete(State::table('limits'), ['bucket' => $bucket], ['%s']);
    }

    public static function guard($user, string $username, string $password)
    {
        if ($username === '' || $password === '') {
            return $user;
        }
        $buckets = self::buckets($username);
        if (self::hits(self::key('lock|' . $buckets['pair'])) || self::hits(self::key('lock|' . $buckets['ip']))) {
            // Core authentication callbacks may replace WP_Error. Stop before checking the password.
            if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
                status_header(429);
                header('Content-Type: text/xml; charset=UTF-8');
                header('Retry-After: 60');
                $message = esc_xml(__('Too many login attempts.', 'site-defense'));
                exit('<?xml version="1.0"?><methodResponse><fault><value><struct>' .
                    '<member><name>faultCode</name><value><int>429</int></value></member>' .
                    '<member><name>faultString</name><value><string>' . $message . '</string></value></member>' .
                    '</struct></value></fault></methodResponse>');
            }
            header('Retry-After: 60');
            wp_die(esc_html__('Too many login attempts. Try again later.', 'site-defense'), '', ['response' => 429, 'back_link' => true]);
        }
        return $user;
    }

    public static function result($user, string $username, string $password)
    {
        if ($username === '' || $password === '') {
            return $user;
        }
        if ($user instanceof \WP_User) {
            self::clear(self::buckets($username)['pair']);
            return $user;
        }
        if (is_wp_error($user) && !array_intersect($user->get_error_codes(), self::CREDENTIAL_ERRORS)) {
            return $user;
        }
        $buckets = self::buckets($username);
        $pairHits = self::count($buckets['pair'], 600);
        $ipHits = self::count($buckets['ip'], 600);
        $nameHits = self::count($buckets['name'], 600);
        if ($pairHits >= 5) {
            $strikes = self::count(self::key('strike|' . $buckets['pair']), HOUR_IN_SECONDS);
            self::lock($buckets['pair'], min(900, 60 * (2 ** min(4, max(0, $strikes - 1)))));
            self::clear($buckets['pair']);
            State::log('login_limit', 'Login attempts paused for an IP and account pair.');
        }
        if ($ipHits >= 50) {
            self::lock($buckets['ip'], 60);
            self::clear($buckets['ip']);
            State::log('login_limit', 'Login attempts paused for a source IP.');
        }
        if ($nameHits === 25) {
            State::log('login_pressure', 'Repeated failures for one account identifier.');
        }
        return new \WP_Error('sd_bad_credentials', __('Invalid login details.', 'site-defense'));
    }

}

