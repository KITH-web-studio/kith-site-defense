<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class TwoFactor
{
    private const COOKIE = 'sd_totp_challenge';
    private static ?\WP_User $applicationUser = null;

    public static function register(): void
    {
        if (defined('WP_CLI') && WP_CLI) {
            return;
        }
        add_filter('determine_current_user', static function ($id) {
            if (!$id || !State::enabled('require_2fa') || get_user_meta($id, '_sd_totp', true)) {
                return $id;
            }
            $user = get_userdata($id);
            return $user && Hardening::privileged($user) ? 0 : $id;
        }, PHP_INT_MAX);
        add_filter('authenticate', [self::class, 'requireCode'], PHP_INT_MAX, 3);
        add_filter('authenticate', static function ($user) {
            self::$applicationUser = null;
            return $user;
        }, PHP_INT_MIN);
        add_action('application_password_did_authenticate', static function (\WP_User $user): void {
            self::$applicationUser = $user;
        });
        add_action('login_form_sd_second_factor', [self::class, 'challenge']);
    }

    public static function secret(): string
    {
        return bin2hex(random_bytes(20));
    }

    public static function base32(string $secret): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        foreach (str_split(hex2bin($secret)) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }
        return implode('', array_map(static fn ($chunk) => $alphabet[bindec(str_pad($chunk, 5, '0'))], str_split($bits, 5)));
    }

    private static function step(string $secret, string $code, int $time): ?int
    {
        if (!ctype_xdigit($secret) || strlen($secret) !== 40 || !preg_match('/^[0-9]{6}$/D', $code)) {
            return null;
        }
        $now = intdiv($time, 30);
        foreach ([$now, $now - 1, $now + 1] as $step) {
            $mac = hash_hmac('sha1', pack('J', $step), hex2bin($secret), true);
            $offset = ord($mac[19]) & 15;
            $value = unpack('N', substr($mac, $offset, 4))[1] & 0x7fffffff;
            if (hash_equals(sprintf('%06d', $value % 1000000), $code)) {
                return $step;
            }
        }
        return null;
    }

    public static function enroll(int $userId, string $code): array
    {
        $secret = (string) get_transient('sd_enroll_' . $userId);
        $step = $secret !== '' ? self::step($secret, $code, time()) : null;
        if ($step === null) {
            return [];
        }
        $codes = [];
        for ($i = 0; $i < 8; $i++) {
            $codes[] = bin2hex(random_bytes(8));
        }
        $encrypted = self::encrypt($secret);
        if ($encrypted === false) {
            return [];
        }
        $previous = get_user_meta($userId, '_sd_totp', true);
        $settings = ['secret' => $encrypted, 'step' => $step, 'recovery' => array_map([Login::class, 'key'], $codes)];
        $saved = $previous
            ? update_user_meta($userId, '_sd_totp', $settings, $previous)
            : add_user_meta($userId, '_sd_totp', $settings, true);
        if (!$saved) {
            return [];
        }
        delete_transient('sd_enroll_' . $userId);
        return $codes;
    }

    private static function cipherKey(): string
    {
        return hash('sha256', wp_salt('secure_auth') . '|site-defense-totp', true);
    }

    private static function encrypt(string $secret): string|false
    {
        if (!function_exists('sodium_crypto_secretbox')) {
            return false;
        }
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return base64_encode($nonce . sodium_crypto_secretbox($secret, $nonce, self::cipherKey()));
    }

    private static function decrypt(string $secret): string|false
    {
        $data = base64_decode($secret, true);
        if (!function_exists('sodium_crypto_secretbox_open') || !is_string($data) ||
            strlen($data) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            return false;
        }
        $nonce = substr($data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return sodium_crypto_secretbox_open(substr($data, strlen($nonce)), $nonce, self::cipherKey());
    }

    public static function requireCode($user, string $username, string $password)
    {
        if (!$user instanceof \WP_User || !Hardening::privileged($user)) {
            return $user;
        }
        $enrolled = (bool) get_user_meta($user->ID, '_sd_totp', true);
        if (!$enrolled && !State::enabled('require_2fa')) {
            return $user;
        }
        if ((defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) || (defined('REST_REQUEST') && REST_REQUEST)) {
            if ($enrolled && self::$applicationUser === $user) {
                return $user;
            }
            return new \WP_Error('sd_totp_api', __('Use an application password for this integration.', 'site-defense'));
        }
        if (!$enrolled && (!is_ssl() || !function_exists('sodium_crypto_secretbox'))) {
            return new \WP_Error('sd_totp_setup', __('Two-factor enrollment requires HTTPS and PHP Sodium.', 'site-defense'));
        }
        $token = bin2hex(random_bytes(32));
        $target = State::field($_POST, 'redirect_to') ?: State::field($_POST, 'redirect');
        $redirect = wp_validate_redirect($target, admin_url()) ?: admin_url();
        if (!set_transient('sd_challenge_' . Login::key($token), [
            'id' => $user->ID, 'remember' => !empty($_POST['rememberme']), 'redirect' => $redirect,
            'enroll' => !$enrolled, 'setup' => $enrolled ? '' : self::secret(),
        ], 300)) {
            return new \WP_Error('sd_totp_unavailable', __('Unable to start the second-factor check.', 'site-defense'));
        }
        self::cookie($token, time() + 300);
        wp_safe_redirect(add_query_arg('action', 'sd_second_factor', wp_login_url()), 303);
        exit;
    }

    private static function cookie(string $value, int $expires): void
    {
        setcookie(self::COOKIE, $value, [
            'expires' => $expires, 'path' => SITECOOKIEPATH ?: '/', 'secure' => is_ssl(),
            'httponly' => true, 'samesite' => 'Lax',
        ]);
    }

    public static function challenge(): void
    {
        nocache_headers();
        $token = State::field($_COOKIE, self::COOKIE);
        if (!preg_match('/^[a-f0-9]{64}$/D', $token)) {
            wp_die(esc_html__('Sign in again to start a new verification.', 'site-defense'), '', ['response' => 403]);
        }
        $key = Login::key($token);
        $transient = 'sd_challenge_' . $key;
        $pending = get_transient($transient);
        if (!is_array($pending) || !isset($pending['id'])) {
            wp_die(esc_html__('This verification has expired. Sign in again.', 'site-defense'), '', ['response' => 403]);
        }
        add_action('login_enqueue_scripts', static function (): void {
            wp_enqueue_style('site-defense-login', plugins_url('assets/login.css', SITE_DEFENSE_DIR . '/site-defense.php'), ['login'], '1.0.0');
        });
        $error = '';
        if (State::field($_SERVER, 'REQUEST_METHOD') === 'POST') {
            if (!hash_equals(Login::key('form|' . $token), State::field($_POST, 'sd_challenge'))) {
                wp_die(esc_html__('Invalid verification request.', 'site-defense'), '', ['response' => 403]);
            }
            $hits = Login::count(Login::key('totp|' . $pending['id']), 300);
            if ($hits < 1 || $hits > 10) {
                wp_die(esc_html__('Too many verification attempts. Try again later.', 'site-defense'), '', ['response' => 429]);
            }
            $user = get_userdata($pending['id']);
            $codes = [];
            $valid = false;
            if ($user && Hardening::privileged($user)) {
                $code = trim(State::field($_POST, 'sd_code'));
                if (!empty($pending['enroll']) && !get_user_meta($user->ID, '_sd_totp', true)) {
                    if (!is_ssl() || !function_exists('sodium_crypto_secretbox')) {
                        wp_die(esc_html__('Two-factor enrollment requires HTTPS and PHP Sodium.', 'site-defense'), '', ['response' => 403]);
                    }
                    set_transient('sd_enroll_' . $user->ID, $pending['setup'], 60);
                    $codes = self::enroll($user->ID, $code);
                    $valid = (bool) $codes;
                } else {
                    $valid = self::verify($user->ID, $code, $key);
                }
            }
            if ($valid) {
                delete_transient($transient);
                self::cookie('', time() - HOUR_IN_SECONDS);
                wp_set_auth_cookie($user->ID, $pending['remember'], is_ssl());
                do_action('wp_login', $user->user_login, $user);
                if ($codes) {
                    State::log('two_factor', 'Two-factor authentication enabled for user #' . $user->ID, true, ['user_id' => $user->ID]);
                    login_header(__('Two-factor recovery codes', 'site-defense'));
                    echo '<section class="sd-login-panel"><h2>' . esc_html__('Two-factor recovery codes', 'site-defense') . '</h2>';
                    echo '<p>' . esc_html__('Save these recovery codes now. Each can be used once.', 'site-defense') . '</p><ul class="sd-recovery-codes">';
                    foreach ($codes as $recovery) {
                        echo '<li><code>' . esc_html($recovery) . '</code></li>';
                    }
                    echo '</ul><p><a class="button button-primary" href="' . esc_url($pending['redirect']) . '">' . esc_html__('Continue', 'site-defense') . '</a></p></section>';
                    login_footer();
                    exit;
                }
                wp_safe_redirect($pending['redirect']);
                exit;
            }
            $error = __('The code is invalid or has already been used.', 'site-defense');
        }
        login_header(__('Two-factor authentication', 'site-defense'), '', $error ? new \WP_Error('sd_totp', $error) : null);
        echo '<form class="sd-login-panel" method="post"><h2>' . esc_html__('Two-factor authentication', 'site-defense') . '</h2>';
        if (!empty($pending['enroll'])) {
            echo '<p>' . esc_html__('Your site requires a second factor for privileged access. Add this setup key to your authenticator and enter its code.', 'site-defense') . '</p>';
            echo '<p class="sd-login-key"><code>' . esc_html(self::base32($pending['setup'])) . '</code></p>';
        }
        echo '<p><label for="sd-code">' . esc_html__('Authenticator or recovery code', 'site-defense') . '</label>';
        echo '<input type="text" name="sd_code" id="sd-code" class="input" maxlength="16" autocomplete="one-time-code" required></p>';
        echo '<input type="hidden" name="sd_challenge" value="' . esc_attr(Login::key('form|' . $token)) . '">';
        echo '<p><button class="button button-primary button-large">' . esc_html__('Verify and sign in', 'site-defense') . '</button></p></form>';
        login_footer('sd-code');
        exit;
    }

    private static function verify(int $userId, string $code, string $challenge): bool
    {
        $previous = get_user_meta($userId, '_sd_totp', true);
        if (!is_array($previous) || ($previous['challenge'] ?? '') === $challenge) {
            return false;
        }
        $next = $previous;
        $secret = self::decrypt($previous['secret'] ?? '');
        $step = $secret !== false ? self::step($secret, $code, time()) : null;
        $recovery = array_search(Login::key(strtolower($code)), $previous['recovery'], true);
        if ($step !== null && $step > $previous['step']) {
            $next['step'] = $step;
        } elseif ($recovery !== false) {
            unset($next['recovery'][$recovery]);
        } else {
            return false;
        }
        $next['challenge'] = $challenge;
        return (bool) update_user_meta($userId, '_sd_totp', $next, $previous);
    }
}

