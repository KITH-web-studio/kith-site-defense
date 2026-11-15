<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class PluginUpdates
{
    private const PLUGIN = 'site-defense/site-defense.php';
    private const ZIP = 'site-defense.zip';
    private const MANIFEST = 'site-defense-update.json';
    private const SIGNATURE = 'site-defense-update.sig';
    private const MAX_ZIP = 32 * 1024 * 1024;
    // This marker cannot be downloaded if WordPress runs without the verification hook.
    private const PACKAGE = 'https://site-defense-update.invalid:1/v';
    private const VERSION = '(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){2}(?:-rc\.[1-9][0-9]{0,5})?';

    public static function register(): void
    {
        add_filter('update_plugins_github.com', [self::class, 'offer'], 10, 3);
        add_filter('upgrader_pre_download', [self::class, 'download'], 100, 4);
        add_action('update_option_sd_settings', [self::class, 'settingsChanged'], 10, 2);
    }

    public static function includesCandidates(): bool
    {
        return State::enabled('plugin_release_candidates');
    }

    public static function settingsChanged($old, $new): void
    {
        if (!empty($old['plugin_release_candidates']) !== !empty($new['plugin_release_candidates'])) {
            delete_site_transient('update_plugins');
        }
    }

    public static function offer($update, array $headers, string $plugin)
    {
        if ($plugin !== self::pluginFile()) {
            return $update;
        }
        [$installed, $repository] = self::identity();
        if ($repository === '' || ($headers['UpdateURI'] ?? '') !== 'https://github.com/' . $repository || self::key() === '') {
            return false;
        }
        $rc = self::includesCandidates();
        $cacheKey = 'sd_plugin_release_' . md5($repository . '|' . $installed . '|' . PHP_VERSION . '|' . get_bloginfo('version') . '|' . (int) $rc);
        $cache = get_site_transient($cacheKey);
        if (is_array($cache)) {
            $manifest = $cache['manifest'] ?? null;
        } else {
            $manifest = self::discover($repository, $installed, $rc);
            set_site_transient($cacheKey, $manifest ? ['manifest' => $manifest] : [], $manifest ? 6 * HOUR_IN_SECONDS : 15 * MINUTE_IN_SECONDS);
        }
        if (!is_array($manifest) || !self::eligible($manifest['version'] ?? null, $installed, $rc) || !self::compatible($manifest)) {
            return false;
        }
        return ['slug' => 'site-defense', 'version' => $manifest['version'], 'requires' => $manifest['requires_wp'],
            'requires_php' => $manifest['requires_php'], 'url' => 'https://github.com/' . $repository . '/releases/tag/v' . $manifest['version'],
            'package' => self::PACKAGE . $manifest['version']];
    }

    public static function download($reply, $package, $upgrader, array $context)
    {
        // Bulk plugin updates may provide only the plugin basename in hook_extra.
        if (!$upgrader instanceof \Plugin_Upgrader || ($context['type'] ?? 'plugin') !== 'plugin' ||
            ($context['action'] ?? 'update') !== 'update' ||
            ($context['plugin'] ?? '') !== self::pluginFile()) {
            return $reply;
        }
        [$installed, $repository] = self::identity();
        $version = is_string($package) && str_starts_with($package, self::PACKAGE) ? substr($package, strlen(self::PACKAGE)) : '';
        $rc = self::includesCandidates();
        if ($repository === '' || self::key() === '' || !self::eligible($version, $installed, $rc)) {
            return new \WP_Error('sd_plugin_update_unavailable', __('This Site Defense update is unavailable for the selected channel.', 'site-defense'));
        }
        $release = self::api($repository, '/tags/v' . $version);
        $manifest = self::releaseVersion($release, $installed, $rc) === $version ? self::manifest($repository, $version) : null;
        if (!$manifest || !self::compatible($manifest)) {
            return new \WP_Error('sd_plugin_update_manifest', __('The signed Site Defense release could not be verified.', 'site-defense'));
        }
        $file = wp_tempnam(self::ZIP);
        if (!$file) {
            return new \WP_Error('sd_plugin_update_download', __('Unable to download the Site Defense update.', 'site-defense'));
        }
        $response = self::get(self::assetUrl($repository, $version, self::ZIP), $manifest['bytes'] + 1, $file);
        clearstatcache(true, $file);
        if (wp_remote_retrieve_response_code($response) === 200 && @filesize($file) === $manifest['bytes'] &&
            hash_equals($manifest['sha256'], (string) @hash_file('sha256', $file))) {
            return $file;
        }
        wp_delete_file($file);
        return new \WP_Error('sd_plugin_update_checksum', __('The Site Defense ZIP failed verification. The installed plugin was kept.', 'site-defense'));
    }

    private static function identity(): array
    {
        $headers = get_file_data(SITE_DEFENSE_DIR . '/site-defense.php', ['version' => 'Version', 'uri' => 'Update URI']);
        preg_match('~^https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99})$~D', $headers['uri'], $match);
        return [$headers['version'], $match[1] ?? ''];
    }

    private static function pluginFile(): string
    {
        return plugin_basename(SITE_DEFENSE_DIR . '/site-defense.php');
    }

    private static function key(): string
    {
        static $key;
        if ($key !== null) {
            return $key;
        }
        $data = json_decode((string) @file_get_contents(SITE_DEFENSE_DIR . '/data/plugin-updates.json'), true);
        $value = is_string($data['public_key'] ?? null) ? base64_decode($data['public_key'], true) : false;
        return $key = function_exists('sodium_crypto_sign_verify_detached') && is_string($value) && strlen($value) === 32 ? $value : '';
    }

    private static function eligible($version, string $installed, bool $rc): bool
    {
        return is_string($version) && preg_match('/^' . self::VERSION . '$/D', $version) &&
            ($rc || !str_contains($version, '-rc.')) && version_compare($version, $installed, '>');
    }

    private static function discover(string $repository, string $installed, bool $rc): ?array
    {
        $releases = [self::api($repository, '/latest')];
        if ($rc) {
            $recent = self::api($repository, '?per_page=20');
            if (is_array($recent) && array_is_list($recent)) {
                $releases = array_merge($releases, $recent);
            }
        }
        $versions = [];
        foreach ($releases as $release) {
            $version = self::releaseVersion($release, $installed, $rc);
            if ($version !== null) {
                $versions[$version] = $version;
            }
        }
        usort($versions, static fn (string $a, string $b): int => version_compare($b, $a));
        foreach (array_slice($versions, 0, 4) as $version) {
            $manifest = self::manifest($repository, $version);
            if ($manifest && self::compatible($manifest)) {
                return $manifest;
            }
        }
        return null;
    }

    private static function releaseVersion($release, string $installed, bool $rc): ?string
    {
        if (!is_array($release) || ($release['draft'] ?? null) !== false || !is_string($tag = $release['tag_name'] ?? null) ||
            !str_starts_with($tag, 'v') || !self::eligible($version = substr($tag, 1), $installed, $rc) ||
            ($release['prerelease'] ?? null) !== str_contains($version, '-rc.') || !is_array($release['assets'] ?? null)) {
            return null;
        }
        $names = [];
        foreach ($release['assets'] as $asset) {
            if (($asset['state'] ?? null) === 'uploaded' && is_string($asset['name'] ?? null)) {
                $names[] = $asset['name'];
            }
        }
        return array_diff([self::ZIP, self::MANIFEST, self::SIGNATURE], $names) ? null : $version;
    }

    private static function manifest(string $repository, string $version): ?array
    {
        $payload = self::get(self::assetUrl($repository, $version, self::MANIFEST), 4097);
        if (wp_remote_retrieve_response_code($payload) !== 200) {
            return null;
        }
        $signature = self::get(self::assetUrl($repository, $version, self::SIGNATURE), 65);
        $bytes = wp_remote_retrieve_body($payload);
        $proof = wp_remote_retrieve_body($signature);
        if (wp_remote_retrieve_response_code($signature) !== 200 || strlen($bytes) > 4096 || strlen($proof) !== 64 ||
            !sodium_crypto_sign_verify_detached($proof, $bytes, self::key())) {
            return null;
        }
        $data = json_decode($bytes, true, 8);
        if (!is_array($data) || ($data['schema'] ?? null) !== 1 || ($data['repository'] ?? null) !== $repository ||
            ($data['plugin'] ?? null) !== self::PLUGIN || ($data['version'] ?? null) !== $version || ($data['zip'] ?? null) !== self::ZIP ||
            !is_int($data['bytes'] ?? null) || $data['bytes'] < 1 || $data['bytes'] > self::MAX_ZIP ||
            !is_string($data['sha256'] ?? null) || !preg_match('/^[a-f0-9]{64}$/D', $data['sha256'])) {
            return null;
        }
        return $data;
    }

    private static function compatible(array $manifest): bool
    {
        foreach (['requires_wp' => get_bloginfo('version'), 'requires_php' => PHP_VERSION] as $key => $version) {
            $required = $manifest[$key] ?? null;
            if (!is_string($required) || !preg_match('/^[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?$/D', $required) ||
                version_compare($version, $required, '<')) {
                return false;
            }
        }
        return true;
    }

    private static function api(string $repository, string $path)
    {
        $response = self::get('https://api.github.com/repos/' . $repository . '/releases' . $path, 512 * 1024, api: true);
        return wp_remote_retrieve_response_code($response) === 200 ? json_decode(wp_remote_retrieve_body($response), true, 20) : null;
    }

    private static function assetUrl(string $repository, string $version, string $file): string
    {
        return 'https://github.com/' . $repository . '/releases/download/v' . $version . '/' . $file;
    }

    private static function get(string $url, int $limit, string $file = '', bool $api = false)
    {
        $options = ['timeout' => $file === '' ? 6 : 30, 'redirection' => $api ? 0 : 3, 'limit_response_size' => $limit,
            'user-agent' => 'Site Defense updater', 'decompress' => false];
        if ($api) {
            $options['headers'] = ['Accept' => 'application/vnd.github+json'];
        }
        if ($file !== '') {
            $options['stream'] = true;
            $options['filename'] = $file;
        }
        return wp_safe_remote_get($url, $options);
    }
}
