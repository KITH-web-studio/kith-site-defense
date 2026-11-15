<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class OfficialFiles
{
    private const DOWNLOADS = 'https://downloads.wordpress.org/';
    private const MAX_ARCHIVE = 128 * 1024 * 1024;

    public static function reference(string $type, string $file, bool $freshVersion = false): ?array
    {
        global $wp_version, $wp_local_package;
        $file = wp_normalize_path($file);
        if ($type === 'core') {
            $root = wp_normalize_path(realpath(ABSPATH) ?: ABSPATH);
            $root = trailingslashit($root);
            if (!str_starts_with($file, $root)) {
                return null;
            }
            $version = $wp_version;
            $locale = $wp_local_package ?: 'en_US';
            if (!self::version($version) || !preg_match('/^[a-zA-Z0-9_]{2,40}$/D', $locale)) {
                return null;
            }
            $relative = substr($file, strlen($root));
            $query = http_build_query(['version' => $version, 'locale' => $locale]);
            $folder = $locale === 'en_US' ? '' : $locale . '/';
            return [
                'key' => 'core:' . $version . ':' . $locale, 'component' => 'WordPress', 'version' => $version,
                'type' => 'core', 'locale' => $locale, 'relative' => $relative, 'entry' => 'wordpress/' . $relative,
                'archive' => self::DOWNLOADS . 'release/' . $folder . 'wordpress-' . rawurlencode($version) . '.zip',
                'manifest' => 'https://api.wordpress.org/core/checksums/1.0/?' . $query,
            ];
        }
        $root = trailingslashit(wp_normalize_path(realpath(WP_PLUGIN_DIR) ?: WP_PLUGIN_DIR));
        if ($type !== 'plugins' || !str_starts_with($file, $root)) {
            return null;
        }
        [$slug, $relative] = array_pad(explode('/', substr($file, strlen($root)), 2), 2, '');
        if ($relative === '' || !preg_match('/^[a-z0-9][a-z0-9_-]{0,99}$/D', $slug)) {
            return null;
        }
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $versions = [];
        foreach (get_plugins('/' . $slug) as $main => $plugin) {
            if ($freshVersion) {
                $header = $root . $slug . '/' . $main;
                if (Scanner::linked($header) || !is_readable($header)) {
                    return null;
                }
                $plugin = get_plugin_data($header, false, false);
                if ($plugin['Name'] === '') {
                    return null;
                }
            }
            $versions[] = $plugin['Version'];
        }
        $versions = array_unique($versions);
        $version = reset($versions);
        if (count($versions) !== 1 || !is_string($version) || !self::version($version)) {
            return null;
        }
        $artifact = rawurlencode($version);
        return [
            'key' => 'plugin:' . $slug . ':' . $version, 'component' => $slug, 'version' => $version,
            'type' => 'plugin', 'locale' => '', 'relative' => $relative, 'entry' => $slug . '/' . $relative,
            'archive' => self::DOWNLOADS . 'plugin/' . $slug . '.' . $artifact . '.zip',
            'manifest' => self::DOWNLOADS . 'plugin-checksums/' . $slug . '/' . $artifact . '.json',
        ];
    }

    private static function version(string $version): bool
    {
        return (bool) preg_match('/^[0-9][A-Za-z0-9._+-]{0,79}$/D', $version);
    }

    public static function checksums(array $ref, bool $fresh = false): array
    {
        $key = 'sd_ref_' . md5($ref['key']);
        $cached = $fresh ? false : get_transient($key);
        if (is_array($cached)) {
            return $cached;
        }
        $response = wp_safe_remote_get($ref['manifest'], ['timeout' => 5, 'redirection' => 0, 'limit_response_size' => 4 * 1024 * 1024]);
        $data = wp_remote_retrieve_response_code($response) === 200 ? json_decode(wp_remote_retrieve_body($response), true) : null;
        $entries = $data[$ref['type'] === 'core' ? 'checksums' : 'files'] ?? null;
        $entries = is_array($entries) && $entries ? $entries : ['_unavailable' => true];
        if (!$fresh || empty($entries['_unavailable'])) {
            set_transient($key, $entries, DAY_IN_SECONDS);
        }
        return $entries;
    }

    public static function expected(array $ref, array $checksums): ?string
    {
        $entry = $checksums[$ref['relative']] ?? null;
        $hash = is_string($entry) ? $entry : ($entry['sha256'] ?? $entry['md5'] ?? null);
        return is_string($hash) && preg_match('/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/iD', $hash) ? strtolower($hash) : null;
    }

    public static function extract(array $ref, string $checksum, $destination): bool
    {
        if (!class_exists(\ZipArchive::class)) {
            return false;
        }
        $temporary = tmpfile();
        if (!$temporary) {
            return false;
        }
        $path = stream_get_meta_data($temporary)['uri'];
        $zip = new \ZipArchive();
        try {
            $response = wp_safe_remote_get($ref['archive'], [
                'timeout' => 35, 'redirection' => 0, 'limit_response_size' => self::MAX_ARCHIVE + 1,
                'stream' => true, 'filename' => $path,
            ]);
            clearstatcache(true, $path);
            $size = @filesize($path);
            if (wp_remote_retrieve_response_code($response) !== 200 || !$size || $size > self::MAX_ARCHIVE ||
                $zip->open($path, \ZipArchive::RDONLY) !== true) {
                return false;
            }
            try {
                $index = $zip->locateName($ref['entry']);
                $stat = $index === false ? false : $zip->statIndex($index);
                if (!$stat || $stat['name'] !== $ref['entry'] || $stat['size'] > Scanner::MAX_FILE_SIZE ||
                    !$zip->getExternalAttributesIndex($index, $platform, $attributes) ||
                    ($platform === \ZipArchive::OPSYS_UNIX && (($attributes >> 16) & 0170000) === 0120000)) {
                    return false;
                }
                $entry = $zip->getStreamIndex($index);
                if (!$entry) {
                    return false;
                }
                try {
                    $bytes = stream_copy_to_stream($entry, $destination, Scanner::MAX_FILE_SIZE + 1);
                    $file = stream_get_meta_data($destination)['uri'];
                    return $bytes === $stat['size'] && fflush($destination) &&
                        hash_equals($checksum, (string) @hash_file(strlen($checksum) === 64 ? 'sha256' : 'md5', $file));
                } finally {
                    fclose($entry);
                }
            } finally {
                $zip->close();
            }
        } finally {
            fclose($temporary);
        }
    }
}
