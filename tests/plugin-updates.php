<?php
// wp eval-file tests/plugin-updates.php /path/to/signed-fixtures single|bulk
if (!defined('SD_RELEASE_LAB') || SD_RELEASE_LAB !== true || wp_get_environment_type() !== 'local') {
    throw new RuntimeException('A disposable WordPress release lab is required.');
}

require_once ABSPATH . 'wp-admin/includes/admin.php';
require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

use SiteDefense\PluginUpdates;
use SiteDefense\State;

$root = $args[0] ?? '';
$mode = $args[1] ?? 'single';
$slug = 'site-defense/site-defense.php';
$repository = 'KITH-web-studio/kith-site-defense';
$prefix = 'https://github.com/' . $repository . '/releases/download/v';
$api = 'https://api.github.com/repos/' . $repository . '/releases';
$files = ['site-defense.zip', 'site-defense-update.json', 'site-defense-update.sig'];
$installed = get_file_data(WP_PLUGIN_DIR . '/' . $slug, ['version' => 'Version'])['version'];
$stable = '1.0.0';
$rc = '1.1.0-rc.1';
$older = '0.9.0';
$transient = static fn (bool $rc): string => 'sd_plugin_release_' .
    md5($repository . '|' . $installed . '|' . PHP_VERSION . '|' . get_bloginfo('version') . '|' . (int) $rc);
$release = static fn (string $version): array => ['tag_name' => 'v' . $version, 'draft' => false,
    'prerelease' => str_contains($version, '-rc.'), 'assets' => array_map(
        static fn ($file) => ['name' => $file, 'state' => 'uploaded'], $files
    )];
$expect = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};
$phase = '';
$history = [];
$http = static function ($reply, array $options, string $url) use ($root, $prefix, $api, $files, $release, $stable, $rc, $older, &$phase, &$history, $expect) {
    $history[] = $url;
    $body = '';
    $code = 200;
    if (str_starts_with($url, 'https://api.wordpress.org/plugins/update-check/')) {
        $body = '{"plugins":{},"translations":[],"no_update":{}}';
    } elseif (str_starts_with($url, 'https://api.wordpress.org/themes/update-check/')) {
        $body = '{"themes":{},"translations":[],"no_update":{}}';
    } elseif ($url === "$api/latest") {
        $body = json_encode($release(match ($phase) {
            'no_stable' => $rc,
            'incompatible' => '1.2.0',
            'downgrade' => $older,
            default => $stable,
        }));
    } elseif ($url === "$api?per_page=20") {
        $draft = $release('1.3.0-rc.1');
        $draft['draft'] = true;
        $body = json_encode([$draft, $release($rc), $release($stable)]);
    } elseif (str_starts_with($url, "$api/tags/v")) {
        $body = json_encode($release(substr($url, strlen("$api/tags/v"))));
    } elseif (str_starts_with($url, $prefix)) {
        [$version, $asset] = array_pad(explode('/', substr($url, strlen($prefix)), 2), 2, '');
        $expect(in_array($version, [$stable, $rc, '1.2.0'], true) && in_array($asset, $files, true), 'Unexpected release asset URL.');
        $fixture = $root . '/' . ($phase === 'wrong_version' && $asset !== 'site-defense.zip' ? $rc : $version) . '/' . $asset;
        $body = file_get_contents($fixture);
        if ($asset === 'site-defense-update.sig' && $phase === 'missing_signature') {
            $code = 404;
            $body = '';
        }
        if (($asset === 'site-defense-update.json' && $phase === 'bad_manifest') ||
            ($asset === 'site-defense.zip' && $phase === 'bad_zip')) {
            $body[0] = $body[0] ^ "\x01";
        }
        if (!empty($options['stream'])) {
            $expect(($options['limit_response_size'] ?? 0) === strlen($body) + 1, 'ZIP must be streamed with the signed size limit.');
            file_put_contents($options['filename'], $body);
            $body = '';
        }
    } else {
        return new WP_Error('sd_unexpected_fixture_request', 'Unexpected test request.');
    }
    if (str_contains($url, 'github.com')) {
        $expect(($options['user-agent'] ?? '') === 'Site Defense updater' && !array_key_exists('authorization',
            array_change_key_case($options['headers'] ?? [])), 'GitHub requests must be anonymous.');
    }
    return ['body' => $body, 'response' => ['code' => $code, 'message' => 'Fixture']];
};
$original = get_option('sd_settings', null);
$check = static function (bool $flush = true) use ($slug, $transient) {
    if ($flush) {
        delete_site_transient($transient(PluginUpdates::includesCandidates()));
    }
    delete_site_transient('update_plugins');
    wp_update_plugins();
    return get_site_transient('update_plugins')->response[$slug] ?? null;
};
$channel = static function (bool $rc) {
    $settings = State::settings();
    $settings['plugin_release_candidates'] = $rc;
    update_option('sd_settings', $settings);
};
$context = ['type' => 'plugin', 'action' => 'update', 'plugin' => $slug];
$skin = new WP_Ajax_Upgrader_Skin();
$upgrader = new Plugin_Upgrader($skin);
$upgrader->init();
$checksum = hash_file('sha256', WP_PLUGIN_DIR . '/' . $slug);
add_filter('pre_http_request', $http, 10, 3);
add_filter('filesystem_method', static fn () => 'direct');

try {
    $channel(false);
    $phase = 'no_stable';
    $expect($check() === null, 'Stable policy accepted an RC mislabeled as the latest release.');
    $phase = 'downgrade';
    $expect($check() === null, 'A rollback was offered as an update.');
    $phase = 'incompatible';
    $expect($check() === null, 'An incompatible PHP requirement was ignored.');
    foreach (['missing_signature', 'bad_manifest', 'wrong_version'] as $phase) {
        $expect($check() === null, 'Invalid release metadata made it into the WordPress transient.');
    }
    $phase = '';
    $history = [];
    $offer = $check();
    $expect($offer->new_version === $stable && $offer->package === "https://site-defense-update.invalid:1/v$stable", 'WordPress did not offer the signed stable version.');
    $expect(!in_array("$api?per_page=20", $history, true) && !in_array("$prefix$stable/site-defense.zip", $history, true),
        'Checking stable versions should not query RC or download the ZIP.');
    $history = [];
    $check(false);
    $expect(!in_array("$api/latest", $history, true), 'Repeat WordPress checks should use the release cache.');
    $channel(true);
    $expect(get_site_transient('update_plugins') === false, 'Changing channels did not invalidate the WordPress update list.');
    $rcOffer = $check();
    $expect($rcOffer->new_version === $rc, 'RC opt-in did not offer the newer candidate.');
    $channel(false);
    $expect(is_wp_error($upgrader->download_package($rcOffer->package, false, $context)), 'A stale RC offer bypassed the stable policy.');
    $expect(is_wp_error($upgrader->download_package("$prefix$stable/site-defense.zip", false, $context)), 'A direct ZIP bypassed signing.');
    remove_filter('upgrader_pre_download', [PluginUpdates::class, 'download'], 100);
    try {
        $expect(is_wp_error($upgrader->download_package($offer->package, false, $context)), 'Package marker downloaded with the verifier removed.');
    } finally {
        add_filter('upgrader_pre_download', [PluginUpdates::class, 'download'], 100, 4);
    }

    $phase = 'bad_zip';
    $offer = $check();
    $result = $upgrader->upgrade($slug);
    $expect($result !== true && in_array('sd_plugin_update_checksum', $skin->get_errors()->get_error_codes(), true),
        'Modified ZIP did not fail inside the native updater. ' . $skin->get_error_messages());
    $expect(hash_file('sha256', WP_PLUGIN_DIR . '/' . $slug) === $checksum && is_plugin_active($slug), 'Failed update changed the installed plugin.');
    $phase = 'missing_signature';
    $expect(is_wp_error($upgrader->download_package($offer->package, false, $context)), 'A previously offered update installed after its signature was removed.');
    $phase = '';
    $skin = new WP_Ajax_Upgrader_Skin();
    $upgrader = new Plugin_Upgrader($skin);
    if ($mode === 'bulk') {
        $channel(true);
        $target = $rc;
        $check();
        $result = $upgrader->bulk_upgrade([$slug]);
        $expect(!empty($result[$slug]) && !is_wp_error($result[$slug]), 'The native bulk update failed. ' . $skin->get_error_messages());
    } else {
        $target = $stable;
        $check();
        $result = $upgrader->upgrade($slug);
        $expect($result === true, 'The native update failed.');
    }
    $actual = get_file_data(WP_PLUGIN_DIR . '/' . $slug, ['version' => 'Version'])['version'];
    $expect($actual === $target, 'Wrong package version installed.');
    echo wp_json_encode(['wp' => get_bloginfo('version'), 'php' => PHP_VERSION, 'woo' => defined('WC_VERSION') ? WC_VERSION : null,
        'mode' => $mode, 'installed' => $actual, 'security' => 'passed']), PHP_EOL;
} finally {
    delete_site_transient($transient(false));
    delete_site_transient($transient(true));
    delete_site_transient('update_plugins');
    if ($original === null) {
        delete_option('sd_settings');
    } else {
        update_option('sd_settings', $original);
    }
    remove_filter('pre_http_request', $http, 10);
}

