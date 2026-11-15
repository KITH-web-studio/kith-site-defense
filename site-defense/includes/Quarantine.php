<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Quarantine
{
    private const CHUNK_SIZE = 256 * 1024;
    public const PAGE_SIZE = 30;

    public static function available(): bool
    {
        return (defined('WP_CLI') && WP_CLI) ||
            (current_user_can('manage_options') && current_user_can('update_plugins'));
    }

    public static function install(): bool
    {
        if (get_option('sd_quarantine_schema') === '2') {
            return true;
        }

        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $entries = State::table('quarantine');
        $chunks = State::table('quarantine_chunks');
        $charset = $wpdb->get_charset_collate();

        dbDelta("CREATE TABLE $entries (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            path text NOT NULL,
            path_key char(64) NOT NULL,
            digest char(64) NOT NULL,
            bytes bigint unsigned NOT NULL,
            permissions smallint unsigned NOT NULL,
            created bigint unsigned NOT NULL,
            state varchar(16) NOT NULL,
            replacement char(64) NOT NULL DEFAULT '',
            reference varchar(250) NOT NULL DEFAULT '',
            PRIMARY KEY  (id),
            KEY path_key (path_key),
            KEY state_id (state,id)
        ) ENGINE=InnoDB $charset;");
        dbDelta("CREATE TABLE $chunks (
            entry_id bigint unsigned NOT NULL,
            chunk_index int unsigned NOT NULL,
            data mediumblob NOT NULL,
            PRIMARY KEY  (entry_id,chunk_index)
        ) ENGINE=InnoDB $charset;");

        foreach ([$entries, $chunks] as $table) {
            if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table))) !== $table) {
                return false;
            }
        }
        if ($wpdb->get_var("SHOW COLUMNS FROM $entries LIKE 'replacement'") !== 'replacement' ||
            $wpdb->get_var("SHOW COLUMNS FROM $entries LIKE 'reference'") !== 'reference') {
            return false;
        }
        update_option('sd_quarantine_schema', '2', false);
        return true;
    }

    public static function selector(array $finding): string
    {
        return hash('sha256', $finding[0] . "\n" . $finding[1] . "\n" . ($finding[2] ?? ''));
    }

    public static function canOffer(string $path): bool
    {
        $location = self::resolve($path);
        return $location && is_file($location[0]) && !is_link($location[0]) && !self::protectedFile($location[0]);
    }

    public static function entries(int $page): array
    {
        global $wpdb;
        $table = State::table('quarantine');
        return $wpdb->get_results($wpdb->prepare(
            "SELECT id, path, bytes, created, state FROM $table WHERE state IN ('stored','repaired','repair_undone') ORDER BY id DESC LIMIT %d OFFSET %d",
            self::PAGE_SIZE + 1, ($page - 1) * self::PAGE_SIZE
        ), ARRAY_A) ?: [];
    }

    public static function move(string $selector): string
    {
        if (!self::install()) {
            return __('Quarantine storage is unavailable.', 'site-defense');
        }

        return Scanner::locked(static function () use ($selector): string {
            $scan = (array) get_option('sd_scan', []);
            foreach ($scan['findings'] ?? [] as $finding) {
                if (in_array($finding[0], Scanner::QUARANTINE_FINDINGS, true) &&
                    hash_equals(self::selector($finding), $selector)) {
                    return self::capture($finding);
                }
            }
            return __('This finding is no longer available. Scan again before quarantining the file.', 'site-defense');
        });
    }

    public static function moveFinding(array $finding): string
    {
        if (!in_array($finding[0] ?? '', Scanner::QUARANTINE_FINDINGS, true) || !self::install()) {
            return __('Invalid or unauthorized request.', 'site-defense');
        }
        return Scanner::locked(static fn () => self::capture($finding));
    }

    private static function capture(array $finding, ?array &$record = null): string
    {
        [$status, $path] = $finding;
        $location = self::resolve($path);
        if (!$location || !is_file($location[0]) || !is_readable($location[0]) || is_link($location[0])) {
            return __('The file is missing or its location cannot be verified.', 'site-defense');
        }
        [$file, $type] = $location;

        if (self::protectedFile($file)) {
            return __('This file is required by the running site. Keep it in place to preserve access to recovery.', 'site-defense');
        }
        $source = @fopen($file, 'rb');
        if (!$source) {
            return __('The file could not be opened.', 'site-defense');
        }
        try {
            $stat = fstat($source);
            if (!$stat || ($stat['mode'] & 0170000) !== 0100000 || $stat['size'] > Scanner::MAX_FILE_SIZE) {
                return __('This file exceeds the quarantine size limit or is not a regular file.', 'site-defense');
            }
            $context = hash_init('sha256');
            $bytes = hash_update_stream($context, $source, $stat['size'] + 1);
            $digest = hash_final($context);
            if ($bytes !== $stat['size'] || !self::matchesScan($finding, $file, $type, $digest)) {
                return __('The file changed since it was scanned. Scan it again before moving it.', 'site-defense');
            }

            $entry = self::existing($path, $digest);
            $verified = $entry && self::readCopy($entry);
            if (!$verified) {
                rewind($source);
                $entry = self::store($path, $source, $stat, $digest) ? self::existing($path, $digest) : null;
                $verified = $entry && self::readCopy($entry);
            }
            if (!$verified) {
                return __('The quarantine copy could not be verified. The original file was kept.', 'site-defense');
            }
        } finally {
            // Windows requires us to close the source handle before unlinking it.
            fclose($source);
        }

        $resolved = self::resolve($path);
        if (!$resolved || $resolved[0] !== $file || is_link($file) || !is_file($file) ||
            @hash_file('sha256', $file) !== $digest) {
            return __('A verified copy is in quarantine. The source changed before it could be removed.', 'site-defense');
        }
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($file, true);
        }
        if (!@unlink($file)) {
            return __('A verified copy is in quarantine. The server could not remove the original file.', 'site-defense');
        }

        State::log('file_quarantined', $path);
        $record = $entry;
        return __('File moved to quarantine.', 'site-defense');
    }

    public static function cleanupMove(array $finding, bool $retry): array|\WP_Error
    {
        if (!self::install() || !in_array($finding[0], Scanner::QUARANTINE_FINDINGS, true)) {
            return new \WP_Error('sd_cleanup_file', __('Quarantine storage is unavailable.', 'site-defense'));
        }
        $entry = null;
        $message = Scanner::locked(static function () use ($finding, $retry, &$entry): string {
            $location = self::resolve($finding[1]);
            if ($retry && $location && !file_exists($location[0]) && !is_link($location[0])) {
                $saved = self::existing($finding[1], $finding[2]);
                if ($saved && self::readCopy($saved)) {
                    $entry = $saved;
                    return '';
                }
            }
            return self::capture($finding, $entry);
        });
        return $entry ?: new \WP_Error('sd_cleanup_file', $message);
    }

    private static function matchesScan(array $finding, string $file, string $type, string $digest): bool
    {
        $expected = $finding[2] ?? null;
        if (is_string($expected)) {
            return hash_equals($expected, $digest);
        }
        // Older scan results have no fingerprint. Confirm the original finding against the current file.
        return Scanner::recheck($type, $file, $finding[0]);
    }

    private static function existing(string $path, string $digest): ?array
    {
        global $wpdb;
        $table = State::table('quarantine');
        return $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table WHERE path_key = %s AND digest = %s AND state = 'stored' ORDER BY id DESC LIMIT 1",
            hash('sha256', $path), $digest
        ), ARRAY_A) ?: null;
    }

    private static function store(string $path, $source, array $stat, string $digest, array $repair = []): ?array
    {
        global $wpdb;
        $table = State::table('quarantine');
        $chunks = State::table('quarantine_chunks');
        $entry = [
            'path' => $path, 'path_key' => hash('sha256', $path), 'digest' => $digest,
            'bytes' => $stat['size'], 'permissions' => $stat['mode'] & 0777,
            'created' => time(), 'state' => 'stored',
        ];
        $formats = ['%s', '%s', '%s', '%d', '%d', '%d', '%s'];
        if ($repair) {
            $entry['state'] = 'repaired';
            $entry['replacement'] = $repair['replacement'];
            $entry['reference'] = $repair['reference'];
            array_push($formats, '%s', '%s');
        }

        if ($wpdb->query('START TRANSACTION') === false) {
            return null;
        }
        $committed = false;
        try {
            if ($wpdb->insert($table, $entry, $formats) !== 1) {
                return null;
            }
            $entry['id'] = (int) $wpdb->insert_id;
            for ($offset = 0; $offset < $entry['bytes']; $offset += self::CHUNK_SIZE) {
                $length = min(self::CHUNK_SIZE, $entry['bytes'] - $offset);
                $data = fread($source, $length);
                if (!is_string($data) || strlen($data) !== $length || $wpdb->insert($chunks, [
                    'entry_id' => $entry['id'],
                    'chunk_index' => intdiv($offset, self::CHUNK_SIZE),
                    'data' => base64_encode($data),
                ], ['%d', '%d', '%s']) !== 1) {
                    return null;
                }
            }
            $committed = self::readCopy($entry) && $wpdb->query('COMMIT') !== false;
            return $committed ? $entry : null;
        } finally {
            if (!$committed) {
                $wpdb->query('ROLLBACK');
            }
        }
    }

    public static function backupForRepair(string $path, string $file, string $digest, string $replacement, string $reference): ?array
    {
        global $wpdb;
        $table = State::table('quarantine');
        $existing = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table WHERE path_key=%s AND digest=%s AND replacement=%s AND reference=%s AND state='repaired'
             ORDER BY id DESC LIMIT 1",
            hash('sha256', $path), $digest, $replacement, $reference
        ), ARRAY_A);
        $source = @fopen($file, 'rb');
        if (!$source) {
            return null;
        }
        try {
            $stat = fstat($source);
            if (!$stat || ($stat['mode'] & 0170000) !== 0100000 || $stat['size'] > Scanner::MAX_FILE_SIZE) {
                return null;
            }
            if ($existing && (int) $existing['permissions'] === ($stat['mode'] & 0777) && self::readCopy($existing)) {
                return $existing;
            }
            return self::store($path, $source, $stat, $digest, compact('replacement', 'reference'));
        } finally {
            fclose($source);
        }
    }

    public static function repairEntry(int $id): ?array
    {
        global $wpdb;
        $table = State::table('quarantine');
        return $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table WHERE id=%d AND state IN ('repaired','repair_undone')", $id
        ), ARRAY_A) ?: null;
    }

    public static function verificationBackup(int $id, string $path, string $digest): ?array
    {
        if ($id < 1 || get_option('sd_quarantine_schema') !== '2') {
            return null;
        }
        global $wpdb;
        $table = State::table('quarantine');
        $entry = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table WHERE id=%d AND path_key=%s AND digest=%s AND state IN ('stored','repaired')",
            $id, hash('sha256', $path), $digest
        ), ARRAY_A);
        return $entry && self::readCopy($entry) ? ['state' => $entry['state'], 'replacement' => $entry['replacement']] : null;
    }

    public static function recoveredRepairId(string $path, string $digest): int
    {
        global $wpdb;
        $file = self::resolve($path)[0] ?? '';
        if ($file === '' || Scanner::linked($file) || !is_file($file)) {
            return 0;
        }
        $table = State::table('quarantine');
        $current = @hash_file('sha256', $file);
        $entry = $current ? $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table WHERE path_key=%s AND digest=%s AND replacement=%s AND state='repaired' ORDER BY id DESC LIMIT 1",
            hash('sha256', $path), $digest, $current
        ), ARRAY_A) : null;
        return $entry && self::readCopy($entry) ? (int) $entry['id'] : 0;
    }

    public static function readRepairCopy(array $entry, $destination): bool
    {
        return self::readCopy($entry, $destination);
    }

    public static function markRepairUndone(int $id): bool
    {
        global $wpdb;
        return $wpdb->update(State::table('quarantine'), ['state' => 'repair_undone'], ['id' => $id], ['%s'], ['%d']) !== false;
    }

    private static function readCopy(array $entry, $destination = null): bool
    {
        global $wpdb;
        $chunks = State::table('quarantine_chunks');
        $hash = hash_init('sha256');
        $size = (int) $entry['bytes'];
        if ($size < 0 || $size > Scanner::MAX_FILE_SIZE) {
            return false;
        }
        for ($offset = 0; $offset < $size; $offset += self::CHUNK_SIZE) {
            $encoded = $wpdb->get_var($wpdb->prepare(
                "SELECT data FROM $chunks WHERE entry_id = %d AND chunk_index = %d",
                $entry['id'], intdiv($offset, self::CHUNK_SIZE)
            ));
            $data = is_string($encoded) ? base64_decode($encoded, true) : false;
            if (!is_string($data) || strlen($data) !== min(self::CHUNK_SIZE, $size - $offset)) {
                return false;
            }
            if ($destination && fwrite($destination, $data) !== strlen($data)) {
                return false;
            }
            hash_update($hash, $data);
        }
        return hash_equals($entry['digest'], hash_final($hash));
    }

    public static function restore(int $id): string
    {
        if (!self::install()) {
            return __('Quarantine storage is unavailable.', 'site-defense');
        }

        return Scanner::locked(static function () use ($id): string {
            global $wpdb;
            $table = State::table('quarantine');
            $entry = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM $table WHERE id = %d AND state = 'stored'", $id
            ), ARRAY_A);
            if (!$entry) {
                return __('This quarantine entry is no longer available.', 'site-defense');
            }
            $location = self::resolve($entry['path']);
            if (!$location) {
                return __('The original folder is missing or cannot be verified. The copy remains in quarantine.', 'site-defense');
            }
            $file = $location[0];
            if (file_exists($file) || is_link($file)) {
                return __('A file already exists at the original path. The copy remains in quarantine.', 'site-defense');
            }
            $temporary = tmpfile();
            if (!$temporary) {
                return __('Unable to prepare the file for restoration.', 'site-defense');
            }
            try {
                if (!self::readCopy($entry, $temporary) || !fflush($temporary)) {
                    return __('The quarantine copy failed its integrity check.', 'site-defense');
                }
                $result = self::publish($entry, $file, $temporary);
                if ($result !== '') {
                    return $result;
                }
            } finally {
                fclose($temporary);
            }
            if ($wpdb->update($table, ['state' => 'restored'], ['id' => $id], ['%s'], ['%d']) === 1 &&
                $wpdb->delete(State::table('quarantine_chunks'), ['entry_id' => $id], ['%d']) !== false) {
                $wpdb->delete($table, ['id' => $id], ['%d']);
            }
            State::log('file_restored', $entry['path']);
            return __('File restored to its original location.', 'site-defense');
        });
    }

    private static function publish(array $entry, string $file, $temporary): string
    {
        if ((self::resolve($entry['path'])[0] ?? '') !== $file) {
            return __('The original folder is missing or cannot be verified. The copy remains in quarantine.', 'site-defense');
        }
        $temporaryPath = stream_get_meta_data($temporary)['uri'];
        if (!function_exists('link') || !@link($temporaryPath, $file)) {
            // Some hosts mount their temporary directory on a different filesystem.
            $target = @fopen($file, 'xb');
            if (!$target) {
                return file_exists($file) || is_link($file)
                    ? __('A file already exists at the original path. The copy remains in quarantine.', 'site-defense')
                    : __('The file could not be restored. The copy remains in quarantine.', 'site-defense');
            }
            $identity = fstat($target);
            rewind($temporary);
            $written = stream_copy_to_stream($temporary, $target);
            $saved = fflush($target) && $written === (int) $entry['bytes'];
            fclose($target);
            if (!$saved || @hash_file('sha256', $file) !== $entry['digest']) {
                clearstatcache(true, $file);
                $current = @lstat($file);
                if ($identity && $current && $identity['dev'] === $current['dev'] &&
                    $identity['ino'] === $current['ino'] && !is_link($file)) {
                    @unlink($file);
                }
                return __('The file could not be restored. The copy remains in quarantine.', 'site-defense');
            }
        }
        @chmod($file, (int) $entry['permissions']);
        return '';
    }

    private static function protectedFile(string $file): bool
    {
        $plugin = wp_normalize_path(realpath(SITE_DEFENSE_DIR) ?: SITE_DEFENSE_DIR);
        if (str_starts_with($file, trailingslashit($plugin))) {
            return true;
        }
        foreach (['wp-login.php', 'wp-admin/admin-post.php'] as $entryPoint) {
            $required = realpath(ABSPATH . $entryPoint);
            if ($required !== false && wp_normalize_path($required) === $file) {
                return true;
            }
        }
        return in_array($file, array_map('wp_normalize_path', get_included_files()), true);
    }

    public static function resolve(string $path): ?array
    {
        if ($path === '' || str_contains($path, "\0")) {
            return null;
        }
        $path = wp_normalize_path($path);
        $absolute = preg_match('~^(?:[A-Z]:/|/)~i', $path) ? $path : wp_normalize_path(ABSPATH) . $path;
        $relative = preg_replace('~^[A-Z]:~i', '', $absolute);
        if (preg_match('~(?:^|/)\.{1,2}(?:/|$)|[\x00-\x1F:]~', $relative) || str_ends_with($absolute, '/')) {
            return null;
        }
        clearstatcache(true);
        $parent = realpath(dirname($absolute));
        if ($parent === false) {
            return null;
        }
        $parent = wp_normalize_path($parent);
        $roots = Scanner::roots();
        foreach ($roots as [$type, $root]) {
            $root = trailingslashit(wp_normalize_path($root));
            if (!str_starts_with($absolute, $root)) {
                continue;
            }
            $canonicalRoot = realpath($root);
            if ($canonicalRoot === false || is_link(untrailingslashit($root))) {
                continue;
            }
            $canonical = trailingslashit(wp_normalize_path($canonicalRoot)) . substr($absolute, strlen($root));
            if (dirname($canonical) === $parent) {
                return [$canonical, Scanner::typeFor($canonical)];
            }
        }
        // The scanner also checks top-level WordPress PHP files, apart from wp-config.php.
        if (dirname($absolute) === untrailingslashit(wp_normalize_path(ABSPATH)) &&
            $parent === wp_normalize_path(realpath(ABSPATH)) &&
            basename($absolute) !== 'wp-config.php' && str_ends_with($absolute, '.php')) {
            return [$parent . '/' . basename($absolute), 'core'];
        }
        return null;
    }
}

