<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class FileRepair
{
    public const FINDING = 'Differs from official checksum';

    public static function canPreview(array $finding): bool
    {
        if (($finding[0] ?? '') !== self::FINDING || !preg_match('/^[a-f0-9]{64}$/D', (string) ($finding[2] ?? ''))) {
            return false;
        }
        $location = Quarantine::resolve($finding[1]);
        return $location && in_array($location[1], ['core', 'plugins'], true) &&
            self::authorized($location[1]) && class_exists(\ZipArchive::class);
    }

    public static function preview(string $selector, bool $cli): array|\WP_Error
    {
        if (!preg_match('/^[a-f0-9]{64}$/D', $selector)) {
            return self::error(__('Use a finding selector from scan results.', 'site-defense'));
        }
        foreach ((array) (get_option('sd_scan', [])['findings'] ?? []) as $finding) {
            if (hash_equals(Quarantine::selector($finding), $selector) && self::canPreview($finding)) {
                return self::prepare($finding[1], $finding[2], $cli);
            }
        }
        return self::error(__('This checksum finding is unavailable. Scan the file again.', 'site-defense'));
    }

    private static function prepare(string $path, string $original, bool $cli): array|\WP_Error
    {
        $target = self::target($path);
        if (is_wp_error($target)) {
            return $target;
        }
        if (!self::matches($target['file'], $original)) {
            return self::changed();
        }
        $ref = $target['ref'];
        $checksum = OfficialFiles::expected($ref, OfficialFiles::checksums($ref, true));
        $copy = self::cleanCopy($ref, $checksum);
        if (is_wp_error($copy)) {
            return $copy;
        }
        try {
            $clean = self::streamHash($copy);
            if ($clean === $original) {
                return self::error(__('The file already matches the official copy.', 'site-defense'));
            }
            if (!self::matches($target['file'], $original)) {
                return self::changed();
            }
            $plan = [
                'id' => bin2hex(random_bytes(16)), 'path' => $path, 'reference' => $ref['key'], 'component' => $ref['component'],
                'version' => $ref['version'], 'locale' => $ref['locale'], 'archive' => $ref['archive'],
                'original_sha256' => $original, 'replacement_sha256' => $clean, 'official_checksum' => $checksum,
                'expires' => time() + 15 * MINUTE_IN_SECONDS, 'owner' => $cli ? 'cli' : 'admin:' . get_current_user_id(),
            ];
            if (!set_transient('sd_repair_' . $plan['id'], $plan, 15 * MINUTE_IN_SECONDS)) {
                return self::error(__('Unable to save the repair preview.', 'site-defense'));
            }
            return $plan;
        } finally {
            fclose($copy);
        }
    }

    public static function plan(string $id, bool $cli): ?array
    {
        if (!preg_match('/^[a-f0-9]{32}$/D', $id)) {
            return null;
        }
        $plan = get_transient('sd_repair_' . $id);
        return is_array($plan) && ($plan['expires'] ?? 0) > time() &&
            ($plan['owner'] ?? '') === ($cli ? 'cli' : 'admin:' . get_current_user_id()) ? $plan : null;
    }

    public static function discard(string $id, bool $cli): void
    {
        if (self::plan($id, $cli)) {
            delete_transient('sd_repair_' . $id);
        }
    }

    public static function apply(string $id, bool $cli): array|\WP_Error
    {
        return self::locked(static function () use ($id, $cli) {
            $plan = self::plan($id, $cli);
            if (!$plan) {
                return self::error(__('The repair preview expired. Create a new preview.', 'site-defense'));
            }
            $target = self::target($plan['path']);
            if (is_wp_error($target)) {
                return $target;
            }
            $ref = $target['ref'];
            if ($ref['key'] !== $plan['reference'] || !self::matches($target['file'], $plan['original_sha256'])) {
                return self::changed();
            }
            $checksum = OfficialFiles::expected($ref, OfficialFiles::checksums($ref, true));
            if ($checksum !== $plan['official_checksum']) {
                return self::error(__('The official checksum changed or is unavailable. Create a new preview.', 'site-defense'));
            }
            $copy = self::cleanCopy($ref, $checksum);
            if (is_wp_error($copy)) {
                return $copy;
            }
            try {
                $current = self::target($plan['path']);
                if (is_wp_error($current) || $current['file'] !== $target['file'] || $current['ref']['key'] !== $ref['key'] ||
                    !self::matches($target['file'], $plan['original_sha256']) || self::streamHash($copy) !== $plan['replacement_sha256']) {
                    return self::changed();
                }
                $entry = Quarantine::backupForRepair($plan['path'], $current['file'], $plan['original_sha256'],
                    $plan['replacement_sha256'], $plan['reference']);
                if (!$entry) {
                    return self::error(__('Unable to verify the original quarantine copy. File replacement was cancelled.', 'site-defense'));
                }
                $result = self::publish($plan['path'], $current, $copy, $plan['original_sha256'], $plan['replacement_sha256']);
                if (is_wp_error($result)) {
                    $result->add_data(['quarantine_id' => (int) $entry['id']]);
                    return $result;
                }
                delete_transient('sd_repair_' . $id);
                State::log('file_repaired', $plan['path'], context: ['path' => $plan['path'], 'digest' => $plan['replacement_sha256']]);
                return ['quarantine_id' => (int) $entry['id'], 'path' => $plan['path'], 'sha256' => $plan['replacement_sha256']];
            } finally {
                fclose($copy);
            }
        });
    }

    public static function undo(int $id): array|\WP_Error
    {
        return self::locked(static function () use ($id) {
            $entry = Quarantine::repairEntry($id);
            if (!$entry) {
                return self::error(__('This repair backup is no longer available.', 'site-defense'));
            }
            $result = ['quarantine_id' => $id, 'path' => $entry['path'], 'sha256' => $entry['digest']];
            if ($entry['state'] === 'repair_undone') {
                return $result;
            }
            $target = self::target($entry['path']);
            if (is_wp_error($target)) {
                return $target;
            }
            if ($target['ref']['key'] !== $entry['reference']) {
                return self::changed();
            }
            if (!self::matches($target['file'], $entry['digest'])) {
                if (!self::matches($target['file'], $entry['replacement'])) {
                    return self::changed();
                }
                $copy = tmpfile();
                if (!$copy) {
                    return self::error(__('Unable to prepare the file for restoration.', 'site-defense'));
                }
                try {
                    if (!Quarantine::readRepairCopy($entry, $copy) || !fflush($copy)) {
                        return self::error(__('The quarantine copy failed its integrity check.', 'site-defense'));
                    }
                    $write = self::publish($entry['path'], $target, $copy, $entry['replacement'], $entry['digest'], (int) $entry['permissions']);
                    if (is_wp_error($write)) {
                        return $write;
                    }
                } finally {
                    fclose($copy);
                }
            }
            if (!Quarantine::markRepairUndone($id)) {
                return self::error(__('The original is in place. Retry to update the repair history.', 'site-defense'));
            }
            State::log('file_repair_undone', $entry['path'], context: ['path' => $entry['path'], 'digest' => $entry['digest']]);
            return $result;
        });
    }

    private static function authorized(string $type): bool
    {
        return Quarantine::available() && ($type !== 'core' || (defined('WP_CLI') && WP_CLI) || current_user_can('update_core'));
    }

    private static function target(string $path): array|\WP_Error
    {
        $location = Quarantine::resolve($path);
        if (!$location || !self::authorized($location[1])) {
            return self::error(__('The repair path or its permissions could not be verified.', 'site-defense'));
        }
        [$file, $type] = $location;
        $stat = @lstat($file);
        $plugin = trailingslashit(wp_normalize_path(realpath(SITE_DEFENSE_DIR) ?: SITE_DEFENSE_DIR));
        if (!$stat || ($stat['mode'] & 0170000) !== 0100000 || $stat['size'] > Scanner::MAX_FILE_SIZE ||
            Scanner::linked($file) || !is_readable($file) || str_starts_with(strtolower($file), strtolower($plugin))) {
            return self::error(__('The repair path or its permissions could not be verified.', 'site-defense'));
        }
        $ref = OfficialFiles::reference($type, $file, true);
        return $ref ? compact('file', 'stat', 'ref') : self::error(__('There is no supported official package for this file.', 'site-defense'));
    }

    private static function cleanCopy(array $ref, ?string $checksum)
    {
        if ($checksum === null) {
            return self::error(__('The official checksum for this file is unavailable.', 'site-defense'));
        }
        $copy = tmpfile();
        if (!$copy || !OfficialFiles::extract($ref, $checksum, $copy)) {
            if ($copy) {
                fclose($copy);
            }
            return self::error(__('The official archive or its file could not be verified.', 'site-defense'));
        }
        return $copy;
    }

    private static function publish(string $path, array $target, $copy, string $expected, string $replacement, ?int $mode = null): bool|\WP_Error
    {
        $file = $target['file'];
        $stage = dirname($file) . '/.sd-repair-' . bin2hex(random_bytes(16)) . '.tmp';
        $stream = @fopen($stage, 'xb');
        if (!$stream) {
            return self::error(__('The server could not stage the replacement beside the original.', 'site-defense'));
        }
        try {
            try {
                if (!@chmod($stage, 0600)) {
                    return self::error(__('The replacement could not be staged with the original permissions.', 'site-defense'));
                }
                rewind($copy);
                $written = stream_copy_to_stream($copy, $stream, Scanner::MAX_FILE_SIZE + 1);
                $ready = $written === fstat($copy)['size'] && fflush($stream);
            } finally {
                fclose($stream);
            }
            clearstatcache(true, $stage);
            $staged = @stat($stage);
            $original = $target['stat'];
            if (!$ready || !$staged || !self::matches($stage, $replacement) ||
                ($staged['uid'] !== $original['uid'] && (!function_exists('chown') || !@chown($stage, $original['uid']))) ||
                ($staged['gid'] !== $original['gid'] && (!function_exists('chgrp') || !@chgrp($stage, $original['gid']))) ||
                !@chmod($stage, $mode ?? ($original['mode'] & 0777))) {
                return self::error(__('The replacement could not be staged with the original permissions.', 'site-defense'));
            }
            $current = self::target($path);
            $identity = array_flip(['dev', 'ino', 'uid', 'gid', 'mode']);
            if (is_wp_error($current) || $current['file'] !== $file || $current['ref']['key'] !== $target['ref']['key'] ||
                array_intersect_key($original, $identity) !== array_intersect_key($current['stat'], $identity) ||
                !self::matches($file, $expected)) {
                return self::changed();
            }
            if (!@rename($stage, $file)) {
                return self::error(__('The server could not atomically replace the file. The quarantine copy is intact.', 'site-defense'));
            }
            if (function_exists('opcache_invalidate')) {
                @opcache_invalidate($file, true);
            }
            return self::matches($file, $replacement) ? true :
                self::error(__('The file changed during verification. Inspect the target and its quarantine copy.', 'site-defense'));
        } finally {
            if (is_file($stage)) {
                @unlink($stage);
            }
        }
    }

    private static function streamHash($stream): string
    {
        return (string) @hash_file('sha256', stream_get_meta_data($stream)['uri']);
    }

    private static function matches(string $file, string $sha256): bool
    {
        clearstatcache(true, $file);
        $stat = @lstat($file);
        return $stat && ($stat['mode'] & 0170000) === 0100000 && $stat['size'] <= Scanner::MAX_FILE_SIZE &&
            !Scanner::linked($file) && hash_equals($sha256, (string) @hash_file('sha256', $file));
    }

    private static function locked(callable $operation): array|\WP_Error
    {
        if (!Quarantine::available() || !Quarantine::install()) {
            return self::error(__('Quarantine storage is unavailable.', 'site-defense'));
        }
        $result = null;
        $lock = Scanner::locked(static function () use ($operation, &$result): string {
            $result = $operation();
            return '';
        });
        return $result ?? self::error($lock);
    }

    private static function changed(): \WP_Error
    {
        return self::error(__('The file or installed version changed. Scan again before applying a repair.', 'site-defense'));
    }

    private static function error(string $message): \WP_Error
    {
        return new \WP_Error('sd_repair', $message);
    }
}
