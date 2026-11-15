<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class CleanupVerification
{
    public static function verify(string $id): array|\WP_Error
    {
        $plan = CleanupPlan::show($id);
        if (!$plan) {
            return new \WP_Error('sd_cleanup', __('Cleanup plan or step was not found.', 'site-defense'));
        }
        $steps = [];
        $counts = [];
        $cron = null;
        if (in_array('cron', array_column($plan['steps'], 'type'), true)) {
            $cron = CronCleanup::snapshot()[1] ?? null;
        }
        foreach ($plan['steps'] as $key => $step) {
            $record = match ($step['type']) {
                'cron' => self::cron($step, $cron),
                'db_content' => CleanupPlan::verifyDatabaseStep($id, $key),
                default => self::file($step),
            };
            if (is_wp_error($record)) {
                return $record;
            }
            $status = $record['status'];
            $counts[$status] = ($counts[$status] ?? 0) + 1;
            $steps[$key] = $record;
        }
        $points = self::entryPoints($plan['evidence']);
        $entryStatuses = array_map(static fn (array $point) => $point['after']['status'], $points);
        $entryStatus = match (true) {
            !$points => 'no_saved_hypothesis',
            in_array('still_affected', $entryStatuses, true) => 'still_affected',
            (bool) array_diff($entryStatuses, ['outside_affected_range', 'component_absent']) => 'review_required',
            default => 'outside_saved_vulnerability_scope',
        };
        return [
            'plan_id' => $id, 'verified_at' => time(), 'snapshot_at' => $plan['created'],
            'evidence_sha256' => $plan['evidence_sha256'], 'summary' => $counts, 'steps' => $steps,
            'entry_status' => $entryStatus, 'entry_points' => $points,
            'before_checks' => $plan['evidence']['status'] ?? [], 'current_checks' => Investigation::status(),
            'verification_scope' => 'selected_targets_and_saved_entry_hypotheses',
        ];
    }

    private static function file(array $step): array
    {
        $path = $step['target'];
        $file = Quarantine::resolve($path)[0] ?? '';
        $after = ['state' => 'unavailable', 'sha256' => null];
        if ($file !== '') {
            clearstatcache(true, $file);
            $stat = @lstat($file);
            if ($stat === false && is_readable(dirname($file))) {
                $after['state'] = 'absent';
            } elseif ($stat && ($stat['mode'] & 0170000) === 0100000 && $stat['size'] <= Scanner::MAX_FILE_SIZE &&
                !Scanner::linked($file) && ($hash = @hash_file('sha256', $file))) {
                $after = ['state' => 'present', 'sha256' => $hash];
            }
        }
        $state = $step['state'];
        $prior = $after['state'] === 'present' && hash_equals($step['sha256'], $after['sha256']);
        $backup = $state === 'applied' ?
            Quarantine::verificationBackup((int) ($step['quarantine_id'] ?? 0), $path, $step['sha256']) : null;
        $verified = $step['type'] === 'quarantine'
            ? $after['state'] === 'absent' && ($backup['state'] ?? null) === 'stored'
            : $after['state'] === 'present' && ($backup['state'] ?? null) === 'repaired' &&
                hash_equals($backup['replacement'], $after['sha256']);
        $status = match (true) {
            in_array($state, ['applying', 'undoing'], true) => 'in_progress',
            $after['state'] === 'unavailable' => 'unverified',
            $state === 'undone' && $prior => 'undone',
            $state === 'pending' && $prior => 'pending',
            $state === 'applied' && $verified => 'verified',
            $state === 'applied' && !$backup => 'backup_unverified',
            default => 'changed',
        };
        return self::step($step, $status, $after + ['backup_verified' => $backup !== null,
            'expected_replacement_sha256' => $backup['replacement'] ?? null]);
    }

    private static function cron(array $step, ?array $events): array
    {
        $timestamp = $step['timestamp'];
        $rescheduled = [];
        $current = null;
        $state = 'unavailable';
        if ($events !== null) {
            $current = $events[$timestamp][$step['target']][$step['event_key']] ?? null;
            foreach ($events as $time => $hooks) {
                if (is_int($time) && $time !== $timestamp && isset($hooks[$step['target']][$step['event_key']])) {
                    $rescheduled[] = $time;
                }
            }
            $state = match (true) {
                $current !== null => 'present',
                (bool) $rescheduled => 'rescheduled',
                default => 'absent',
            };
        }
        $hash = is_array($current) ? CronCleanup::eventHash($current) : null;
        $prior = $hash === $step['sha256'];
        $status = match (true) {
            in_array($step['state'], ['applying', 'undoing'], true) => 'in_progress',
            $state === 'unavailable' => 'unverified',
            $step['state'] === 'undone' && $prior => 'undone',
            $step['state'] === 'pending' && $prior => 'pending',
            $step['state'] === 'applied' && $state === 'absent' => 'verified',
            default => 'changed',
        };
        return self::step($step, $status, ['state' => $state, 'sha256' => $hash, 'rescheduled_at' => $rescheduled]);
    }

    private static function step(array $step, string $status, array $after): array
    {
        $before = ['state' => 'present', 'sha256' => $step['sha256']];
        if ($step['type'] === 'cron') {
            $before['scheduled_at'] = $step['timestamp'];
        }
        return ['type' => $step['type'], 'target' => $step['target'], 'plan_state' => $step['state'],
            'before' => $before, 'after' => $after, 'status' => $status];
    }

    private static function entryPoints(array $evidence): array
    {
        $points = $evidence['entry_hypotheses'] ?? [];
        $catalog = $evidence['vulnerabilities'] ?? [];
        $targets = [];
        foreach ($points as $index => &$point) {
            $point['after'] = ['status' => 'manual_review_required'];
            if ($point['vector'] !== 'suspected_vulnerable_component') {
                continue;
            }
            $matching = array_values(array_filter($catalog, static fn ($row) => $row['key'] === $point['component'] &&
                (!empty($point['cve']) ? $row['cve'] === $point['cve'] :
                    (empty($point['advisory']) || $row['id'] === $point['advisory']))));
            $old = count($matching) === 1 ? $matching[0] : null;
            $point['before'] = ['version' => $old['version'] ?? null, 'active' => $old['active'] ?? null];
            $point['advisory'] ??= $old['id'] ?? '';
            $targets[$index] = $point;
        }
        unset($point);
        if (!$targets) {
            return $points;
        }
        // A long-lived MCP process must see the current installed plugin headers.
        wp_cache_delete('plugins', 'plugins');
        $installed = Vulnerabilities::inventory();
        $header = @file_get_contents(ABSPATH . WPINC . '/version.php', false, null, 0, 32768);
        $installed['core:wordpress'][0] = is_string($header) &&
            preg_match('/^\s*\$wp_version\s*=\s*[\x27"]([A-Za-z0-9._+-]{1,90})[\x27"]/m', $header, $match) ? $match[1] : '';
        foreach (Vulnerabilities::assessments($targets, $installed) as $index => $after) {
            $matches = $after['matches'];
            $component = $targets[$index]['component'];
            $removed = $after['version'] === null && self::pluginAbsent($component);
            $after['status'] = match (true) {
                $removed => 'component_absent',
                !$matches => 'unverified',
                in_array(true, array_column($matches, 'affected'), true) => 'still_affected',
                default => 'outside_affected_range',
            };
            $points[$index]['after'] = $after;
        }
        return $points;
    }

    private static function pluginAbsent(string $component): bool
    {
        if (!preg_match('/^plugin:([a-zA-Z0-9][a-zA-Z0-9_-]{0,99})$/D', $component, $match) || !is_readable(WP_PLUGIN_DIR)) {
            return false;
        }
        $path = trailingslashit(WP_PLUGIN_DIR) . $match[1];
        return !file_exists($path) && !is_link($path) && !file_exists($path . '.php') && !is_link($path . '.php');
    }
}
