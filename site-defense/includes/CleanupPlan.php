<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class CleanupPlan
{
    public const PREFIX = 'sd_cleanup_plan_';

    private static function candidates(): array
    {
        $steps = [];
        foreach (get_option('sd_scan', [])['findings'] ?? [] as $finding) {
            [$reason, $path] = $finding;
            $digest = $finding[2] ?? '';
            if (!Investigation::path($path) || !is_string($digest) || !preg_match('/^[a-f0-9]{64}$/D', $digest)) {
                continue;
            }
            $repair = $reason === FileRepair::FINDING;
            if ($repair && !in_array(Quarantine::resolve($path)[1] ?? '', ['core', 'plugins'], true)) {
                continue;
            }
            if (!$repair && (!in_array($reason, Scanner::QUARANTINE_FINDINGS, true) || !Quarantine::canOffer($path))) {
                continue;
            }
            $id = Quarantine::selector($finding);
            $steps[$id] = ['type' => $repair ? 'repair' : 'quarantine', 'target' => $path,
                'sha256' => $digest, 'reason' => $reason];
        }
        $audit = DbAudit::report();
        return $steps + CronCleanup::targets($audit['findings'] ?? []) + ($audit['cleanup_content'] ?? []);
    }

    public static function targets(): array
    {
        return array_map([self::class, 'publicStep'], self::candidates());
    }

    private static function publicStep(array $step): array
    {
        unset($step['backup']);
        return $step;
    }

    public static function create(array $ids, string $accessLog = ''): array|\WP_Error
    {
        if (!$ids || count($ids) > 10 || !array_is_list($ids)) {
            return self::failure(__('Select between 1 and 10 cleanup targets from the investigation.', 'site-defense'));
        }
        $catalog = self::candidates();
        $steps = [];
        $paths = [];
        $databaseFields = [];
        $seen = [];
        foreach ($ids as $id) {
            if (!is_string($id) || !isset($catalog[$id]) || isset($seen[$id])) {
                return self::failure(__('A selected cleanup target is stale or unknown. Refresh the investigation.', 'site-defense'));
            }
            $seen[$id] = true;
            $step = $catalog[$id];
            if ($step['type'] === 'db_content') {
                $field = $step['target'];
                if (isset($databaseFields[$field])) {
                    $steps[$databaseFields[$field]]['fragments'][] = $step['fragments'][0];
                } else {
                    $databaseFields[$field] = $id;
                    $steps[$id] = $step + ['state' => 'pending'];
                }
                continue;
            }
            if ($step['type'] !== 'cron' && isset($paths[$step['target']])) {
                return self::failure(__('Select only one action per file.', 'site-defense'));
            }
            if ($step['type'] !== 'cron') {
                $paths[$step['target']] = true;
            }
            $steps[$id] = $step + ['state' => 'pending'];
        }
        foreach ($databaseFields as $id) {
            $prepared = DbContentCleanup::prepare($steps[$id]);
            if (is_wp_error($prepared)) {
                return $prepared;
            }
            $steps[$id] = $prepared;
        }
        $evidence = Investigation::report(24, 80, $accessLog);
        $plan = ['id' => bin2hex(random_bytes(16)), 'created' => time(), 'created_by' => get_current_user_id(),
            'evidence_sha256' => hash('sha256', (string) wp_json_encode($evidence)), 'evidence' => $evidence, 'steps' => $steps];
        if (!add_option(self::PREFIX . $plan['id'], $plan, '', false)) {
            return self::failure(__('Unable to save the cleanup plan.', 'site-defense'));
        }
        return self::visible($plan);
    }

    public static function show(string $id): ?array
    {
        $plan = self::read($id);
        return $plan ? self::visible($plan) : null;
    }

    public static function preview(string $id, string $stepId): array|\WP_Error
    {
        if (!current_user_can('manage_options')) {
            return self::failure(__('Permission denied.', 'site-defense'));
        }
        $step = self::read($id)['steps'][$stepId] ?? null;
        if (($step['type'] ?? null) !== 'db_content') {
            return self::failure(__('Database cleanup step not found.', 'site-defense'));
        }
        return DbContentCleanup::preview($step);
    }

    public static function verifyDatabaseStep(string $id, string $stepId): array|\WP_Error
    {
        $step = self::read($id)['steps'][$stepId] ?? null;
        if (($step['type'] ?? null) !== 'db_content') {
            return self::failure(__('Database cleanup step not found.', 'site-defense'));
        }
        return DbContentCleanup::verification($step);
    }

    private static function read(string $id): ?array
    {
        return preg_match('/^[a-f0-9]{32}$/D', $id) ? get_option(self::PREFIX . $id, null) : null;
    }

    private static function visible(array $plan): array
    {
        $plan['steps'] = array_map([self::class, 'publicStep'], $plan['steps']);
        return $plan;
    }

    public static function change(string $id, string $stepId, bool $undo, string $repairPreview = ''): array|\WP_Error
    {
        global $wpdb;
        $lock = 'sd-cleanup-' . md5($wpdb->options);
        if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $lock)) !== 1) {
            return self::failure(__('A cleanup operation is already running.', 'site-defense'));
        }
        try {
            wp_cache_delete(self::PREFIX . $id, 'options');
            $plan = self::read($id);
            if (!isset($plan['steps'][$stepId])) {
                return self::failure(__('Cleanup plan or step was not found.', 'site-defense'));
            }
            $step = $plan['steps'][$stepId];
            if ($step['type'] === 'db_content' && !current_user_can('manage_options')) {
                return self::failure(__('Permission denied.', 'site-defense'));
            }
            if ($step['state'] === ($undo ? 'undone' : 'applied')) {
                return self::publicStep($step);
            }
            if (!in_array($step['state'], $undo ? ['applied', 'undoing'] : ['pending', 'applying'], true)) {
                return self::failure(__('This cleanup step cannot be changed in its current state.', 'site-defense'));
            }
            $retry = in_array($step['state'], ['applying', 'undoing'], true);
            if (!$undo && !$retry && $step['type'] === 'cron' && !CronCleanup::present($step)) {
                return self::failure(__('The scheduled event changed. Refresh the investigation.', 'site-defense'));
            }
            if (!$retry && $step['type'] === 'db_content') {
                $preflight = DbContentCleanup::preflight($step, $undo);
                if (is_wp_error($preflight)) {
                    return $preflight;
                }
            }
            if ($step['type'] === 'repair' && !$undo && !($retry && Quarantine::recoveredRepairId($step['target'], $step['sha256']))) {
                $preview = FileRepair::plan($repairPreview, true);
                if (!$preview || $preview['path'] !== $step['target'] || $preview['original_sha256'] !== $step['sha256']) {
                    return self::failure(__('Prepare a matching official file repair preview first.', 'site-defense'));
                }
            }
            $step['state'] = $undo ? 'undoing' : 'applying';
            if (!$retry && !self::saveStep($plan, $stepId, $step)) {
                return self::failure(__('Unable to save the cleanup plan.', 'site-defense'));
            }
            $result = self::execute($step, $undo, $retry, $repairPreview);
            if (is_wp_error($result)) {
                return $result;
            }
            if (!$undo && $result) {
                $step['quarantine_id'] = $result;
            }
            $step['state'] = $undo ? 'undone' : 'applied';
            $step[$undo ? 'undone_at' : 'applied_at'] = time();
            if (!self::saveStep($plan, $stepId, $step)) {
                return self::failure(__('The target changed. Retry the same step to update the cleanup history.', 'site-defense'));
            }
            State::log($undo ? 'cleanup_undone' : 'cleanup_applied', $step['target'], context: ['path' => $step['target']]);
            return self::publicStep($step);
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }

    private static function execute(array $step, bool $undo, bool $retry, string $repairPreview): int|\WP_Error
    {
        if ($step['type'] === 'db_content') {
            return DbContentCleanup::change($step, $undo, $retry);
        }
        if ($step['type'] === 'cron') {
            return CronCleanup::change($step, $undo, $retry) ? 0 :
                self::failure(__('The scheduled event changed or the schedule could not be saved. Inspect the current schedule.', 'site-defense'));
        }
        if ($step['type'] === 'repair') {
            if ($undo) {
                $result = FileRepair::undo($step['quarantine_id']);
            } else {
                $id = $retry ? Quarantine::recoveredRepairId($step['target'], $step['sha256']) : 0;
                $result = $id ? ['quarantine_id' => $id] : FileRepair::apply($repairPreview, true);
            }
            return is_wp_error($result) ? $result : $result['quarantine_id'];
        }
        if (!$undo) {
            $result = Quarantine::cleanupMove([$step['reason'], $step['target'], $step['sha256']], $retry);
            return is_wp_error($result) ? $result : (int) $result['id'];
        }
        $file = Quarantine::resolve($step['target'])[0] ?? '';
        if ($retry && $file !== '' && !Scanner::linked($file) && is_file($file) && @hash_file('sha256', $file) === $step['sha256']) {
            return 0;
        }
        $message = Quarantine::restore($step['quarantine_id']);
        return $message === __('File restored to its original location.', 'site-defense') ? 0 : self::failure($message);
    }

    private static function saveStep(array &$plan, string $id, array $step): bool
    {
        $plan['steps'][$id] = $step;
        return update_option(self::PREFIX . $plan['id'], $plan, false);
    }

    private static function failure(string $message): \WP_Error
    {
        return new \WP_Error('sd_cleanup', $message);
    }
}
