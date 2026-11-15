<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class CronCleanup
{
    public static function snapshot(): ?array
    {
        global $wpdb;
        $raw = $wpdb->get_var($wpdb->prepare("SELECT option_value FROM $wpdb->options WHERE option_name=%s", 'cron'));
        if (!is_string($raw) || strlen($raw) > 4 * 1024 * 1024) {
            return null;
        }
        $events = @unserialize($raw, ['allowed_classes' => false, 'max_depth' => 48]);
        return is_array($events) && serialize($events) === $raw ? [$raw, $events] : null;
    }

    public static function eventHash(array $event): string
    {
        return hash('sha256', serialize($event));
    }

    public static function allowed(string $hook): bool
    {
        return (bool) preg_match('/^[a-zA-Z0-9_.:-]{1,130}$/D', $hook) &&
            !preg_match('/^(?:woocommerce_|wc_|action_scheduler_|sd_)/i', $hook);
    }

    public static function targets(array $findings): array
    {
        $snapshot = self::snapshot();
        if (!$snapshot) {
            return [];
        }
        [, $events] = $snapshot;
        $targets = [];
        foreach ($findings as $row) {
            $key = $row['event_key'] ?? '';
            if ($row['type'] !== 'cron_payload' || !preg_match('/^[a-f0-9]{32}$/D', $key) || !self::allowed($row['location'])) {
                continue;
            }
            $event = $events[$row['id']][$row['location']][$key] ?? null;
            if (is_array($event) && self::eventHash($event) === ($row['event_sha256'] ?? '') && self::safeEvent($event)) {
                $id = hash('sha256', serialize([$row['id'], $row['location'], $key, $row['event_sha256']]));
                $targets[$id] = ['type' => 'cron', 'target' => $row['location'], 'timestamp' => $row['id'],
                    'event_key' => $key, 'sha256' => $row['event_sha256'], 'backup' => base64_encode(serialize($event))];
            }
        }
        return $targets;
    }

    public static function present(array $step): bool
    {
        $snapshot = self::snapshot();
        $event = $snapshot[1][$step['timestamp']][$step['target']][$step['event_key']] ?? null;
        return is_array($event) && self::eventHash($event) === $step['sha256'];
    }

    private static function safeEvent(array $event): bool
    {
        $serialized = serialize($event);
        // Keep the recovery record limited to ordinary arrays and scalars.
        return strlen($serialized) <= 65536 &&
            !preg_match('/(?:^|[;{])(?:O|C|E|R|r):\d+:/', $serialized);
    }

    public static function change(array $step, bool $undo, bool $retry = false): bool
    {
        global $wpdb;
        $snapshot = self::snapshot();
        if (!$snapshot || !self::allowed($step['target'])) {
            return false;
        }
        [$raw, $events] = $snapshot;
        [$time, $hook, $key] = [$step['timestamp'], $step['target'], $step['event_key']];
        $existing = $events[$time][$hook][$key] ?? null;
        if ($undo) {
            if ($existing !== null) {
                return is_array($existing) && self::eventHash($existing) === $step['sha256'];
            }
            $backup = base64_decode($step['backup'], true);
            $event = is_string($backup) ? @unserialize($backup, ['allowed_classes' => false, 'max_depth' => 48]) : null;
            if (!is_array($event) || !self::safeEvent($event) || self::eventHash($event) !== $step['sha256']) {
                return false;
            }
            $events[$time][$hook][$key] = $event;
            ksort($events, SORT_NATURAL);
        } else {
            if ($existing === null) {
                return $retry;
            }
            if (!is_array($existing) || self::eventHash($existing) !== $step['sha256']) {
                return false;
            }
            unset($events[$time][$hook][$key]);
            if (!$events[$time][$hook]) {
                unset($events[$time][$hook]);
            }
            if (!$events[$time]) {
                unset($events[$time]);
            }
        }
        $changed = $wpdb->query($wpdb->prepare(
            "UPDATE $wpdb->options SET option_value=%s WHERE option_name=%s AND BINARY option_value=%s",
            serialize($events), 'cron', $raw
        )) === 1;
        if ($changed) {
            wp_cache_delete('cron', 'options');
            wp_cache_delete('alloptions', 'options');
        }
        return $changed;
    }
}
