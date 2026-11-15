<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class DbContentCleanup
{
    private const POST_TYPES = ['post', 'page', 'product'];
    private const COMMENT_PARENTS = ['post', 'page'];
    public const AUDIT_LIMIT = 200;

    public static function auditTargets(string $source, array $row): array
    {
        $type = $row['location'];
        if ($source === 'posts' && in_array($type, self::POST_TYPES, true)) {
            $fields = ['post_content' => $row['value'], 'post_excerpt' => $row['excerpt']];
            $identity = ['record_type' => $type];
        } elseif ($source === 'comments' && in_array($type, ['', 'comment'], true) &&
            in_array($row['parent_type'], self::COMMENT_PARENTS, true)) {
            $fields = ['comment_content' => $row['value']];
            $identity = ['record_type' => $type, 'parent_id' => (int) $row['object_id'], 'parent_type' => $row['parent_type']];
        } else {
            return [];
        }
        $id = (int) $row['id'];
        $targets = [];
        foreach ($fields as $field => $value) {
            $fragments = StoredHtml::fragments($value);
            if (!$fragments) {
                continue;
            }
            $target = ['type' => 'db_content', 'target' => "$source/$id/$field", 'source' => $source, 'record_id' => $id,
                'field' => $field, 'sha256' => hash('sha256', $value), 'before_bytes' => strlen($value)] + $identity;
            foreach ($fragments as $fragment) {
                $selector = hash('sha256', serialize([$target, $fragment]));
                $targets[$selector] = $target + ['fragments' => [$fragment]];
            }
        }
        return $targets;
    }

    public static function prepare(array $step): array|\WP_Error
    {
        $before = self::read($step);
        if ($before === null || hash('sha256', $before) !== $step['sha256']) {
            return self::changed();
        }
        $known = array_column(StoredHtml::fragments($before), null, 'offset');
        usort($step['fragments'], static fn ($a, $b) => $a['offset'] <=> $b['offset']);
        foreach ($step['fragments'] as $fragment) {
            if (($known[$fragment['offset']] ?? null) !== $fragment) {
                return self::changed();
            }
        }
        $after = StoredHtml::remove($before, $step['fragments']);
        if ($after === null) {
            return self::changed();
        }
        return $step + ['after_sha256' => hash('sha256', $after), 'after_bytes' => strlen($after), 'backup' => base64_encode($before)];
    }

    public static function preview(array $step): array|\WP_Error
    {
        if (!($values = self::backup($step))) {
            return self::invalidBackup();
        }
        [$before] = $values;
        $result = self::verification($step);
        $result['fragments'] = [];
        foreach ($step['fragments'] as $fragment) {
            $snippet = substr($before, $fragment['offset'], min(240, $fragment['bytes']));
            // Preserve visible code while removing terminal controls and encoding markup as text.
            $snippet = htmlspecialchars($snippet, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $snippet = preg_replace('/\p{C}/u', ' ', $snippet) ?? '';
            $result['fragments'][] = $fragment + ['snippet' => $snippet,
                'truncated' => $fragment['bytes'] > 240];
        }
        return $result;
    }

    public static function preflight(array $step, bool $undo): true|\WP_Error
    {
        if (self::backup($step) === null) {
            return self::invalidBackup();
        }
        $current = self::read($step);
        return $current !== null && hash('sha256', $current) === $step[$undo ? 'after_sha256' : 'sha256'] ? true : self::changed();
    }

    public static function change(array $step, bool $undo, bool $retry): int|\WP_Error
    {
        global $wpdb;
        if (!($values = self::backup($step))) {
            return self::invalidBackup();
        }
        $query = self::target($step);
        if (!$query) {
            return self::changed();
        }
        [$before, $after] = $values;
        [$from, $to] = $undo ? [$after, $before] : [$before, $after];
        [$table, $field, $where, $keys] = $query;
        $changed = $wpdb->query($wpdb->prepare("UPDATE $table SET $field=%s WHERE $where AND BINARY $field=%s", [$to, ...$keys, $from]));
        if ($changed !== 1 && !($changed === 0 && $retry && self::read($step) === $to)) {
            return self::changed();
        }
        if ($step['source'] === 'posts') {
            clean_post_cache($step['record_id']);
        } else {
            clean_comment_cache($step['record_id']);
        }
        return 0;
    }

    public static function verification(array $step): array
    {
        $current = self::read($step);
        $hash = $current === null ? null : hash('sha256', $current);
        $backup = self::backup($step) !== null;
        $state = match ($hash) {
            null => 'unavailable',
            $step['sha256'] => 'original',
            $step['after_sha256'] => 'cleaned',
            default => 'changed',
        };
        $status = match (true) {
            $state === 'unavailable' => 'unverified',
            !$backup => 'backup_unverified',
            $state === 'changed' => 'changed',
            in_array($step['state'], ['applying', 'undoing'], true) => 'in_progress',
            $step['state'] === 'applied' && $state === 'cleaned' => 'verified',
            $step['state'] === 'undone' && $state === 'original' => 'undone',
            $step['state'] === 'pending' && $state === 'original' => 'pending',
            default => 'changed',
        };
        return ['type' => $step['type'], 'target' => $step['target'], 'plan_state' => $step['state'], 'status' => $status,
            'before' => ['state' => 'original', 'sha256' => $step['sha256'], 'bytes' => $step['before_bytes']],
            'expected_after' => ['sha256' => $step['after_sha256'], 'bytes' => $step['after_bytes']],
            'after' => ['state' => $state, 'sha256' => $hash, 'bytes' => $current === null ? null : strlen($current),
                'backup_verified' => $backup]];
    }

    private static function backup(array $step): ?array
    {
        $encoded = $step['backup'] ?? '';
        if (!is_string($encoded) || strlen($encoded) > 4 * (int) ceil(StoredHtml::MAX_BYTES / 3)) {
            return null;
        }
        $original = base64_decode($encoded, true);
        if ($original === false || hash('sha256', $original) !== $step['sha256']) {
            return null;
        }
        $replacement = StoredHtml::remove($original, $step['fragments']);
        return $replacement !== null && hash('sha256', $replacement) === $step['after_sha256'] ? [$original, $replacement] : null;
    }

    private static function read(array $step): ?string
    {
        global $wpdb;
        $query = self::target($step);
        if (!$query) {
            return null;
        }
        [$table, $field, $where, $keys] = $query;
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT CASE WHEN OCTET_LENGTH($field)<=%d THEN $field END AS value FROM $table WHERE $where",
            [StoredHtml::MAX_BYTES, ...$keys]
        ), ARRAY_A);
        return $row['value'] ?? null;
    }

    private static function target(array $step): ?array
    {
        global $wpdb;
        $id = $step['record_id'];
        if (!is_int($id) || $id < 1) {
            return null;
        }
        $type = $step['record_type'];
        if ($step['source'] === 'posts' && in_array($type, self::POST_TYPES, true) &&
            in_array($step['field'], ['post_content', 'post_excerpt'], true)) {
            return [$wpdb->posts, $step['field'], 'ID=%d AND BINARY post_type=%s', [$id, $type]];
        }
        if ($step['source'] === 'comments' && in_array($type, ['', 'comment'], true) && $step['field'] === 'comment_content' &&
            in_array($step['parent_type'] ?? null, self::COMMENT_PARENTS, true)) {
            return ["$wpdb->comments c INNER JOIN $wpdb->posts p ON p.ID=c.comment_post_ID", 'c.comment_content',
                'c.comment_ID=%d AND BINARY c.comment_type=%s AND c.comment_post_ID=%d AND BINARY p.post_type=%s',
                [$id, $type, $step['parent_id'], $step['parent_type']]];
        }
        return null;
    }

    private static function changed(): \WP_Error
    {
        return new \WP_Error('sd_cleanup_content_changed', __('The database field changed or is unavailable. Refresh the database audit before continuing.', 'site-defense'));
    }

    private static function invalidBackup(): \WP_Error
    {
        return new \WP_Error('sd_cleanup_content_backup', __('The database cleanup backup could not be verified.', 'site-defense'));
    }
}
