<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class DbAudit
{
    private const BATCH = 20;
    private const MAX_VALUE = 262144;
    private const MAX_CRON = 2097152;
    private const MAX_FINDINGS = 500;
    private const PHASES = ['users', 'cron', 'options', 'posts', 'postmeta', 'comments'];
    public const PAGE_SIZE = 25;

    public static function register(): void
    {
        add_action('sd_db_audit_slice', [self::class, 'slice']);
    }

    public static function locked(callable $operation): string
    {
        global $wpdb;
        $lock = 'sd-db-audit-' . md5($wpdb->options);
        if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $lock)) !== 1) {
            return __('A database audit operation is already running.', 'site-defense');
        }
        try {
            return $operation();
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }

    public static function start(): string
    {
        return self::locked(static function (): string {
            if ((self::report()['status'] ?? '') !== 'running') {
                $report = [
                    'status' => 'running', 'started' => time(), 'finished' => 0, 'phase' => 0, 'cursor' => 0,
                    'checked' => [], 'skipped' => [], 'counts' => [], 'findings' => [], 'cleanup_content' => [],
                ];
                if (!update_option('sd_db_audit', $report, false)) {
                    return __('Unable to save the database audit.', 'site-defense');
                }
            }
            self::schedule();
            return __('Database audit queued.', 'site-defense');
        });
    }

    private static function schedule(): void
    {
        if (!wp_next_scheduled('sd_db_audit_slice')) {
            wp_schedule_single_event(time() + 5, 'sd_db_audit_slice');
        }
    }

    public static function report(): array
    {
        return (array) get_option('sd_db_audit', []);
    }

    public static function trusted(): array
    {
        return (array) get_option('sd_db_audit_trusted', []);
    }

    public static function trust(int $userId, string $fingerprint): string
    {
        return self::locked(static function () use ($userId, $fingerprint): string {
            global $wpdb;
            $sql = $wpdb->prepare(
                "SELECT u.ID AS user_id, u.user_login, u.user_registered, CASE WHEN OCTET_LENGTH(m.meta_value) <= %d THEN m.meta_value END AS value
                 FROM $wpdb->usermeta m INNER JOIN $wpdb->users u ON m.user_id=u.ID
                 WHERE m.user_id=%d AND m.meta_key=%s ORDER BY m.umeta_id LIMIT 2",
                self::MAX_VALUE, $userId, $wpdb->prefix . 'capabilities'
            );
            $rows = $wpdb->get_results($sql, ARRAY_A);
            $account = count($rows ?? []) === 1 ? self::account($rows[0]) : null;
            if (!$account || !$account['privileged'] || !hash_equals($account['fingerprint'], $fingerprint)) {
                return __('The account or its privileges changed. Run the database audit again.', 'site-defense');
            }
            $before = self::trusted();
            $after = $before;
            $after[$userId] = ['fingerprint' => $fingerprint, 'login' => $account['login']];
            if ($before !== $after && !update_option('sd_db_audit_trusted', $after, false)) {
                return __('Unable to save trusted accounts.', 'site-defense');
            }
            if ($before !== $after) {
                State::log('protection_changed', 'Database audit trusted user #' . $userId, context: ['user_id' => $userId]);
            }
            return __('Account privileges confirmed.', 'site-defense');
        });
    }

    public static function untrust(int $userId): string
    {
        return self::locked(static function () use ($userId): string {
            $trusted = self::trusted();
            if (!isset($trusted[$userId])) {
                return __('Trusted account not found.', 'site-defense');
            }
            unset($trusted[$userId]);
            if (!update_option('sd_db_audit_trusted', $trusted, false)) {
                return __('Unable to save trusted accounts.', 'site-defense');
            }
            State::log('protection_changed', 'Database audit removed trust for user #' . $userId, context: ['user_id' => $userId]);
            return __('Account confirmation removed.', 'site-defense');
        });
    }

    public static function slice(): void
    {
        self::locked(static function (): string {
            $report = self::report();
            if (($report['status'] ?? '') !== 'running') {
                return '';
            }
            self::schedule();
            $deadline = microtime(true) + 2;
            for ($batch = 0; $batch < 5 && microtime(true) < $deadline; $batch++) {
                $phase = self::PHASES[$report['phase']] ?? null;
                if ($phase === null) {
                    $report['status'] = 'complete';
                    $report['finished'] = time();
                    break;
                }
                if ($phase === 'cron') {
                    $done = self::cron($report);
                } else {
                    $done = self::rows($report, $phase);
                }
                if ($done === null) {
                    $report['status'] = 'failed';
                    $report['finished'] = time();
                    break;
                }
                if ($done) {
                    $report['phase']++;
                    $report['cursor'] = 0;
                }
            }
            if (update_option('sd_db_audit', $report, false) && $report['status'] !== 'running') {
                wp_clear_scheduled_hook('sd_db_audit_slice');
            }
            return '';
        });
    }

    private static function rows(array &$report, string $phase): ?bool
    {
        global $wpdb;
        $orderTypes = "'shop_order','shop_order_refund','shop_order_placehold','shop_subscription'";
        $sql = match ($phase) {
            'users' => "SELECT m.umeta_id AS id, u.ID AS user_id, u.user_login, u.user_registered,
                        CASE WHEN OCTET_LENGTH(m.meta_value) <= %d THEN m.meta_value END AS value
                        FROM $wpdb->usermeta m INNER JOIN $wpdb->users u ON m.user_id=u.ID
                        WHERE m.umeta_id>%d AND m.meta_key=%s ORDER BY m.umeta_id LIMIT %d",
            'options' => "SELECT option_id AS id, option_name AS location,
                          CASE WHEN OCTET_LENGTH(option_value) <= %d THEN option_value END AS value
                          FROM $wpdb->options WHERE option_id>%d AND option_name<>'cron'
                          AND option_name NOT LIKE %s AND option_name NOT LIKE %s AND option_name NOT LIKE %s ORDER BY option_id LIMIT %d",
            'posts' => "SELECT ID AS id, post_type AS location,
                        CASE WHEN OCTET_LENGTH(post_content)+OCTET_LENGTH(post_excerpt) <= %d
                             THEN post_content END AS value,
                        CASE WHEN OCTET_LENGTH(post_content)+OCTET_LENGTH(post_excerpt) <= %d
                             THEN post_excerpt END AS excerpt
                        FROM $wpdb->posts WHERE ID>%d AND post_type NOT IN ($orderTypes) ORDER BY ID LIMIT %d",
            'postmeta' => "SELECT m.meta_id AS id, m.post_id AS object_id, m.meta_key AS location,
                           CASE WHEN OCTET_LENGTH(m.meta_value) <= %d THEN m.meta_value END AS value
                           FROM $wpdb->postmeta m INNER JOIN $wpdb->posts p ON p.ID=m.post_id
                           WHERE m.meta_id>%d AND p.post_type NOT IN ($orderTypes) ORDER BY m.meta_id LIMIT %d",
            'comments' => "SELECT c.comment_ID AS id, c.comment_type AS location, c.comment_post_ID AS object_id, p.post_type AS parent_type,
                           CASE WHEN OCTET_LENGTH(c.comment_content) <= %d THEN c.comment_content END AS value
                           FROM $wpdb->comments c LEFT JOIN $wpdb->posts p ON p.ID=c.comment_post_ID
                           WHERE c.comment_ID>%d AND c.comment_type<>'order_note' ORDER BY c.comment_ID LIMIT %d",
        };
        $params = $phase === 'posts' ? [self::MAX_VALUE, self::MAX_VALUE, $report['cursor']] : [self::MAX_VALUE, $report['cursor']];
        if ($phase === 'users') {
            $params[] = $wpdb->prefix . 'capabilities';
        } elseif ($phase === 'options') {
            $params = array_merge($params, array_map(static fn ($prefix) => $wpdb->esc_like($prefix) . '%', ['sd_', '_transient_', '_site_transient_']));
        }
        $params[] = self::BATCH;
        $rows = $wpdb->get_results($wpdb->prepare($sql, $params), ARRAY_A);
        if ($wpdb->last_error !== '' || !is_array($rows)) {
            return null;
        }
        foreach ($rows as $row) {
            $report['cursor'] = (int) $row['id'];
            if ($row['value'] === null) {
                self::increment($report['skipped'], $phase);
                continue;
            }
            self::increment($report['checked'], $phase);
            if ($phase === 'users') {
                self::inspectUser($report, $row);
            } else {
                $signals = self::signals($row['value'] . (isset($row['excerpt']) ? "\n" . $row['excerpt'] : ''));
                $signals = self::recordCleanupTargets($report, $phase, $row, $signals);
                foreach ($signals as $signal) {
                    self::finding($report, $signal, $phase, (int) $row['id'], $row['location'], (int) ($row['object_id'] ?? 0));
                }
            }
        }
        return count($rows) < self::BATCH;
    }

    private static function recordCleanupTargets(array &$report, string $source, array $row, array $signals): array
    {
        $available = DbContentCleanup::AUDIT_LIMIT - count($report['cleanup_content'] ?? []);
        if ($available < 1 || !preg_match('~<(?:script|meta)\b~i', $row['value'] . "\n" . ($row['excerpt'] ?? ''))) {
            return $signals;
        }
        $targets = DbContentCleanup::auditTargets($source, $row);
        foreach (array_slice($targets, 0, $available, true) as $id => $target) {
            $report['cleanup_content'][$id] = $target;
            $signal = $target['fragments'][0]['kind'] === 'meta_refresh' ? 'stored_redirect' : 'stored_script';
            if (!in_array($signal, $signals, true)) {
                $signals[] = $signal;
            }
        }
        return $signals;
    }

    private static function account(array $row): ?array
    {
        $caps = self::decode($row['value']);
        if (!is_array($caps)) {
            return null;
        }
        $roleCaps = [];
        $roles = wp_roles()->roles;
        foreach ($caps as $name => $value) {
            if (!is_string($name) || !is_scalar($value)) {
                return null;
            }
            if (isset($roles[$name])) {
                $roleCaps = array_merge($roleCaps, $roles[$name]['capabilities']);
            }
        }
        $effective = array_filter(array_merge($roleCaps, $caps));
        $privileged = count(array_intersect(array_keys($effective), Hardening::PRIVILEGED_CAPS)) > 0 ||
            !empty($caps['administrator']);
        ksort($effective);
        return [
            'privileged' => $privileged,
            'login' => self::label($row['user_login']),
            'fingerprint' => hash('sha256', serialize([$row['user_login'], $row['user_registered'], array_keys($effective)])),
            'roles' => array_map([self::class, 'label'], array_keys(array_intersect_key($caps, $roles))),
        ];
    }

    private static function inspectUser(array &$report, array $row): void
    {
        $userId = (int) $row['user_id'];
        $account = self::account($row);
        if ($account === null) {
            self::finding($report, 'invalid_capabilities', 'users', $userId, $row['user_login']);
            return;
        }
        if (!$account['privileged']) {
            return;
        }
        $trusted = self::trusted()[$userId]['fingerprint'] ?? null;
        if ($trusted !== $account['fingerprint']) {
            self::finding($report, $trusted === null ? 'unconfirmed_privileges' : 'changed_privileges',
                'users', $userId, $account['login'], 0, ['fingerprint' => $account['fingerprint'], 'roles' => $account['roles']]);
        }
    }

    private static function cron(array &$report): ?bool
    {
        global $wpdb;
        // Read raw storage so a serialized object cannot run a wake-up callback during the audit.
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT CASE WHEN OCTET_LENGTH(option_value)<=%d THEN option_value END AS value
             FROM $wpdb->options WHERE option_name=%s",
            self::MAX_CRON, 'cron'
        ), ARRAY_A);
        if ($wpdb->last_error !== '') {
            return null;
        }
        if ($row === null || $row['value'] === null) {
            if ($row !== null) {
                self::increment($report['skipped'], 'cron');
            }
            return true;
        }
        $events = self::decode($row['value']);
        if ($events === null) {
            self::finding($report, 'invalid_cron', 'cron', 0, 'cron');
            return true;
        }
        $index = 0;
        $processed = 0;
        foreach (self::cronEntries($events) as [$timestamp, $hook, $event]) {
            if (++$index <= $report['cursor']) {
                continue;
            }
            $report['cursor'] = $index;
            self::inspectCronEvent($report, $timestamp, $hook, $event);
            if (++$processed >= 100) {
                return false;
            }
        }
        return true;
    }

    private static function cronEntries(array $events): \Generator
    {
        unset($events['version']);
        foreach ($events as $timestamp => $hooks) {
            if (!is_int($timestamp) || $timestamp < 1 || !is_array($hooks)) {
                yield [0, 'cron', null];
                continue;
            }
            foreach ($hooks as $hook => $instances) {
                if (!is_string($hook) || !is_array($instances)) {
                    yield [$timestamp, 'cron', null];
                    continue;
                }
                foreach ($instances as $event) {
                    yield [$timestamp, $hook, $event];
                }
            }
        }
    }

    private static function inspectCronEvent(array &$report, int $timestamp, string $hook, $event): void
    {
        self::increment($report['checked'], 'cron');
        if (!is_array($event) || !array_key_exists('schedule', $event) ||
            ($event['schedule'] !== false && !is_string($event['schedule'])) || !is_array($event['args'] ?? null)) {
            self::finding($report, 'invalid_cron', 'cron', $timestamp, $hook);
            return;
        }
        $arguments = serialize($event['args']);
        if (strlen($arguments) > self::MAX_VALUE) {
            self::increment($report['skipped'], 'cron');
        } elseif (self::signals($arguments)) {
            self::finding($report, 'cron_payload', 'cron', $timestamp, $hook, extra: [
                'event_key' => md5($arguments), 'event_sha256' => CronCleanup::eventHash($event),
            ]);
        } elseif (!has_action($hook)) {
            self::finding($report, 'cron_no_callback', 'cron', $timestamp, $hook);
        }
    }

    private static function decode(?string $raw): ?array
    {
        if ($raw === null || !str_starts_with($raw, 'a:')) {
            return null;
        }
        $data = @unserialize($raw, ['allowed_classes' => false, 'max_depth' => 48]);
        return is_array($data) ? $data : null;
    }

    public static function signals(string $value): array
    {
        $signals = [];
        if ($value === '' || strpbrk($value, '<:=(') === false) {
            return $signals;
        }
        $value = str_replace('\"', '"', $value);
        if (preg_match_all('~<script\b([^>]{0,1024})>~i', $value, $tags, PREG_SET_ORDER)) {
            foreach ($tags as $tag) {
                $attributes = $tag[1];
                if (!preg_match('~(?:^|\s)type\s*=\s*["\x27]?(?:application/(?:ld\+json|json)|importmap|speculationrules)(?:["\x27\s]|$)~i', $attributes) ||
                    preg_match('~(?:^|\s)src\s*=~i', $attributes)) {
                    $signals[] = 'stored_script';
                    break;
                }
            }
        }
        if (preg_match('~<\?(?:php\s|=)|\b(?:href|src)\s*=\s*["\x27]?\s*javascript\s*:|\b(?:eval|Function)\s*\(\s*(?:atob|unescape)\s*\(~i', $value)) {
            $signals[] = 'stored_code';
        }
        $meta = preg_match('~<meta\b[^>]{0,1024}\bhttp-equiv\s*=\s*["\x27]?\s*refresh\b[^>]{0,1024}\burl\s*=|<meta\b[^>]{0,1024}\burl\s*=[^>]{0,1024}\bhttp-equiv\s*=\s*["\x27]?\s*refresh\b~i', $value);
        $javascript = preg_match('~\b(?:(?:window|document|top|self)\s*\.\s*location(?:\s*\.\s*href)?|location\s*\.\s*href)\s*=(?!=)|\blocation\s*\.\s*(?:replace|assign)\s*\(~i', $value);
        if ($meta || $javascript || (in_array('stored_script', $signals, true) &&
            preg_match('~\blocation\s*=(?!=)~i', $value))) {
            $signals[] = 'stored_redirect';
        }
        return $signals;
    }

    private static function finding(array &$report, string $type, string $source, int $id, string $location, int $objectId = 0, array $extra = []): void
    {
        self::increment($report['counts'], $type);
        if (count($report['findings']) < self::MAX_FINDINGS) {
            $report['findings'][] = $extra + [
                'type' => $type, 'source' => $source, 'id' => $id, 'location' => self::label($location), 'object_id' => $objectId,
            ];
        }
    }

    private static function increment(array &$counts, string $key): void
    {
        $counts[$key] = ($counts[$key] ?? 0) + 1;
    }

    private static function label(string $value): string
    {
        return preg_replace('/[\p{C}]+/u', '', wp_check_invalid_utf8(substr($value, 0, 180))) ?? '';
    }

    public static function findingLabel(string $type): string
    {
        return match ($type) {
            'unconfirmed_privileges' => __('Unconfirmed privileged account', 'site-defense'),
            'changed_privileges' => __('Privileges changed since confirmation', 'site-defense'),
            'invalid_capabilities' => __('Malformed account privileges', 'site-defense'),
            'cron_no_callback' => __('WP-Cron hook has no callback in this run', 'site-defense'),
            'cron_payload' => __('WP-Cron arguments contain script or redirect markers', 'site-defense'),
            'invalid_cron' => __('Malformed WP-Cron entry', 'site-defense'),
            'stored_script' => __('Executable script tag', 'site-defense'),
            'stored_code' => __('Executable code marker', 'site-defense'),
            'stored_redirect' => __('Automatic redirect marker', 'site-defense'),
            default => $type,
        };
    }
}
