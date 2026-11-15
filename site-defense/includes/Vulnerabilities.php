<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class Vulnerabilities
{
    private const MAX_PACKET = 70 * 1024 * 1024;

    public static function register(): void
    {
        add_action('sd_daily', [self::class, 'daily']);
        add_action('sd_check_versions', static fn () => self::check(true));
        foreach (['upgrader_process_complete', 'activated_plugin', 'deactivated_plugin', 'deleted_plugin', 'switch_theme', 'deleted_theme'] as $hook) {
            add_action($hook, [self::class, 'schedule']);
        }
        if (State::enabled('observe')) {
            add_action('parse_request', [self::class, 'filterRequest'], -1000);
        }
    }

    public static function schedule(): void
    {
        if (!wp_next_scheduled('sd_check_versions')) {
            wp_schedule_single_event(time() + 20, 'sd_check_versions');
        }
    }

    private static function config(): array
    {
        static $config;
        if (isset($config)) {
            return $config;
        }
        $path = SITE_DEFENSE_DIR . '/data/update.json';
        $payload = is_readable($path) ? json_decode(file_get_contents($path), true) : [];
        $config = is_array($payload) ? $payload : [];
        return $config;
    }

    private static function database(): string
    {
        $stored = get_option('sd_vulnerability_db', []);
        if (is_array($stored) && !empty($stored['version']) && !empty($stored['compressed']) &&
            $stored['version'] >= (int) (self::config()['seed_version'] ?? 0)) {
            $decoded = gzdecode(base64_decode($stored['compressed']), self::MAX_PACKET);
            if (is_string($decoded)) {
                return $decoded;
            }
        }
        $path = SITE_DEFENSE_DIR . '/data/vulnerabilities.json.gz';
        if (is_readable($path)) {
            $bytes = file_get_contents($path);
            $decoded = is_string($bytes) ? gzdecode($bytes, self::MAX_PACKET) : false;
            if (is_string($decoded)) {
                return $decoded;
            }
        }
        return '';
    }

    private static function lines(string $database): \Generator
    {
        $offset = 0;
        while (($newline = strpos($database, "\n", $offset)) !== false) {
            yield json_decode(substr($database, $offset, $newline - $offset), true);
            $offset = $newline + 1;
        }
    }

    public static function daily(): void
    {
        if (State::enabled('feed_auto')) {
            self::refresh();
        }
        if (State::enabled('kev_auto')) {
            Kev::refresh();
        }
        self::check(true);
    }

    private static function status(string $message, bool $success = false): string
    {
        $status = (array) get_option('sd_feed_status', []);
        $status['message'] = $message;
        $status['attempt'] = time();
        if ($success) {
            $status['success'] = time();
        }
        update_option('sd_feed_status', $status, false);
        return translate($message, 'site-defense');
    }

    public static function refresh(): string
    {
        $url = self::updateEndpoint();
        if ($url === '') {
            return self::status('The update endpoint has not been configured in this build.');
        }
        $response = wp_safe_remote_get($url . '/latest.json', [
            'timeout' => 10, 'redirection' => 0, 'limit_response_size' => 1024,
            'user-agent' => 'Site Defense vulnerability database', 'headers' => ['Accept' => 'application/json'],
        ]);
        if (wp_remote_retrieve_response_code($response) !== 200) {
            return self::status('Unable to reach the database publisher.');
        }
        $manifest = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($manifest) || !isset($manifest['version']) || !is_int($manifest['version']) || $manifest['version'] < 1) {
            return self::status('Invalid update manifest.');
        }
        $installed = self::version();
        if ($manifest['version'] < $installed) {
            return self::status('The publisher returned an older database.');
        }
        if ($manifest['version'] === $installed) {
            return self::status('Vulnerability database is current.', true);
        }
        $response = wp_safe_remote_get($url . '/database-' . $manifest['version'] . '.pack', [
            'timeout' => 25, 'redirection' => 0, 'limit_response_size' => self::MAX_PACKET + 1,
            'user-agent' => 'Site Defense vulnerability database',
        ]);
        if (wp_remote_retrieve_response_code($response) !== 200) {
            return self::status('Unable to download the database package.');
        }
        return self::import(wp_remote_retrieve_body($response), $manifest['version']);
    }

    public static function version(): int
    {
        $stored = get_option('sd_vulnerability_db', []);
        return max((int) ($stored['version'] ?? 0), (int) (self::config()['seed_version'] ?? 0));
    }

    public static function hasUpdateEndpoint(): bool
    {
        return self::updateEndpoint() !== '';
    }

    private static function updateEndpoint(): string
    {
        $url = defined('SITE_DEFENSE_FEED_URL') ? SITE_DEFENSE_FEED_URL : (self::config()['url'] ?? '');
        $parts = is_string($url) ? wp_parse_url($url) : false;
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            return '';
        }
        return rtrim($url, '/');
    }

    public static function import(string $package, ?int $expectedVersion = null): string
    {
        if (strlen($package) <= 64 || strlen($package) > self::MAX_PACKET) {
            return self::status('Invalid database package size.');
        }
        $key = base64_decode(self::config()['public_key'] ?? '', true);
        if (!function_exists('sodium_crypto_sign_verify_detached') || !is_string($key) || strlen($key) !== 32) {
            return self::status('This installation cannot verify database signatures.');
        }
        $compressed = substr($package, 64);
        if (!sodium_crypto_sign_verify_detached(substr($package, 0, 64), $compressed, $key)) {
            return self::status('Database signature verification failed.');
        }
        $json = @gzdecode($compressed, self::MAX_PACKET);
        $lines = self::lines(is_string($json) ? $json : '');
        $data = $lines->current();
        $lines->next();
        if (!is_array($data) || ($data['schema'] ?? null) !== 2 || !$lines->valid() ||
            !is_int($data['version'] ?? null) || $data['version'] < 1 ||
            ($expectedVersion !== null && $data['version'] !== $expectedVersion)) {
            return self::status('Invalid or incompatible database format.');
        }
        while ($lines->valid()) {
            $row = $lines->current();
            if (!self::validComponent($row)) {
                return self::status('Invalid database component entry.');
            }
            $lines->next();
        }
        global $wpdb;
        $lock = 'sd-feed-' . md5($wpdb->options);
        if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 1)', $lock)) !== 1) {
            return self::status('A database import is already running.');
        }
        try {
            wp_cache_delete('sd_vulnerability_db', 'options');
            if ($data['version'] <= self::version()) {
                return self::status('This database is already installed or older than the installed version.');
            }
            if (!update_option('sd_vulnerability_db', [
                'version' => $data['version'], 'compressed' => base64_encode($compressed),
            ], false)) {
                return self::status('Unable to store the database package.');
            }
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
        self::schedule();
        return self::status('Vulnerability database updated.', true);
    }

    private static function validComponent($row): bool
    {
        if (!is_array($row) || !is_string($row[0] ?? null) ||
            !preg_match('~^(?:core|plugin|theme):[^:\\x00-\\x1f]{1,200}$~D', $row[0]) || !is_array($row[1] ?? null)) {
            return false;
        }
        foreach ($row[1] as $record) {
            if (!is_array($record) || count($record) < 7 || !is_string($record[0] ?? null) ||
                !is_string($record[1] ?? null) || !is_array($record[4] ?? null) ||
                !is_array($record[5] ?? null) || !is_string($record[6] ?? null) ||
                array_filter($record[5], static fn ($value) => !is_string($value))) {
                return false;
            }
            foreach ($record[4] as $range) {
                if (!is_array($range) || !is_string($range[0] ?? null) || !is_bool($range[1] ?? null) ||
                    !is_string($range[2] ?? null) || !is_bool($range[3] ?? null)) {
                    return false;
                }
            }
        }
        return true;
    }

    public static function check(bool $refresh = false): void
    {
        global $wpdb;
        $lock = 'sd-versions-' . md5($wpdb->options);
        if ((int) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $lock)) !== 1) {
            self::schedule();
            return;
        }
        try {
            foreach (['sd_findings', 'sd_vulnerability_seen', 'sd_wpvulnerability_cache', 'sd_kev_seen'] as $option) {
                wp_cache_delete($option, 'options');
            }
            self::compare($refresh);
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }

    public static function inventory(): array
    {
        global $wp_version;
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $installed = ['core:wordpress' => [$wp_version, true]];
        foreach (get_plugins() as $file => $plugin) {
            $slug = str_contains($file, '/') ? dirname($file) : basename($file, '.php');
            $installed['plugin:' . $slug] = [$plugin['Version'], is_plugin_active($file)];
        }
        foreach (wp_get_themes() as $slug => $theme) {
            $installed['theme:' . $slug] = [$theme->get('Version'), in_array($slug, [get_stylesheet(), get_template()], true)];
        }
        return $installed;
    }

    private static function compare(bool $refresh): void
    {
        $installed = self::inventory();
        $lines = self::lines(self::database());
        $versionUsed = (int) ($lines->current()['version'] ?? 0);
        $lines->next();
        $findings = [];
        $covered = [];
        while ($lines->valid()) {
            [$key, $records] = $lines->current();
            $lines->next();
            if (!isset($installed[$key]) || $installed[$key][0] === '') {
                continue;
            }
            $covered[$key] = true;
            [$version, $active] = $installed[$key];
            foreach ($records as $record) {
                [$id, $title, $cve, $score, $ranges, $fixed, $link] = $record;
                $informational = (bool) ($record[8] ?? false);
                foreach ($ranges as $range) {
                    if (!self::inRange($version, $range)) {
                        continue;
                    }
                    $findings[] = compact('key', 'version', 'active', 'id', 'title', 'cve', 'score', 'range', 'fixed', 'link', 'informational')
                        + ['source' => 'Wordfence'];
                    break;
                }
            }
        }
        $external = [];
        if (State::enabled('wpvulnerability')) {
            [$components, $external] = WPVulnerability::read($installed, $refresh);
            foreach ($components as $key => $records) {
                [$version, $active] = $installed[$key];
                if ($version === '' || !$records) {
                    continue;
                }
                $covered[$key] = true;
                foreach ($records as $record) {
                    if (!self::matchesBounds($version, $record['bounds'])) {
                        continue;
                    }
                    $findings[] = $record + compact('key', 'version', 'active') + ['source' => 'WPVulnerability', 'informational' => false];
                }
            }
        }
        $findings = self::deduplicate($findings);
        if (State::enabled('kev_auto')) {
            $kev = Kev::cache()['entries'];
            foreach ($findings as &$finding) {
                foreach (array_merge([$finding['cve']], $finding['aliases'] ?? []) as $id) {
                    if (is_string($id) && isset($kev[$id])) {
                        $finding['kev'] = $kev[$id];
                        $finding['kev_cve'] = $id;
                        break;
                    }
                }
            }
            unset($finding);
            usort($findings, static fn ($a, $b) => empty($a['kev']) <=> empty($b['kev']));
        }
        self::notifyNew($findings);
        update_option('sd_findings', [
            'version' => $versionUsed, 'checked' => time(), 'items' => $findings,
            'covered' => count($covered), 'components' => count($installed), 'wpvulnerability' => $external,
        ], false);
    }

    private static function identifiers(array $finding): array
    {
        $keys = [];
        $link = $finding['link'];
        $aliases = array_merge([$finding['cve'], $finding['id']], $finding['aliases'] ?? []);
        if (preg_match('~^https?://www\.wordfence\.com/threat-intel/vulnerabilities/.+~i', $link)) {
            $aliases[] = $link;
        }
        foreach ($aliases as $alias) {
            if (is_string($alias) && $alias !== '') {
                $alias = preg_replace('~^https?://~i', '', $alias);
                $keys[] = hash('sha256', $finding['key'] . '|' . rtrim($alias, '/'));
            }
        }
        return array_unique($keys);
    }

    private static function deduplicate(array $findings): array
    {
        $byAlias = [];
        $unique = [];
        foreach ($findings as $finding) {
            $ids = self::identifiers($finding);
            $matching = array_key_first(array_intersect_key(array_fill_keys($ids, true), $byAlias));
            if ($matching !== null) {
                $index = $byAlias[$matching];
                $unique[$index]['aliases'] = array_values(array_unique(array_merge(
                    $unique[$index]['aliases'] ?? [], $finding['aliases'] ?? [],
                    array_filter([$finding['id'], $finding['cve']])
                )));
            } else {
                $index = count($unique);
                $unique[] = $finding;
            }
            foreach ($ids as $id) {
                $byAlias[$id] ??= $index;
            }
        }
        return $unique;
    }

    private static function notifyNew(array $findings): void
    {
        $known = get_option('sd_vulnerability_seen', null);
        $seen = is_array($known) ? $known : [];
        $previousKev = (array) get_option('sd_kev_seen', []);
        $kevSeen = $previousKev;
        if ($known === null) {
            foreach (get_option('sd_findings', [])['items'] ?? [] as $previous) {
                if (empty($previous['informational'])) {
                    $seen += array_fill_keys(self::identifiers($previous), true);
                }
            }
        }
        foreach ($findings as $finding) {
            if (!empty($finding['informational'])) {
                continue;
            }
            $ids = self::identifiers($finding);
            if (!$ids) {
                continue;
            }
            $keys = array_fill_keys($ids, true);
            $alreadyKnown = (bool) array_intersect_key($keys, $seen);
            $kevListed = !empty($finding['kev']);
            if (!$alreadyKnown && !Incidents::recordVulnerability(reset($ids), $finding)) {
                continue;
            }
            $seen += $keys;
            if ($kevListed && (array_intersect_key($keys, $kevSeen) || !$alreadyKnown ||
                Incidents::recordVulnerability(hash('sha256', 'kev:' . reset($ids)), $finding, 'vulnerability_escalated'))) {
                $kevSeen += $keys;
            }
        }
        if ($seen !== $known) {
            update_option('sd_vulnerability_seen', $seen, false);
        }
        if ($kevSeen !== $previousKev) {
            update_option('sd_kev_seen', $kevSeen, false);
        }
    }

    public static function describe(array $finding, bool $includeLink = true): string
    {
        $detail = sprintf(__('Component: %1$s · Installed version: %2$s', 'site-defense'), $finding['key'], $finding['version']);
        $detail .= "\n" . ($finding['cve'] ?: $finding['id']) . ' · ' . $finding['title'];
        if ($finding['score'] !== null) {
            $detail .= ' · CVSS ' . $finding['score'];
        }
        $detail .= "\n" . sprintf(__('Fixed version: %s', 'site-defense'), implode(', ', $finding['fixed']) ?: __('Unknown', 'site-defense'));
        if (!empty($finding['kev'])) {
            $detail .= "\n" . sprintf(__('CISA KEV added %1$s on %2$s.', 'site-defense'),
                $finding['kev_cve'], $finding['kev']);
        }
        return $detail . ($includeLink && $finding['link'] ? "\n" . $finding['link'] : '');
    }

    public static function inRange(string $version, array $range): bool
    {
        [$low, $includeLow, $high, $includeHigh] = $range;
        return ($low === '*' || version_compare($version, $low, $includeLow ? '>=' : '>')) &&
            ($high === '*' || version_compare($version, $high, $includeHigh ? '<=' : '<'));
    }

    private static function matchesBounds(string $version, array $bounds): bool
    {
        foreach ($bounds as [$bound, $operator]) {
            if (!version_compare($version, $bound, $operator)) {
                return false;
            }
        }
        return (bool) $bounds;
    }

    public static function assessments(array $targets, array $installed): array
    {
        $results = [];
        if (!$targets) {
            return $results;
        }
        $cache = (array) get_option('sd_wpvulnerability_cache', []);
        $lines = self::lines(self::database());
        $version = (int) ($lines->current()['version'] ?? 0);
        $lines->next();
        $byComponent = [];
        foreach ($targets as $index => $target) {
            $key = $target['component'];
            $byComponent[$key][] = $index;
            [$current, $active] = $installed[$key] ?? [null, null];
            $results[$index] = ['version' => $current, 'active' => $active, 'matches' => [], 'catalog_version' => $version];
        }
        while ($lines->valid()) {
            [$key, $records] = $lines->current();
            $lines->next();
            if (!isset($byComponent[$key], $installed[$key]) || $installed[$key][0] === '') {
                continue;
            }
            foreach ($records as $record) {
                if (!empty($record[8])) {
                    continue;
                }
                foreach ($byComponent[$key] as $index) {
                    if (!self::matchesAdvisory($targets[$index], $record[0], $record[2])) {
                        continue;
                    }
                    $affected = false;
                    foreach ($record[4] as $range) {
                        $affected = $affected || self::inRange($installed[$key][0], $range);
                    }
                    $results[$index]['matches'][] = ['source' => 'Wordfence', 'affected' => $affected, 'fixed' => $record[5]];
                }
            }
        }
        foreach ($targets as $index => $target) {
            $entry = $cache[$target['component']] ?? [];
            $current = $results[$index]['version'];
            if (!$current) {
                continue;
            }
            foreach ($entry['records'] ?? [] as $record) {
                if (self::matchesAdvisory($target, $record['id'], $record['cve'], $record['aliases'] ?? [])) {
                    $results[$index]['matches'][] = ['source' => 'WPVulnerability', 'fetched_at' => $entry['fetched'] ?? 0,
                        'affected' => self::matchesBounds($current, $record['bounds']), 'fixed' => $record['fixed']];
                }
            }
        }
        return $results;
    }

    private static function matchesAdvisory(array $target, string $id, ?string $cve, array $aliases = []): bool
    {
        if (!empty($target['cve'])) {
            return $target['cve'] === $cve || in_array($target['cve'], $aliases, true);
        }
        return !empty($target['advisory']) && ($target['advisory'] === $id || in_array($target['advisory'], $aliases, true));
    }

    public static function coreRuleActive(string $version): bool
    {
        return Firewall::coreRuleActive($version);
    }

    public static function filterRequest(\WP $wp): void
    {
        if (!State::enabled('observe')) {
            return;
        }
        $inputs = array_slice(array_merge($_GET, $_POST), 0, 32);
        foreach ($inputs as $input) {
            if (!is_string($input)) {
                continue;
            }
            $text = substr(wp_unslash($input), 0, 2048);
            if (FirewallMatcher::traversal($text) || preg_match('~<\s*script\b|\bunion\s+(all\s+)?select\b~i', $text)) {
                State::log('waf_observe', 'Possible injection or traversal in request parameters.',
                    context: RequestEvidence::capture($_SERVER, 'wordpress'));
                return;
            }
        }
        foreach (array_slice($_FILES, 0, 16) as $file) {
            if (is_string($file['name'] ?? null) && Scanner::executable($file['name'])) {
                State::log('waf_observe', 'Request contains an executable file upload.',
                    context: RequestEvidence::capture($_SERVER, 'wordpress'));
                return;
            }
        }
    }

}

