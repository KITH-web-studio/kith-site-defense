<?php
// This engine runs before WordPress. Its configuration contains no notification credentials.
if (defined('SD_EARLY_LOADED') || !isset($sdMarker) || !is_string($sdMarker) || !is_readable($sdMarker)) {
    return;
}
$sdConfigPath = dirname($sdMarker) . '/sd-early-config.php';
$sdHeader = "<?php exit; // Site Defense early runtime\n?>\n";
$sdContents = @file_get_contents($sdConfigPath);
if (is_string($sdContents) && str_starts_with($sdContents, $sdHeader)) {
    $sdConfig = json_decode(substr($sdContents, strlen($sdHeader)), true);
} else {
    // An upgraded WordPress request will migrate config written by older releases.
    $sdConfig = json_decode((string) file_get_contents($sdMarker), true);
    if (($sdConfig['uploads'] ?? '') === '/__sd-runtime-moved__') {
        return;
    }
}
if (!is_array($sdConfig)) {
    return;
}
define('SD_EARLY_LOADED', true);
require_once __DIR__ . '/includes/RequestEvidence.php';
$sdReport = static function (string $kind, string $id, string $route) use ($sdMarker): void {
    $path = dirname($sdMarker) . '/sd-early-events.php';
    if (is_link($path)) {
        return;
    }
    $handle = @fopen($path, 'c+b');
    if (!$handle) {
        return;
    }
    if (flock($handle, LOCK_EX | LOCK_NB)) {
        $size = fstat($handle)['size'];
        if ($size === 0) {
            fwrite($handle, "<?php exit; // Site Defense early events\n");
        }
        if ($size < 65536) {
            fseek($handle, 0, SEEK_END);
            $request = \SiteDefense\RequestEvidence::capture($_SERVER, 'early');
            fwrite($handle, json_encode(['kind' => $kind, 'time' => time(), 'id' => $id, 'route' => $route,
                'path' => $request['route'], 'method' => $request['method'], 'request_id' => $request['request_id']]) . "\n");
        }
        flock($handle, LOCK_UN);
    }
    fclose($handle);
};
$sdScript = realpath($_SERVER['SCRIPT_FILENAME'] ?? '');
$sdUploads = !empty($sdConfig['uploads']) ? realpath($sdConfig['uploads']) : false;
$sdOriginal = str_replace('\\', '/', $_SERVER['SCRIPT_FILENAME'] ?? '');
$sdUploadPath = rtrim(str_replace('\\', '/', $sdConfig['uploads'] ?? ''), '/') . '/';
if (($sdUploadPath !== '/' && str_starts_with($sdOriginal, $sdUploadPath)) ||
    ($sdScript && $sdUploads && str_starts_with(str_replace('\\', '/', $sdScript),
        rtrim(str_replace('\\', '/', $sdUploads), '/') . '/'))) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    $sdReport('waf_block', 'UPLOADS-PHP', '/uploads');
    exit($sdConfig['uploads_blocked'] ?? 'PHP execution in uploads is disabled.');
}
if (empty($sdConfig['waf']) || ($sdConfig['firewall_schema'] ?? 0) !== 2) {
    return;
}
require_once __DIR__ . '/includes/FirewallMatcher.php';
define('SD_EARLY_WAF_READY', true);
foreach ($sdConfig['rules'] ?? [] as $sdRule) {
    if (!\SiteDefense\FirewallMatcher::matches($sdRule, $_SERVER, $_GET, $_POST)) {
        continue;
    }
    $GLOBALS['sd_early_matches'][$sdRule['id']] = true;
    $sdBlock = $sdRule['mode'] === 'block';
    $sdReport($sdBlock ? 'waf_block' : 'waf_observe', $sdRule['id'], $sdRule['label']);
    if ($sdBlock) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=UTF-8');
        exit($sdConfig['blocked'] ?? 'Request blocked.');
    }
}

