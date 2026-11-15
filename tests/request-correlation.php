<?php
// Run with: php tests/request-correlation.php
define('ABSPATH', __DIR__);
define('MINUTE_IN_SECONDS', 60);

function get_option(string $name): bool
{
    return $name === 'sd_early_enabled';
}

require dirname(__DIR__) . '/site-defense/includes/RequestEvidence.php';
require dirname(__DIR__) . '/site-defense/includes/RequestCorrelation.php';
require dirname(__DIR__) . '/site-defense/includes/Investigation.php';

use SiteDefense\Investigation;
use SiteDefense\RequestCorrelation;
use SiteDefense\RequestEvidence;

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$id = 'proxy-request-888';
$withoutTrustedId = RequestEvidence::capture(['HTTP_SITE_DEFENSE_REQUEST_ID' => $id, 'HTTP_X_REQUEST_ID' => $id], 'early');
check($withoutTrustedId['request_id'] === '', 'Client headers must be ignored.');

$time = time();
$uri = '/wp-content/plugins/fixture/demo.php';
$waf = ['id' => 'waf-event:1', 'time' => $time, 'method' => 'POST', 'path' => $uri, 'kind' => 'waf_observe',
    'request_id' => $id, 'layer' => 'early'];
$block = array_replace($waf, ['id' => 'waf-event:2', 'kind' => 'waf_block', 'layer' => 'wordpress']);
$proxy = ['time' => gmdate('c', $time), 'method' => 'POST', 'path' => $uri . '?secret=private-lab-value',
    'status' => 403, 'sd_request_id' => $id];
$legacy = '192.0.2.10 - - [' . gmdate('d/M/Y:H:i:s O', $time) . '] "POST /wp-login.php HTTP/1.1" 302 0';
$file = tempnam(sys_get_temp_dir(), 'sd-proxy-test-');
if ($file === false) {
    throw new RuntimeException('Could not create test log.');
}

try {
    file_put_contents($file, json_encode($proxy) . "\n" . $legacy . "\n");
    [$report, $posts, $confirmed] = RequestCorrelation::build([$waf, $block], false, $file, $time - 3600, 10);
    $request = $report['requests'][0];
    check($request['status'] === 'confirmed' && count($request['sources']['waf']) === 2, 'A request can trigger two WAF rules.');
    check(count($confirmed[$request['sources']['proxy'][0]['id']]) === 2, 'The proxy record must reference both rules.');
    check(array_column($posts, 'path') === ['/wp-login.php'], 'Combined fallback must exclude the blocked POST.');
    check(!str_contains(json_encode($report), 'private-lab-value'), 'Query data must be omitted from the report.');

    $mismatch = array_replace($proxy, ['path' => '/elsewhere', 'status' => 200]);
    file_put_contents($file, json_encode($proxy) . "\n" . json_encode($mismatch) . "\n");
    [$report, , $confirmed, $conflicted] = RequestCorrelation::build([$waf, $block], false, $file, $time - 3600, 10);
    $request = $report['requests'][0];
    check($request['status'] === 'conflict' && !$confirmed && isset($conflicted[$id]), 'Duplicate IDs must not confirm a link.');
    check($request['gaps'] === ['duplicate_proxy_id', 'path_mismatch', 'block_status_mismatch'], 'Report the conflicting source fields.');

    [$report] = RequestCorrelation::build([$waf], false, $file . '.missing', $time - 3600, 10);
    check($report['proxy']['status'] === 'unavailable' && $report['requests'][0]['gaps'] === ['proxy_log_unavailable'],
        'Show a gap when a previously selected log cannot be read.');
} finally {
    unlink($file);
}

$fileEvent = ['id' => 'journal:3', 'kind' => 'file_changed', 'time' => $time + 60, 'path' => 'wp-content/uploads/test.php'];
$versions = [['key' => 'plugin:fixture', 'active' => true, 'id' => 'test-advisory', 'cve' => 'CVE-2099-19999']];
$hypotheses = new ReflectionMethod(Investigation::class, 'hypotheses');
$evidence = $hypotheses->invoke(null, [$waf, $fileEvent], $versions, [$waf['id'] => ['proxy:evidence']], [], []);
check(count($evidence) === 1 && $evidence[0]['confidence'] === 'possible' &&
    $evidence[0]['evidence'] === ['waf-event:1', 'journal:3', 'proxy:evidence'], 'The later file event remains a time-based hypothesis.');
check($hypotheses->invoke(null, [$waf, $fileEvent], $versions, [], [], [$id => true]) === [],
    'An observation must not suggest entry for the same request that the WAF blocked.');

echo "Request correlation regression checks passed.\n";
