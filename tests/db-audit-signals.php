<?php
// Run with: php tests/db-audit-signals.php
define('ABSPATH', __DIR__);
require dirname(__DIR__) . '/site-defense/includes/DbAudit.php';

$cases = [
    '<script src="/assets/demo.js"></script>' => ['stored_script'],
    '<script data-type="application/json">void(0)</script>' => ['stored_script'],
    '<script type="application/ld+json">{"name":"Demo"}</script>' => [],
    '<script type="application/json" src="/assets/demo.js"></script>' => ['stored_script'],
    '<meta content="0; url=/next" http-equiv="refresh">' => ['stored_redirect'],
    '<meta http-equiv=refresh content="1; url=/next">' => ['stored_redirect'],
    '<meta http-equiv=\"refresh\" content=\"1; url=/next\">' => ['stored_redirect'],
    '<script>location = "/next";</script>' => ['stored_script', 'stored_redirect'],
    '<script>window.location.replace("/next")</script>' => ['stored_script', 'stored_redirect'],
    '<p>window.location == "/next"</p>' => [],
    '<?php echo "fixture"; ?>' => ['stored_code'],
    '<a href="javascript:void(0)">Demo</a>' => ['stored_code'],
    '<a href="https://example.invalid">Demo</a>' => [],
    '<p>&lt;script&gt;Example&lt;/script&gt;</p>' => [],
];

foreach ($cases as $source => $expected) {
    $actual = \SiteDefense\DbAudit::signals($source);
    if ($actual !== $expected) {
        fwrite(STDERR, 'Unexpected flags for ' . $source . ': ' . json_encode($actual) . PHP_EOL);
        exit(1);
    }
}

echo count($cases), " database signal cases passed.\n";
