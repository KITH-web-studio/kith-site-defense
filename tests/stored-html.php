<?php
// Run on a local WordPress site: wp eval-file tests/stored-html.php
use SiteDefense\StoredHtml;

$cases = [
    '<script data-value="a>b">void(0)</script>' => ['script'],
    '<script type="module" src="/sample.js"></script>' => ['script'],
    '<script type="text/plain">text</script><script type="application/ld+json">{}</script>' => [],
    '<!-- <script>void(0)</script> --><textarea><script>void(0)</script></textarea>' => [],
    '<template><script>void(0)</script></template><noscript><script>void(0)</script></noscript>' => [],
    '<svg><script>void(0)</script></svg>' => [],
    '<meta content="0; url=/local" http-equiv="refr&#101;sh">' => ['meta_refresh'],
    '<meta http-equiv="refresh" content="30">' => [],
    '<p><script>incomplete' => [],
    '{"template":"<script>void(0)</script>"}' => [],
    serialize(['template' => '<script>void(0)</script>']) => [],
    '[gallery]<script>void(0)</script>' => ['script'],
];

foreach ($cases as $html => $expected) {
    $got = array_column(StoredHtml::fragments($html), 'kind');
    if ($got !== $expected) {
        throw new RuntimeException('Unexpected cleanup fragments for fixture ' . $html);
    }
}

$html = "Безпечний текст\r\n<<script>void(0)</script>img src=x onerror=alert(1)>";
$fragments = StoredHtml::fragments($html);
if (count($fragments) !== 1 || $fragments[0]['line'] !== 2 ||
    StoredHtml::remove($html, $fragments) !== "Безпечний текст\r\n<<!---->img src=x onerror=alert(1)>" ||
    StoredHtml::remove(str_replace('void(0)', 'void(1)', $html), $fragments) !== null ||
    StoredHtml::remove($html, [$fragments[0], $fragments[0]]) !== null) {
    throw new RuntimeException('The HTML edit changed unexpected bytes or accepted a stale or overlapping span.');
}

echo "Stored HTML span and replacement checks passed.\n";
