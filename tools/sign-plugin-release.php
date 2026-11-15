<?php
if (PHP_SAPI !== 'cli' || $argc !== 4 || !extension_loaded('sodium') || !extension_loaded('zip')) {
    fwrite(STDERR, "Usage: php tools/sign-plugin-release.php <site-defense.zip> <private-key-path> <output-directory>\n");
    exit(1);
}

[$script, $path, $keyPath, $output] = $argv;
$size = is_file($path) ? filesize($path) : false;
$zip = new ZipArchive();
if (basename($path) !== 'site-defense.zip' || !$size || $size > 32 * 1024 * 1024 || $zip->open($path, ZipArchive::CHECKCONS) !== true) {
    fwrite(STDERR, "Invalid Site Defense ZIP.\n");
    exit(1);
}
for ($index = 0; $index < $zip->numFiles; $index++) {
    $entry = $zip->getNameIndex($index);
    if (!is_string($entry) || !str_starts_with($entry, 'site-defense/') || str_contains($entry, '\\') ||
        preg_match('~(?:^|/)\.{1,2}(?:/|$)|[\x00-\x1f]~', $entry)) {
        fwrite(STDERR, "Unexpected entry in the Site Defense ZIP.\n");
        exit(1);
    }
}
$main = 'site-defense/site-defense.php';
$bootstrap = $zip->getFromName($main, 8192);
$publicConfig = json_decode((string) $zip->getFromName('site-defense/data/plugin-updates.json', 1024), true);
$zip->close();

$headers = [];
foreach (['name' => 'Plugin Name', 'version' => 'Version', 'update' => 'Update URI', 'wp' => 'Requires at least', 'php' => 'Requires PHP'] as $field => $label) {
    if (!is_string($bootstrap) || !preg_match('/^[ \t*]*' . preg_quote($label, '/') . ':[ \t]*([^\r\n]+)/m', $bootstrap, $match)) {
        fwrite(STDERR, "A release header is missing from the ZIP.\n");
        exit(1);
    }
    $headers[$field] = trim($match[1]);
}
if ($headers['name'] !== 'Site Defense' ||
    !preg_match('~^https://github\.com/([A-Za-z0-9-]+/[A-Za-z0-9_.-]+)$~D', $headers['update'], $repository) ||
    !preg_match('/^(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){2}(?:-rc\.[1-9][0-9]{0,5})?$/D', $headers['version']) ||
    !preg_match('/^[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?$/D', $headers['wp']) ||
    !preg_match('/^[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?$/D', $headers['php'])) {
    fwrite(STDERR, "Invalid Site Defense release metadata.\n");
    exit(1);
}

$key = base64_decode(trim((string) @file_get_contents($keyPath)), true);
if (!is_string($key) || strlen($key) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES ||
    base64_encode(sodium_crypto_sign_publickey_from_secretkey($key)) !== ($publicConfig['public_key'] ?? null)) {
    fwrite(STDERR, "The signing key does not match the public key included in the ZIP.\n");
    exit(1);
}
$manifest = json_encode(['schema' => 1, 'repository' => $repository[1], 'plugin' => $main, 'version' => $headers['version'],
    'zip' => basename($path), 'bytes' => $size, 'sha256' => hash_file('sha256', $path),
    'requires_wp' => $headers['wp'], 'requires_php' => $headers['php']], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
$signature = sodium_crypto_sign_detached($manifest, $key);
sodium_memzero($key);
if ((!is_dir($output) && !mkdir($output, 0777, true)) ||
    file_put_contents($output . '/site-defense-update.json', $manifest, LOCK_EX) !== strlen($manifest) ||
    file_put_contents($output . '/site-defense-update.sig', $signature, LOCK_EX) !== strlen($signature)) {
    fwrite(STDERR, "Unable to write the release manifest and signature.\n");
    exit(1);
}
echo 'Signed Site Defense v', $headers['version'], PHP_EOL;
