<?php
if (PHP_SAPI !== 'cli' || $argc !== 5 || !extension_loaded('sodium')) {
    exit(1);
}
$config = json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR);
$key = base64_decode($config['public_key'], true);
foreach (array_slice($argv, 2) as $path) {
    $bytes = file_get_contents($path);
    if (strlen($bytes) <= SODIUM_CRYPTO_SIGN_BYTES ||
        !sodium_crypto_sign_verify_detached(substr($bytes, 0, SODIUM_CRYPTO_SIGN_BYTES), substr($bytes, SODIUM_CRYPTO_SIGN_BYTES), $key)) {
        fwrite(STDERR, "Invalid release package signature.\n");
        exit(1);
    }
}
