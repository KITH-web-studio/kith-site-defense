<?php
if (PHP_SAPI !== 'cli' || $argc !== 4 || !extension_loaded('sodium')) {
    fwrite(STDERR, "Usage: php tools/sign-rules.php <rules.json> <private-key-path> <output.pack>\n");
    exit(1);
}
$data = file_get_contents($argv[1]);
json_decode($data, true, flags: JSON_THROW_ON_ERROR);
$key = base64_decode(trim(file_get_contents($argv[2])), true);
if (!is_string($key) || strlen($key) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
    exit(2);
}
if (file_put_contents($argv[3], sodium_crypto_sign_detached($data, $key) . $data) === false) {
    exit(3);
}

