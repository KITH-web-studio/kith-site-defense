<?php
if (PHP_SAPI !== 'cli' || !extension_loaded('sodium') || $argc !== 2) {
    fwrite(STDERR, "Usage: php tools/create-signing-key.php <private-key-path>\n");
    exit(1);
}
umask(0077);
$file = @fopen($argv[1], 'xb');
if (!$file) {
    fwrite(STDERR, "Cannot exclusively create the key file.\n");
    exit(1);
}
$keypair = sodium_crypto_sign_keypair();
$key = base64_encode(sodium_crypto_sign_secretkey($keypair));
if (fwrite($file, $key . PHP_EOL) !== strlen($key . PHP_EOL) || !fclose($file)) {
    fwrite(STDERR, "Could not store the signing key.\n");
    exit(1);
}
echo base64_encode(sodium_crypto_sign_publickey($keypair)) . PHP_EOL;

