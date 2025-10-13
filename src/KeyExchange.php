<?php
declare(strict_types=1);

namespace IvanSostarko\OttoCrypt;

use IvanSostarko\OttoCrypt\Support\HKDF;

final class KeyExchange
{
    /** Generate an X25519 keypair. */
    public static function generateKeypair(): array
    {
        $sk = random_bytes(SODIUM_CRYPTO_BOX_SECRETKEYBYTES); // 32 bytes
        $pk = sodium_crypto_scalarmult_base($sk);
        return ['secret' => $sk, 'public' => $pk];
    }

    /** Derive X25519 shared secret between my secret key and peer's public key. */
    public static function deriveSharedSecret(string $mySecret, string $theirPublic): string
    {
        return sodium_crypto_scalarmult($mySecret, $theirPublic);
    }

    /** HKDF a 32-byte session key from shared secret. */
    public static function deriveSessionKey(string $sharedSecret, string $salt = '', string $context = 'OTTO-X25519-SESSION'): string
    {
        return HKDF::derive($sharedSecret, 32, $context, $salt, 'sha256');
    }

    /** Encode/Decode helpers (base64, hex) */
    public static function b64(string $bin): string { return base64_encode($bin); }
    public static function unb64(string $b64): string { return base64_decode($b64, true) ?: ''; }
    public static function hex(string $bin): string { return bin2hex($bin); }
    public static function unhex(string $hex): string { return hex2bin($hex) ?: ''; }
}
