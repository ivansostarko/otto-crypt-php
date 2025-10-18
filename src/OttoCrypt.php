<?php
declare(strict_types=1);

namespace IvanSostarko\OttoCrypt;

use InvalidArgumentException;
use RuntimeException;
use IvanSostarko\OttoCrypt\Support\HKDF;

final class OttoCrypt
{
    // Algorithm and KDF identifiers
    private const MAGIC = "OTTO1";
    private const ALGO_ID = 0xA1; // AES-256-GCM with HKDF-SIV-style nonces
    private const KDF_PASSWORD = 0x01;
    private const KDF_RAWKEY   = 0x02;
    private const KDF_X25519   = 0x03;

    // Flags
    private const FLAG_CHUNKED = 0x01;

    private int $chunkSize;
    private int $argonOpslimit;
    private int $argonMemlimit;

    public function __construct()
    {
        $this->chunkSize    = (int) (config('otto-crypt.chunk_size') ?? 1024 * 1024);
        $argon = config('otto-crypt.argon') ?? [];
        $this->argonOpslimit = (int) ($argon['opslimit'] ?? SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE);
        $this->argonMemlimit = (int) ($argon['memlimit'] ?? SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE);
    }

    /** Encrypt a small string (single chunk). Returns [$ciphertext, $headerBin]. */
    public function encryptString(string $plaintext, array $options = []): array
    {
        $ctx = $this->initContext($options, /*chunked*/ false);
        $ad = $ctx['ad'];
        $encKey = $ctx['enc_key'];
        $nonceKey = $ctx['nonce_key'];
        $counter = 0;
        $nonce = $this->chunkNonce($nonceKey, $counter);
        $tag = '';
        $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $encKey, OPENSSL_RAW_DATA, $nonce, $tag, $ad, 16);
        if ($cipher === false) {
            throw new RuntimeException('OpenSSL encryption failed');
        }
        return [$cipher . $tag, $ctx['header']];
    }

    /** Decrypt a small string given ciphertext+tag and header. */
    public function decryptString(string $cipherAndTag, string $header, array $options = []): string
    {
        $ctx = $this->initContextForDecryption($header, $options);
        $ad = $ctx['ad'];
        $encKey = $ctx['enc_key'];
        $nonceKey = $ctx['nonce_key'];
        $counter = 0;
        $nonce = $this->chunkNonce($nonceKey, $counter);
        $len = strlen($cipherAndTag);
        if ($len < 16) {
            throw new InvalidArgumentException('Ciphertext too short');
        }
        $cipher = substr($cipherAndTag, 0, $len - 16);
        $tag = substr($cipherAndTag, -16);
        $plain = openssl_decrypt($cipher, 'aes-256-gcm', $encKey, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
        if ($plain === false) {
            throw new RuntimeException('Decryption failed (auth?)');
        }
        return $plain;
    }

    /** Encrypt a file/stream in chunked mode. */
    public function encryptFile(string $inPath, string $outPath, array $options = []): void
    {
        $ctx = $this->initContext($options, /*chunked*/ true);
        $ad = $ctx['ad'];
        $encKey = $ctx['enc_key'];
        $nonceKey = $ctx['nonce_key'];

        $in = fopen($inPath, 'rb');
        if (!$in) throw new RuntimeException("Cannot open input: $inPath");
        $out = fopen($outPath, 'wb');
        if (!$out) throw new RuntimeException("Cannot open output: $outPath");

        // Write header
        fwrite($out, $ctx['header']);

        $counter = 0;
        while (!feof($in)) {
            $chunk = fread($in, $this->chunkSize);
            if ($chunk === '' || $chunk === false) break;
            $nonce = $this->chunkNonce($nonceKey, $counter);
            $tag = '';
            $cipher = openssl_encrypt($chunk, 'aes-256-gcm', $encKey, OPENSSL_RAW_DATA, $nonce, $tag, $ad, 16);
            if ($cipher === false) throw new RuntimeException('OpenSSL encryption failed');
            $len = strlen($cipher);

            // Write length (uint32 BE), ciphertext, tag(16)
            fwrite($out, pack('N', $len));
            fwrite($out, $cipher);
            fwrite($out, $tag);

            $counter++;
        }
        fclose($in);
        fclose($out);

        // Zero keys
        sodium_memzero($encKey);
        sodium_memzero($nonceKey);
        sodium_memzero($ctx['master_key']);
    }

    /** Decrypt a file/stream written by encryptFile. */
    public function decryptFile(string $inPath, string $outPath, array $options = []): void
    {
        $in = fopen($inPath, 'rb');
        if (!$in) throw new RuntimeException("Cannot open input: $inPath");

        // Read and parse header
        $header = $this->readHeaderStream($in);
        $ctx = $this->initContextForDecryption($header, $options);
        $ad = $ctx['ad'];
        $encKey = $ctx['enc_key'];
        $nonceKey = $ctx['nonce_key'];

        $out = fopen($outPath, 'wb');
        if (!$out) throw new RuntimeException("Cannot open output: $outPath");

        $counter = 0;
        while (!feof($in)) {
            $lenBytes = fread($in, 4);
            if ($lenBytes === '' || $lenBytes === false) break;
            if (strlen($lenBytes) < 4) break;
            $arr = unpack('Nlen', $lenBytes);
            $len = $arr['len'] ?? 0;
            if ($len <= 0) break;

            $cipher = $this->readExact($in, $len);
            $tag = $this->readExact($in, 16);

            $nonce = $this->chunkNonce($nonceKey, $counter);
            $plain = openssl_decrypt($cipher, 'aes-256-gcm', $encKey, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
            if ($plain === false) throw new RuntimeException('Decryption failed (auth?)');

            fwrite($out, $plain);
            $counter++;
        }

        fclose($in);
        fclose($out);

        sodium_memzero($encKey);
        sodium_memzero($nonceKey);
        sodium_memzero($ctx['master_key']);
    }

    // ===== Internal helpers =====

    private function readExact($fp, int $n): string
    {
        $buf = '';
        while (strlen($buf) < $n) {
            $r = fread($fp, $n - strlen($buf));
            if ($r === false || $r === '') throw new RuntimeException('Unexpected EOF');
            $buf .= $r;
        }
        return $buf;
    }

    private function readHeaderStream($fp): string
    {
        $prefix = $this->readExact($fp, 5 + 1 + 1 + 1 + 1 + 2); // magic + algo + kdf + flags + reserved + header_len
        $magic = substr($prefix, 0, 5);
        if ($magic !== self::MAGIC) throw new RuntimeException('Bad magic');
        $algo = ord($prefix[5]);
        if ($algo !== self::ALGO_ID) throw new RuntimeException('Unsupported algo');
        $kdf  = ord($prefix[6]);
        $flags= ord($prefix[7]);
        $reserved = ord($prefix[8]);
        $hlen = unpack('nlen', substr($prefix, 9, 2))['len'];
        $rest = $this->readExact($fp, $hlen);
        return $prefix . $rest;
    }

    private function initContext(array $options, bool $chunked): array
    {
        $fileSalt = random_bytes(16);
        $algoId = chr(self::ALGO_ID);
        $flags = $chunked ? chr(self::FLAG_CHUNKED) : chr(0);
        $reserved = chr(0);

        // Determine KDF & master key
        $kdfId = null;
        $headerExtra = '';
        if (isset($options['password'])) {
            $kdfId = chr(self::KDF_PASSWORD);
            $pwSalt = random_bytes(16);
            $opslimit = $this->argonOpslimit;
            $memlimit = $this->argonMemlimit;
            $master = sodium_crypto_pwhash(32, $options['password'], $pwSalt, $opslimit, $memlimit, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $headerExtra .= $pwSalt;
            $headerExtra .= pack('N', $opslimit);
            $headerExtra .= pack('N', (int)($memlimit / 1024)); // store KiB
        } elseif (isset($options['raw_key'])) {
            $kdfId = chr(self::KDF_RAWKEY);
            $raw = $options['raw_key'];
            if (strlen($raw) !== 32) throw new InvalidArgumentException('raw_key must be 32 bytes');
            $master = $raw;
        } elseif (isset($options['recipient_public'])) {
            $kdfId = chr(self::KDF_X25519);
            $recipientPk = $this->decodeKey($options['recipient_public']);
            if (strlen($recipientPk) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
                throw new InvalidArgumentException('recipient_public invalid length');
            }
            // Ephemeral keypair
            $ephSk = random_bytes(SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
            $ephPk = sodium_crypto_scalarmult_base($ephSk);
            $shared = sodium_crypto_scalarmult($ephSk, $recipientPk);
            $master = HKDF::derive($shared, 32, 'OTTO-E2E-MASTER', $fileSalt, 'sha256');
            sodium_memzero($shared);
            $headerExtra .= $ephPk;
        } else {
            throw new InvalidArgumentException('Provide one of: password, raw_key, recipient_public');
        }

        $encKey = HKDF::derive($master, 32, 'OTTO-ENC-KEY', $fileSalt, 'sha256');
        $nonceKey = HKDF::derive($master, 32, 'OTTO-NONCE-KEY', $fileSalt, 'sha256');

        // Build header
        $var = $fileSalt . $headerExtra;
        $headerLen = pack('n', strlen($var));
        $header = self::MAGIC . $algoId . $kdfId . $flags . $reserved . $headerLen . $var;

        return [
            'header'     => $header,
            'ad'         => $header,
            'enc_key'    => $encKey,
            'nonce_key'  => $nonceKey,
            'master_key' => $master,
        ];
    }

    private function initContextForDecryption(string $header, array $options): array
    {
        if (strlen($header) < 5 + 1 + 1 + 1 + 1 + 2) {
            throw new InvalidArgumentException('Header too short');
        }
        $magic = substr($header, 0, 5);
        if ($magic !== self::MAGIC) throw new RuntimeException('Bad magic');
        $algo = ord($header[5]);
        if ($algo !== self::ALGO_ID) throw new RuntimeException('Unsupported algo');
        $kdf  = ord($header[6]);
        $flags= ord($header[7]);
        $hlen = unpack('nlen', substr($header, 9, 2))['len'];
        $var  = substr($header, 11, $hlen);
        $off = 0;
        $fileSalt = substr($var, $off, 16); $off += 16;

        if ($kdf === self::KDF_PASSWORD) {
            $pwSalt = substr($var, $off, 16); $off += 16;
            $opslimit = unpack('Nn', substr($var, $off, 4))['n']; $off += 4;
            $memKiB   = unpack('Nn', substr($var, $off, 4))['n']; $off += 4;
            $memlimit = $memKiB * 1024;
            $password = $options['password'] ?? null;
            if (!is_string($password)) throw new InvalidArgumentException('Password required');
            $master = sodium_crypto_pwhash(32, $password, $pwSalt, $opslimit, $memlimit, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        } elseif ($kdf === self::KDF_RAWKEY) {
            $raw = $options['raw_key'] ?? null;
            if (!is_string($raw) || strlen($raw) !== 32) throw new InvalidArgumentException('raw_key (32 bytes) required');
            $master = $raw;
        } elseif ($kdf === self::KDF_X25519) {
            $ephPk = substr($var, $off, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES); $off += SODIUM_CRYPTO_BOX_PUBLICKEYBYTES;
            $senderSecret = $options['sender_secret'] ?? null;
            $senderSecret = $this->decodeKey($senderSecret ?? '');
            if (strlen($senderSecret) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
                throw new InvalidArgumentException('sender_secret invalid length');
            }
            $shared = sodium_crypto_scalarmult($senderSecret, $ephPk);
            $master = HKDF::derive($shared, 32, 'OTTO-E2E-MASTER', $fileSalt, 'sha256');
            sodium_memzero($shared);
        } else {
            throw new RuntimeException('Unknown KDF');
        }

        $encKey = HKDF::derive($master, 32, 'OTTO-ENC-KEY', $fileSalt, 'sha256');
        $nonceKey = HKDF::derive($master, 32, 'OTTO-NONCE-KEY', $fileSalt, 'sha256');

        return [
            'ad'         => substr($header, 0, 11 + $hlen),
            'enc_key'    => $encKey,
            'nonce_key'  => $nonceKey,
            'master_key' => $master,
        ];
    }

    private function chunkNonce(string $nonceKey, int $counter): string
    {
        // 64-bit counter (big endian) into info string
        $hi = ($counter >> 32) & 0xFFFFFFFF;
        $lo = $counter & 0xFFFFFFFF;
        $info = "OTTO-CHUNK-NONCE" . pack('NN', $hi, $lo);
        return HKDF::derive($nonceKey, 12, $info, '', 'sha256');
    }

    private function decodeKey(string $txt): string
    {
        $txt = trim($txt);
        if ($txt === '') return '';
        // Try base64 first
        $b = base64_decode($txt, true);
        if ($b !== false && $b !== '') return $b;
        // Try hex
        $h = @hex2bin($txt);
        if ($h !== false) return $h;
        return $txt;
    }
}
