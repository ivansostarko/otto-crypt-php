# OTTO Crypt — Laravel Package


OTTO Crypt is a Laravel‑ready crypto package that provides **end‑to‑end encryption (E2EE)** and **chunked streaming AEAD** for large files (video/audio), while remaining simple to use in apps and Artisan CLI.


> ⚠️ **Security notice**: OTTO Crypt uses trusted primitives (**AES‑256‑GCM, Argon2id, HKDF, X25519**), but its composition ("**OTTO‑256‑GCM‑HKDF‑SIV**") is **custom**. Treat it as experimental until it undergoes an **independent cryptographic review**.

---

## Table of contents

- [Highlights](#highlights)
- [Installation](#installation)
- [Quick start](#quick-start)
  - [CLI (Artisan)](#cli-artisan)
  - [Laravel API (Facade)](#laravel-api-facade)
- [Design & Format](#design--format)
  - [Construction: OTTO‑256‑GCM‑HKDF‑SIV](#construction-otto256gcmhkdfsiv)
  - [Header layout](#header-layout)
  - [Streaming/chunk format](#streamingchunk-format)
  - [Key derivation](#key-derivation)
  - [Nonce derivation (HKDF‑SIV style)](#nonce-derivation-hkdfsiv-style)
  - [X25519 E2E mode](#x25519-e2e-mode)
- [Configuration](#configuration)
- [Comparison with other schemes](#comparison-with-other-schemes)
- [Threat model & security notes](#threat-model--security-notes)
- [Performance](#performance)
- [Docker](#docker)
- [Examples](#examples)
- [Roadmap](#roadmap)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)
- [Responsible disclosure](#responsible-disclosure)

---

## Highlights

- **AES‑256‑GCM AEAD** for authenticated encryption (16‑byte tags).
- **HKDF‑SIV‑style nonces** (misuse‑resistance against nonce reuse by deriving nonces deterministically per chunk).
- **Streaming / chunked** encryption for very large files (default chunk 1 MiB; configurable).
- **E2E session keys** via **X25519** (ephemeral ECDH) or **Argon2id password KDF**, or direct 32‑byte raw keys.
- **Associated Data = full header**, binding ciphertext to algorithm, salts, KDF params, and sender ephemeral key.
- **Laravel native**: auto‑discovered Service Provider + Facade + Artisan commands.

---

## Installation

```bash
composer require ivansostarko/otto-crypt-php

# Optional: publish config
php artisan vendor:publish --provider="IvanSostarko\OttoCrypt\OttoCryptServiceProvider"
```

Requirements: PHP **8.2+**, `ext-openssl`, `ext-sodium`, Laravel **12**.

---

## Quick start

### CLI (Artisan)

**Encrypt with a password (Argon2id):**
```bash
php artisan otto:encrypt storage/app/private/otto-demo/test.exe --out=storage/app/private/otto-demo/test.exe.otto --password="strong-pass"
```

**Decrypt with a password:**
```bash
php artisan otto:decrypt storage/app/private/otto-demo/test.exe --out=storage/app/private/otto-demo/test.exe.otto --password="strong-pass"
```

**End‑to‑end: encrypt to a recipient’s X25519 public key (base64/hex/raw):**
```bash
php artisan otto:encrypt storage/app/private/otto-demo/big.mov --out=storage/app/big.mov.otto --recipient="BASE64_OR_HEX_PUBLIC"
```

**End‑to‑end: decrypt with your X25519 secret key:**
```bash
php artisan otto:decrypt storage/app/private/otto-demo/big.mov.otto --out=storage/app/big.mov --sender-secret="BASE64_OR_HEX_SECRET"
```

### Laravel API (Facade)

```php
use IvanSostarko\OttoCrypt\Facades\OttoCrypt as Otto;

// Encrypt & decrypt small strings (single-shot)
[$cipherAndTag, $header] = Otto::encryptString("Hello OTTO!", options: ['password' => 'P@ssw0rd!']);
$plain = Otto::decryptString($cipherAndTag, $header, options: ['password' => 'P@ssw0rd!']);

// Streaming files (chunked)
Otto::encryptFile($inPath, $outPath, options: ['password' => 'P@ssw0rd!']);
Otto::decryptFile($inPath, $outPath, options: ['password' => 'P@ssw0rd!']);

// E2E using X25519 (recipient public key)
Otto::encryptFile('in.mov', 'in.mov.otto', options: ['recipient_public' => $recipientPkBase64]);

// E2E decryption using your X25519 secret (sender_secret)
Otto::decryptFile('in.mov.otto', 'in.mov', options: ['sender_secret' => $mySecretBase64]);
```

Key exchange helpers:

```php
use IvanSostarko\OttoCrypt\KeyExchange;

// Generate X25519 keypair
$pair = KeyExchange::generateKeypair();
$mySecret = $pair['secret']; // 32 bytes
$myPublic = $pair['public']; // 32 bytes (share with peers)

// Derive a session key from an ECDH shared secret
$shared = KeyExchange::deriveSharedSecret($mySecret, $theirPublic);
$sessionKey = KeyExchange::deriveSessionKey($shared, salt: '', context: 'OTTO-X25519-SESSION');
```

---

## Design & Format

### Construction: OTTO‑256‑GCM‑HKDF‑SIV

- Base AEAD: **AES‑256‑GCM** (OpenSSL). Tag length: 16 bytes.
- Master key sources:
  1) **Argon2id(password, pwSalt, opslimit, memlimit)** → 32‑byte master key  
  2) **Raw key** (exactly 32 bytes)  
  3) **X25519 ECDH** (ephemeral sender key + recipient public key) = shared secret → **HKDF** → 32‑byte master
- From the **master key** and a per‑file **file_salt**, we derive:
  - `enc_key  = HKDF(master, len=32, info="OTTO-ENC-KEY",  salt=file_salt)`
  - `nonce_key= HKDF(master, len=32, info="OTTO-NONCE-KEY", salt=file_salt)`
- **Nonces** are not random. For each chunk `i`, we derive:
  - `nonce_i = HKDF(nonce_key, len=12, info="OTTO-CHUNK-NONCE" || counter64be)`  
  This **deterministic (SIV‑style)** nonce avoids catastrophic failures if an app mistakenly reuses nonces.
- **Associated Data (AD)** for every encryption is the full **header**. Any change to header (algo ID, salts, KDF params, ephemeral key) invalidates decryption.

### Header layout

Binary header (fixed + variable):

```
magic      : "OTTO1" (5 bytes)
algo_id    : 0xA1            // AES-256-GCM + HKDF-SIV nonces
kdf_id     : 0x01=password | 0x02=raw key | 0x03=X25519
flags      : bit0=chunked
reserved   : 0x00
header_len : uint16 BE length of variable section (HVAR)
HVAR:
  file_salt  (16)
  if kdf=01 (password): pw_salt(16) + opslimit(uint32 BE) + memlimitKiB(uint32 BE)
  if kdf=03 (X25519):   eph_pubkey(32)
```

### Streaming/chunk format

For each plaintext chunk:
```
chunk_len : uint32 BE of ciphertext length
cipher    : N bytes (same as plain size)
tag       : 16 bytes (GCM tag)
```
Each chunk is independently AEAD‑protected with its own derived nonce and the header as AD.

### Key derivation

- **Argon2id** defaults (moderate work/memory) are configurable. Use strong passwords or password managers.
- **Raw 32‑byte keys** are accepted for systems that perform KDF externally.
- **X25519**: ephemeral sender secret/public and recipient public → `shared = scalarmult(sk_eph, pk_rcpt)` → `master = HKDF(shared, len=32, info="OTTO-E2E-MASTER", salt=file_salt)`.

### Nonce derivation (HKDF‑SIV style)

```
nonce_key  = HKDF(master, 32, info="OTTO-NONCE-KEY",  salt=file_salt)
enc_key    = HKDF(master, 32, info="OTTO-ENC-KEY",    salt=file_salt)
nonce(i)   = HKDF(nonce_key, 12, info="OTTO-CHUNK-NONCE" || counter64be, salt="")
```

This provides **deterministic** per‑chunk nonces without persisting counters externally and protects against app‑level nonce reuse mistakes.

### X25519 E2E mode

- **Sender**: generates **ephemeral** 32‑byte secret and publishes the corresponding public key in the header’s HVAR.
- **Recipient**: uses their **long‑term secret key** with sender’s ephemeral public to derive the same ECDH shared secret and then the same **master key** → `enc_key` + `nonce_key`.
- This gives **forward secrecy for sessions** (compromise of long‑term keys later does not reveal past sessions if ephemeral keys were erased).

---

## Configuration

`config/otto-crypt.php` (after publish):
```php
return [
    'chunk_size' => 1024 * 1024, // 1 MiB

    'argon' => [
        'opslimit' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        'memlimit' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
    ],
];
```

Tune Argon2id for your hardware. Larger memory/time improves password resistance at a performance cost.

---

## Comparison with other schemes

| Scheme | AEAD | Nonce strategy | Streaming | E2E Handshake | Notes |
|---|---|---|---|---|---|
| **OTTO‑256‑GCM‑HKDF‑SIV** | AES‑256‑GCM | **Deterministic HKDF‑SIV nonces** per chunk | **Yes** (chunked) | **X25519** (ephemeral) | Custom composition; audit recommended |
| AES‑256‑GCM (typical) | AES‑256‑GCM | Random/increment nonces (app‑managed) | App‑defined | App‑defined | Easy to misuse via nonce reuse |
| AES‑SIV (RFC 5297) | SIV (CMAC/HMAC) | Deterministic; misuse‑resistant | App‑defined | App‑defined | Slower; larger overhead; proven MR |
| ChaCha20‑Poly1305 | ChaCha20‑Poly1305 | App‑managed nonces | App‑defined | App‑defined | Great on non‑AES‑NI CPUs |
| libsodium secretstream | XChaCha20‑Poly1305 | Internal (stateful) | **Yes** | App‑defined | Excellent battle‑tested streaming API |

**Why OTTO?** You need:
- Laravel‑native streaming AEAD over AES‑GCM,
- Deterministic nonce derivation to reduce misuse risks, and
- Simple **E2E** with **X25519** baked in.

If you do **not** need AES or Laravel integration, consider **libsodium’s `crypto_secretstream`** (widely reviewed).

---

## Threat model & security notes

- **Provides** confidentiality + integrity (AEAD) for data at rest or in transit.
- **Resists** accidental nonce reuse (per‑chunk HKDF‑derived nonces).  
- **Does not** protect against endpoint compromise (malware/infostealers).
- **Password mode** security depends on password strength and Argon2id parameters. Prefer E2E keys for messengers.
- **Forward secrecy**: E2E mode uses **ephemeral** sender keys per session. Ensure ephemeral secrets are destroyed after use.
- **Randomness**: uses PHP/OpenSSL and libsodium PRNGs. Ensure the OS has good entropy.
- **Side‑channels**: standard OpenSSL AES‑GCM; this library does not attempt to harden against all timing/memory side channels.
- **Key erasure**: sensitive material is zeroed where feasible (`sodium_memzero`) after use, but ephemeral copies may exist in PHP/OPcache/streams.
- **Audit**: get a professional review before production. Treat current version as **pre‑audit**.

---

## Performance

- AES‑256‑GCM leverages **AES‑NI** when available (OpenSSL).  
- HKDF and Argon2id add CPU cost at session setup; chunk encryption is dominated by AES‑GCM.  
- Adjust `chunk_size` for throughput vs. memory usage (1–8 MiB is typical).

---




## Roadmap

- Unit/integration tests and test vectors.
- Optional **AEAD‑SIV** (RFC 5297) backend for fully standardized misuse resistance.
- Multi‑recipient E2E (encrypt same key to several recipients).
- Format versioning & negotiation.
- PHP FFI bindings for hardware engines (where available).

---

## FAQ

**Q: Is OTTO Crypt FIPS compliant?**  
A: It uses OpenSSL’s AES‑GCM and HKDF, which may be FIPS‑validated depending on your OpenSSL build, but the **overall construction is custom** and not a NIST‑standard scheme.

**Q: Can I rotate keys?**  
A: Yes. Re‑encrypt with a new recipient public key or password. The header binds parameters to ciphertext.

**Q: Why not random nonces?**  
A: Random or monotonic nonces are fine if implemented perfectly. Deterministic HKDF‑derived nonces help avoid catastrophic accidental reuse in complex streaming/parallel code.

**Q: Message vs file?**  
A: `encryptString` for small payloads; `encryptFile` for streaming large data (audio/video/files).

**Q: Does this replace libsodium secretstream?**  
A: No. If you can use libsodium’s `crypto_secretstream`, it’s excellent. OTTO focuses on AES‑GCM, Laravel integration, and simple E2E helper flows.

---

## Contributing

PRs welcome. Please include:
- Clear problem statement
- Tests (PHPUnit / Testbench)
- Security considerations for cryptographic changes

Before suggesting algorithmic changes, open an issue to discuss implications.

---

## License

MIT © 2025 Ivan Sostarko

---

## Responsible disclosure

If you discover a vulnerability, **do not open a public issue**. Email the maintainer privately (see `composer.json` author) with details and steps to reproduce. We’ll coordinate a fix and a responsible disclosure timeline.
