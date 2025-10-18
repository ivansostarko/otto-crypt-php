<?php

return [
    // Default chunk size for streaming (in bytes). 1 MiB.
    'chunk_size' => 1024 * 1024,

    // Argon2id defaults (tuned for servers; adjust as needed).
    'argon' => [
        'opslimit' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        'memlimit' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
    ],
];
