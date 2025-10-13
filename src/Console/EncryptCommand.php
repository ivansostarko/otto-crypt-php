<?php
declare(strict_types=1);

namespace IvanSostarko\OttoCrypt\Console;

use Illuminate\Console\Command;
use IvanSostarko\OttoCrypt\Facades\OttoCrypt as Otto;

class EncryptCommand extends Command
{
    protected $signature = 'otto:encrypt {input : Input file path} {--out= : Output file path} {--password=} {--recipient=} {--raw-key=}';
    protected $description = 'Encrypt a file with OTTO Crypt (AES-256-GCM + HKDF-SIV style, streaming).';

    public function handle(): int
    {
        $in = $this->argument('input');
        $out = $this->option('out') ?? ($in . '.otto');

        $options = [];
        if ($pw = $this->option('password')) {
            $options['password'] = $pw;
        }
        if ($rcpt = $this->option('recipient')) {
            $options['recipient_public'] = $rcpt;
        }
        if ($raw = $this->option('raw-key')) {
            $options['raw_key'] = base64_decode($raw, true) ?: hex2bin($raw) ?: $raw;
        }

        try {
            Otto::encryptFile($in, $out, $options);
        } catch (\Throwable $e) {
            $this->error('Encryption failed: ' . $e->getMessage());
            return self::FAILURE;
        }

        $this->info("Encrypted -> {$out}");
        return self::SUCCESS;
    }
}
