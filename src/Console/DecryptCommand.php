<?php
declare(strict_types=1);

namespace IvanSostarko\OttoCrypt\Console;

use Illuminate\Console\Command;
use IvanSostarko\OttoCrypt\OttoCrypt as Core;
use IvanSostarko\OttoCrypt\Facades\OttoCrypt as Otto;

class DecryptCommand extends Command
{
    protected $signature = 'otto:decrypt {input : Encrypted file path} {--out= : Output file path} {--password=} {--sender-secret=} {--raw-key=}';
    protected $description = 'Decrypt a file created by otto:encrypt.';

    public function handle(): int
    {
        $in = $this->argument('input');
        $out = $this->option('out') ?? (preg_replace('/\.otto$/', '', $in) ?: ($in . '.dec'));

        $options = [];
        if ($pw = $this->option('password')) {
            $options['password'] = $pw;
        }
        if ($sk = $this->option('sender-secret')) {
            $options['sender_secret'] = $sk;
        }
        if ($raw = $this->option('raw-key')) {
            $options['raw_key'] = base64_decode($raw, true) ?: hex2bin($raw) ?: $raw;
        }

        try {
            Otto::decryptFile($in, $out, $options);
        } catch (\Throwable $e) {
            $this->error('Decryption failed: ' . $e->getMessage());
            return self::FAILURE;
        }

        $this->info("Decrypted -> {$out}");
        return self::SUCCESS;
    }
}
