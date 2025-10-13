<?php
declare(strict_types=1);

namespace IvanSostarko\OttoCrypt\Support;

final class HKDF
{
    public static function derive(string $ikm, int $length, string $info = '', string $salt = '', string $hash = 'sha256'): string
    {
        $prk = self::extract($ikm, $salt, $hash);
        return self::expand($prk, $info, $length, $hash);
    }

    public static function extract(string $ikm, string $salt = '', string $hash = 'sha256'): string
    {
        if ($salt === '') {
            $salt = str_repeat("\x00", strlen(hash($hash, '', true)));
        }
        return hash_hmac($hash, $ikm, $salt, true);
    }

    public static function expand(string $prk, string $info, int $length, string $hash = 'sha256'): string
    {
        $hashLen = strlen(hash($hash, '', true));
        $n = (int)ceil($length / $hashLen);
        $okm = '';
        $t = '';
        for ($i = 1; $i <= $n; $i++) {
            $t = hash_hmac($hash, $t . $info . chr($i), $prk, true);
            $okm .= $t;
        }
        return substr($okm, 0, $length);
    }
}
