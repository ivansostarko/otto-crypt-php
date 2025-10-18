<?php
declare(strict_types=1);

namespace IvanSostarko\OttoCrypt\Facades;

use Illuminate\Support\Facades\Facade;

class OttoCrypt extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'otto-crypt';
    }
}
