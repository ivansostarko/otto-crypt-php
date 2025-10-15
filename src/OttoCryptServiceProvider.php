<?php
declare(strict_types=1);

namespace IvanSostarko\OttoCrypt;

use Illuminate\Support\ServiceProvider;
use IvanSostarko\OttoCrypt\Console\EncryptCommand;
use IvanSostarko\OttoCrypt\Console\DecryptCommand;

class OttoCryptServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/config/otto-crypt.php', 'otto-crypt');

        $this->app->singleton('otto-crypt', function ($app) {
            return new OttoCrypt();
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/config/otto-crypt.php' => config_path('otto-crypt.php'),
            ], 'config');

            $this->commands([
                EncryptCommand::class,
                DecryptCommand::class,
            ]);
        }
    }
}
