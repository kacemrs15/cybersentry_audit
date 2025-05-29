<?php

namespace CyberSentry;

use CyberSentry\Commands\AuditCommand;
use CyberSentry\Services\CveApiService;
use CyberSentry\Services\ComposerAuditService;
use CyberSentry\Services\NotificationService;
use Illuminate\Support\ServiceProvider;

class CyberSentryServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/cybersentry.php', 'cybersentry');

        $this->app->singleton(CveApiService::class, function ($app) {
            return new CveApiService(
                config('cybersentry.api.base_url'),
                config('cybersentry.api.api_key')
            );
        });

        $this->app->singleton(ComposerAuditService::class);
        $this->app->singleton(NotificationService::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/cybersentry.php' => config_path('cybersentry.php'),
            ], 'cybersentry-config');

            $this->commands([
                AuditCommand::class,
            ]);
        }
    }
}