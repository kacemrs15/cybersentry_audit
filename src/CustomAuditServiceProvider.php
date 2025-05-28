<?php

namespace User\CustomAudit;

use Illuminate\Support\ServiceProvider;
use User\CustomAudit\Commands\RunAuditCommand;
use User\CustomAudit\Contracts\AuditServiceInterface;
use User\CustomAudit\Services\Audits\ComposerAuditService;
use User\CustomAudit\Services\Audits\NpmAuditService;
use User\CustomAudit\Contracts\VulnerabilityDataProviderInterface;
use User\CustomAudit\Services\DataProviders\OpenAiDataProvider;
use User\CustomAudit\Services\DataProviders\CustomCveApiDataProvider;

class CustomAuditServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register(): void
    {
        // Merge configuration
        $this->mergeConfigFrom(
            __DIR__ . '/../config/custom-audit.php', 
            'custom-audit'
        );

        // Bind services to the container (optional, but good practice for testability/swapping implementations)
        // Example binding (can be more specific if needed)
        $this->app->bind(ComposerAuditService::class, function ($app) {
            // Allow path override if needed, though command handles it now
            return new ComposerAuditService(); 
        });

        $this->app->bind(NpmAuditService::class, function ($app) {
            return new NpmAuditService();
        });

        // Bind data providers - could use tagged binding if more providers are expected
        $this->app->bind(OpenAiDataProvider::class, function ($app) {
            return new OpenAiDataProvider();
        });

        $this->app->bind(CustomCveApiDataProvider::class, function ($app) {
            return new CustomCveApiDataProvider();
        });

        // Register the Artisan command
        $this->commands([
            RunAuditCommand::class,
        ]);
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot(): void
    {
        // Publish configuration file
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/custom-audit.php' => config_path('custom-audit.php'),
            ], 'custom-audit-config');
        }

        // Add other boot logic if needed (e.g., loading routes, views, migrations)
    }
}

