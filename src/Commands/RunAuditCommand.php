<?php

namespace User\CustomAudit\Commands;

use Illuminate\Console\Command;
use User\CustomAudit\Services\Audits\ComposerAuditService;
use User\CustomAudit\Services\Audits\NpmAuditService;
use User\CustomAudit\Services\DataProviders\OpenAiDataProvider;
use User\CustomAudit\Services\DataProviders\CustomCveApiDataProvider;
use User\CustomAudit\Services\DataProviders\ComposerAuditDataProvider; // Added
use User\CustomAudit\Contracts\ComposerVulnerabilityDataProviderInterface; // Added
use User\CustomAudit\Contracts\VulnerabilityEnrichmentProviderInterface; // Added
use User\CustomAudit\Services\Reporting\ReportService;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Exception;

class RunAuditCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 
        'custom-audit:run
            {--npm : Include NPM audit even if not enabled in config}
            {--composer : Force Composer audit (useful if only npm is default)}
            {--source= : Override Composer data source (composer_audit|custom_cve_api)}
            {--severity= : Minimum severity level to report (overrides config)}
            {--fail-severity= : Minimum severity level to cause failure (overrides config)}
            {--silent : Suppress notifications}
            {--path= : Specify the project path to audit (defaults to base_path())}
            {--skip-openai : Skip fetching explanations from OpenAI}
            {--skip-custom-cve : Skip fetching data from Custom CVE API (Note: This now primarily controls enrichment if custom API is *not* the source)}
        ';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 
        'Run Composer and/or NPM dependency audits with vulnerability explanations and custom CVE data.';

    protected ReportService $reportService;
    protected array $enrichmentProviders = [];
    protected string $projectPath;

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        // Apply config overrides from options *before* services are instantiated
        $this->configureThresholds();

        $this->reportService = new ReportService($this);
        $this->projectPath = $this->option('path') ?? base_path();

        $this->info("Starting dependency audit for path: {$this->projectPath}");

        // Initialize Enrichment Providers first (e.g., OpenAI)
        $this->initializeEnrichmentProviders();

        // Determine which audits to run
        $enabledAudits = Config::get('custom-audit.enabled_audits', ['composer']);
        $runComposer = in_array('composer', $enabledAudits) || $this->option('composer');
        $runNpm = (in_array('npm', $enabledAudits) || $this->option('npm'));

        $overallSuccess = true;

        // Run Composer Audit
        if ($runComposer) {
            $this->line("Running Composer audit...");
            try {
                $composerDataProvider = $this->resolveComposerDataProvider();
                $composerAudit = new ComposerAuditService($composerDataProvider, $this->projectPath);
                
                if ($composerAudit->run()) {
                    $findings = $this->enrichFindings($composerAudit->getFindings());
                    $this->reportService->addFindings($findings, 'Composer'); // Add source type
                    $this->line("Composer audit completed.");
                } else {
                    $this->error("Composer audit failed: " . $composerAudit->getErrorMessage());
                    $overallSuccess = false;
                }
            } catch (Exception $e) {
                 $this->error("Error initializing or running Composer audit: " . $e->getMessage());
                 Log::error('Composer audit initialization/run error', ['exception' => $e]);
                 $overallSuccess = false;
            }
        }

        // Run NPM Audit
        if ($runNpm) {
            $this->line("Running NPM audit...");
            $npmAudit = new NpmAuditService($this->projectPath); // NPM audit is simpler, no provider selection needed
            if ($npmAudit->run()) {
                // NPM audit output structure might differ, needs standardization or separate handling in ReportService
                // For now, assume enrichFindings can handle it or needs adjustment
                $findings = $this->enrichFindings($npmAudit->getFindings()); 
                $this->reportService->addFindings($findings, 'NPM'); // Add source type
                $this->line("NPM audit completed.");
            } else {
                $this->error("NPM audit failed: " . $npmAudit->getErrorMessage());
                // Decide if NPM failure should fail the whole command
                // $overallSuccess = false; 
            }
        }

        if (!$runComposer && !$runNpm) {
            $this->warn("No audits were enabled or selected to run.");
            return Command::SUCCESS;
        }

        // Generate Report
        $this->reportService->generateReport();

        // Determine Exit Code
        if (!$overallSuccess) {
            return Command::FAILURE; // Indicate a general failure during execution
        }

        // Check if build should fail based on severity
        if ($this->reportService->shouldFailBuild()) {
            $this->error("Audit failed due to vulnerabilities exceeding the configured severity threshold (" . $this->reportService->getFailSeverityThreshold() . ").");
            return Command::FAILURE; // Indicate failure due to found vulnerabilities
        }

        $this->info("Audit finished successfully.");
        return Command::SUCCESS;
    }

    /**
     * Resolve the Composer vulnerability data provider based on configuration/options.
     */
    protected function resolveComposerDataProvider(): ComposerVulnerabilityDataProviderInterface
    {
        $source = $this->option('source') ?? Config::get('custom-audit.composer_data_source', 'composer_audit');

        $this->line("Using Composer data source: {$source}");

        switch ($source) {
            case 'custom_cve_api':
                if (!Config::get('custom-audit.custom_cve_api.enabled', false) || !Config::get('custom-audit.custom_cve_api.url')) {
                     throw new Exception('Custom CVE API selected as source, but it is not enabled or configured properly.');
                }
                // Potentially inject dependencies if needed
                return new CustomCveApiDataProvider(); 
            case 'composer_audit':
            default:
                 // Potentially inject dependencies if needed
                return new ComposerAuditDataProvider();
        }
    }

    /**
     * Initialize enrichment providers (like OpenAI).
     */
    protected function initializeEnrichmentProviders(): void
    {
        $this->enrichmentProviders = []; // Reset
        if (!$this->option('skip-openai') && Config::get('custom-audit.openai.enabled', false)) {
            $this->enrichmentProviders[] = new OpenAiDataProvider();
        }
        // Potentially add Custom CVE API as an *enrichment* provider if it wasn't the primary source
        // And if the skip-custom-cve flag is not set
        $source = $this->option('source') ?? Config::get('custom-audit.composer_data_source', 'composer_audit');
        if ($source !== 'custom_cve_api' && !$this->option('skip-custom-cve') && Config::get('custom-audit.custom_cve_api.enabled', false)) {
             // Check if CustomCveApiDataProvider implements VulnerabilityEnrichmentProviderInterface
             $customProvider = new CustomCveApiDataProvider();
             if ($customProvider instanceof VulnerabilityEnrichmentProviderInterface) {
                 $this->enrichmentProviders[] = $customProvider;
             }
        }
    }

    /**
     * Enrich findings using the initialized enrichment providers.
     *
     * @param array $findings Raw findings from an audit service (e.g., {"advisories": ...} or similar)
     * @return array Enriched findings
     */
    protected function enrichFindings(array $findings): array
    {
        if (empty($this->enrichmentProviders) || empty($findings) || !isset($findings['advisories'])) {
            return $findings; // No providers or no findings to enrich
        }

        $this->line("Enriching findings with external data...");
        
        $totalAdvisories = 0;
        foreach ($findings['advisories'] as $packageName => $advisories) {
             $totalAdvisories += count($advisories);
        }
        
        if ($totalAdvisories === 0) {
             $this->line("No advisories found to enrich.");
             return $findings;
        }

        $progressBar = $this->output->createProgressBar($totalAdvisories);
        $progressBar->start();

        $enrichedFindings = ['advisories' => []];

        foreach ($findings['advisories'] as $packageName => $advisories) {
            if (!isset($enrichedFindings['advisories'][$packageName])) {
                 $enrichedFindings['advisories'][$packageName] = [];
            }
            foreach ($advisories as $advisory) {
                $enrichedAdvisory = $advisory; // Start with original data
                
                foreach ($this->enrichmentProviders as $provider) {
                    try {
                        // Attempt to get explanation (e.g., from OpenAI)
                        if (!isset($enrichedAdvisory['explanation']) || is_null($enrichedAdvisory['explanation'])) {
                             if ($provider instanceof OpenAiDataProvider) { // Be specific about provider type for clarity
                                 $explanation = $provider->getExplanation($enrichedAdvisory);
                                 if ($explanation) {
                                     $enrichedAdvisory['explanation'] = $explanation;
                                 }
                             }
                        }
                        
                        // Attempt to get custom info (e.g., from Custom CVE API if used for enrichment)
                         if (!isset($enrichedAdvisory['custom_info']) || is_null($enrichedAdvisory['custom_info'])) {
                             if ($provider instanceof CustomCveApiDataProvider && !empty($enrichedAdvisory['cve'])) {
                                 $customInfo = $provider->getCustomCveInfo($enrichedAdvisory['cve']);
                                 if ($customInfo) {
                                     $enrichedAdvisory['custom_info'] = $customInfo;
                                 }
                             }
                         }

                    } catch (Exception $e) {
                        Log::warning('Enrichment provider failed.', [
                            'provider' => get_class($provider),
                            'package' => $packageName,
                            'advisory_title' => $advisory['title'] ?? 'N/A',
                            'exception' => $e->getMessage(),
                        ]);
                    }
                }
                $enrichedFindings['advisories'][$packageName][] = $enrichedAdvisory;
                $progressBar->advance();
            }
        }

        $progressBar->finish();
        $this->output->newLine();

        return $enrichedFindings;
    }

    /**
     * Override severity thresholds from config if command options are provided.
     */
    protected function configureThresholds(): void
    {
        if ($severity = $this->option('severity')) {
            Config::set('custom-audit.report_severity_threshold', $severity);
        }
        if ($failSeverity = $this->option('fail-severity')) {
            Config::set('custom-audit.fail_on_severity', $failSeverity);
        }
        // ReportService will read these from Config when instantiated or via setters
    }

    /**
     * Override the constructor to potentially configure thresholds before ReportService is needed.
     * NOTE: We moved threshold setting before ReportService instantiation in handle().
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     * We override this primarily to ensure config overrides happen early.
     *
     * @param \Symfony\Component\Console\Input\InputInterface $input
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     * @return int
     */
    public function execute(
        \Symfony\Component\Console\Input\InputInterface $input,
        \Symfony\Component\Console\Output\OutputInterface $output
    ): int
    {
        // This override might not be strictly necessary anymore since handle() applies overrides first.
        // Keeping it doesn't hurt, but ensures overrides happen before *any* service resolution potentially triggered by execute().
        $this->configureThresholds(); 
        return parent::execute($input, $output);
    }
}

