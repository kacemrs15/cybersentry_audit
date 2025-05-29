<?php

namespace CyberSentry\Commands;

use CyberSentry\Services\ComposerAuditService;
use CyberSentry\Services\CveApiService;
use CyberSentry\Services\NotificationService;
use Illuminate\Console\Command;

class AuditCommand extends Command
{
    protected $signature = 'cybersentry:audit 
                           {--silent : Run audit without output}
                           {--no-ai : Skip AI analysis}
                           {--format=table : Output format (table, json)}';

    protected $description = 'Audit Composer dependencies for vulnerabilities with AI-powered explanations';

    public function __construct(
        private ComposerAuditService $auditService,
        private CveApiService $cveApiService,
        private NotificationService $notificationService
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        if (!$this->option('silent')) {
            $this->info('🔍 Starting CyberSentry security audit...');
        }

        try {
            // Run composer audit
            $vulnerabilities = $this->auditService->audit();

            if (empty($vulnerabilities)) {
                if (!$this->option('silent')) {
                    $this->info('✅ No vulnerabilities found!');
                }
                return 0;
            }

            // Enrich vulnerabilities with AI analysis
            if (!$this->option('no-ai') && config('cybersentry.audit.include_ai_analysis')) {
                $vulnerabilities = $this->enrichWithAiAnalysis($vulnerabilities);
            }

            // Display results
            if (!$this->option('silent')) {
                $this->displayResults($vulnerabilities);
            }

            // Send notifications
            $this->notificationService->notify($vulnerabilities);

            // Determine exit code
            $shouldFail = config('cybersentry.audit.fail_on_vulnerabilities') &&
                $this->hasVulnerabilitiesAboveThreshold($vulnerabilities);

            return $shouldFail ? 1 : 0;

        } catch (\Exception $e) {
            if (!$this->option('silent')) {
                $this->error('❌ Audit failed: ' . $e->getMessage());
            }
            return 2;
        }
    }

    private function enrichWithAiAnalysis(array $vulnerabilities): array
    {
        if (!$this->option('silent')) {
            $this->info('🤖 Enriching vulnerabilities with AI analysis...');
        }

        foreach ($vulnerabilities as &$vulnerability) {
            try {
                $aiData = $this->cveApiService->getAiAnalysis($vulnerability['cve']);
                $vulnerability['ai_explanation'] = $aiData['explanation'] ?? null;
                $vulnerability['ai_solution'] = $aiData['solution'] ?? null;
                $vulnerability['ai_risk_assessment'] = $aiData['risk_assessment'] ?? null;
            } catch (\Exception $e) {
                if (!$this->option('silent')) {
                    $this->warn("Failed to get AI analysis for {$vulnerability['cve']}: {$e->getMessage()}");
                }
            }
        }

        return $vulnerabilities;
    }

    private function displayResults(array $vulnerabilities): void
    {
        if ($this->option('format') === 'json') {
            $this->line(json_encode($vulnerabilities, JSON_PRETTY_PRINT));
            return;
        }

        $this->error("🚨 Found " . count($vulnerabilities) . " vulnerabilities:");
        $this->newLine();

        foreach ($vulnerabilities as $vuln) {
            $this->displayVulnerability($vuln);
        }
    }

    private function displayVulnerability(array $vuln): void
    {
        $severityColor = match($vuln['severity']) {
            'critical' => 'red',
            'high' => 'yellow',
            'medium' => 'blue',
            default => 'gray'
        };

        $this->line("<fg={$severityColor}>📦 Package:</> {$vuln['package']}");
        $this->line("<fg={$severityColor}>🔗 CVE:</> {$vuln['cve']}");
        $this->line("<fg={$severityColor}>⚠️  Severity:</> {$vuln['severity']}");
        $this->line("<fg={$severityColor}>📋 Title:</> {$vuln['title']}");

        if (!empty($vuln['affected_versions'])) {
            $this->line("<fg={$severityColor}>📌 Affected versions:</> {$vuln['affected_versions']}");
        }

        if (!empty($vuln['ai_explanation'])) {
            $this->newLine();
            $this->line("<fg=cyan>🤖 AI Explanation:</>");
            $this->line($this->wrapText($vuln['ai_explanation'], 2));
        }

        if (!empty($vuln['ai_solution'])) {
            $this->newLine();
            $this->line("<fg=green>💡 AI Solution:</>");
            $this->line($this->wrapText($vuln['ai_solution'], 2));
        }

        if (!empty($vuln['ai_risk_assessment'])) {
            $this->newLine();
            $this->line("<fg=magenta>🎯 Risk Assessment:</>");
            $this->line($this->wrapText($vuln['ai_risk_assessment'], 2));
        }

        $this->line('─────────────────────────────────────────────────');
        $this->newLine();
    }

    private function wrapText(string $text, int $indent = 0): string
    {
        $prefix = str_repeat(' ', $indent);
        return $prefix . wordwrap($text, 78 - $indent, "\n{$prefix}");
    }

    private function hasVulnerabilitiesAboveThreshold(array $vulnerabilities): bool
    {
        $threshold = config('cybersentry.audit.severity_threshold', 'low');
        $severityLevels = ['low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
        $thresholdLevel = $severityLevels[$threshold] ?? 1;

        foreach ($vulnerabilities as $vuln) {
            $vulnLevel = $severityLevels[$vuln['severity']] ?? 1;
            if ($vulnLevel >= $thresholdLevel) {
                return true;
            }
        }

        return false;
    }
}