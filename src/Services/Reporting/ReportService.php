<?php

namespace User\CustomAudit\Services\Reporting;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;
use Illuminate\Console\Command;

class ReportService
{
    protected Command $command;
    protected array $allFindings = [];
    protected array $filteredFindings = [];
    protected string $reportSeverityThreshold;
    protected ?string $failSeverityThreshold = null;
    protected array $severityOrder = [
        
'critical
' => 4,
        
'high
' => 3,
        
'medium
' => 2,
        
'low
' => 1,
        
'unknown
' => 0, // Should unknown severity be reported/fail?
    ];

    public function __construct(Command $command)
    {
        $this->command = $command;
        $this->reportSeverityThreshold = Config::get(
'custom-audit.report_severity_threshold
', 
'high
');
        $this->failSeverityThreshold = Config::get(
'custom-audit.fail_on_severity
');
    }

    public function addFindings(array $findings): void
    {
        $this->allFindings = array_merge($this->allFindings, $findings);
    }

    public function generateReport(): void
    {
        $this->filterFindings();

        if (empty($this->filteredFindings)) {
            $this->command->info(
'✅ No vulnerabilities found matching the severity threshold (
' . $this->reportSeverityThreshold . 
').
');
            return;
        }

        $this->command->warn(
'🚨 Vulnerabilities found:
');

        $headers = [
'Severity
', 
'Package
', 
'CVE
', 
'Title
', 
'Affected Versions
', 
'Link
', 
'Explanation (AI)
', 
'Custom Info
'];
        $rows = [];

        // Sort by severity
        usort($this->filteredFindings, function ($a, $b) {
            $sevA = $this->severityOrder[$a[
'severity
'] ?? 
'unknown
'] ?? 0;
            $sevB = $this->severityOrder[$b[
'severity
'] ?? 
'unknown
'] ?? 0;
            return $sevB <=> $sevA; // Higher severity first
        });

        foreach ($this->filteredFindings as $finding) {
            $rows[] = [
                strtoupper($finding[
'severity
'] ?? 
'unknown
'),
                $finding[
'package_name
'] ?? 
'N/A
',
                $finding[
'cve
'] ?? 
'N/A
',
                $this->truncate($finding[
'title
'] ?? 
'N/A
'),
                $finding[
'affected_versions
'] ?? 
'N/A
',
                $finding[
'link
'] ?? 
'N/A
',
                $this->truncate($finding[
'explanation
'] ?? 
'N/A
'),
                $this->formatCustomInfo($finding[
'custom_info
'] ?? null),
            ];
        }

        $this->command->table($headers, $rows);

        // Send notifications if not in silent mode
        if (!$this->command->option(
'silent
')) {
            $this->sendNotifications();
        }
    }

    protected function filterFindings(): void
    {
        $thresholdLevel = $this->severityOrder[$this->reportSeverityThreshold] ?? 0;
        $this->filteredFindings = array_filter($this->allFindings, function ($finding) use ($thresholdLevel) {
            $findingLevel = $this->severityOrder[$finding[
'severity
'] ?? 
'unknown
'] ?? 0;
            return $findingLevel >= $thresholdLevel;
        });
    }

    protected function truncate(string $text, int $length = 50): string
    {
        if (strlen($text) > $length) {
            return substr($text, 0, $length - 3) . 
'...
';
        }
        return $text;
    }

    protected function formatCustomInfo(?array $customInfo): string
    {
        if (empty($customInfo)) {
            return 
'N/A
';
        }
        // Extract key details from the custom info based on user structure
        $details = [];
        if (isset($customInfo[
'vuln_status
'])) $details[] = 
'Status: 
' . $customInfo[
'vuln_status
'];
        if (isset($customInfo[
'ai_solution
'])) $details[] = 
'Solution Hint: 
' . $this->truncate($customInfo[
'ai_solution
']);
        // Add more fields as needed

        return implode(
' | 
', $details);
    }

    protected function sendNotifications(): void
    {
        $webhookUrl = Config::get(
'custom-audit.notifications.webhook_url
');

        if ($webhookUrl && !empty($this->filteredFindings)) {
            try {
                $payload = [
                    
'text
' => 
'🚨 Custom Audit Found Vulnerabilities (
' . count($this->filteredFindings) . 
')
',
                    // Add more structured data if the webhook expects it (e.g., Slack blocks)
                    
'attachments
' => [
                        [
                            
'title
' => 
'Vulnerability Summary
',
                            
'text
' => $this->formatFindingsForNotification(),
                            
'color
' => 
'danger
' // Example color for Slack
                        ]
                    ]
                ];

                Http::post($webhookUrl, $payload);
                $this->command->info(
'Webhook notification sent.
');

            } catch (\Exception $e) {
                Log::error(
'Failed to send webhook notification: 
' . $e->getMessage());
                $this->command->error(
'Failed to send webhook notification.
');
            }
        }

        // Add email notification logic here if needed in the future
    }

    protected function formatFindingsForNotification(): string
    {
        $lines = [];
        foreach ($this->filteredFindings as $finding) {
            $lines[] = sprintf(
"[%s] %s (%s) - %s"
,
                strtoupper($finding[
'severity
'] ?? 
'unknown
'),
                $finding[
'package_name
'] ?? 
'N/A
',
                $finding[
'cve
'] ?? 
'N/A
',
                $finding[
'title
'] ?? 
'N/A
'
            );
        }
        return implode("\n", $lines);
    }

    public function shouldFailBuild(): bool
    {
        if ($this->failSeverityThreshold === null || !isset($this->severityOrder[$this->failSeverityThreshold])) {
            return false; // Failure based on severity is disabled or misconfigured
        }

        $failLevel = $this->severityOrder[$this->failSeverityThreshold];

        foreach ($this->filteredFindings as $finding) {
            $findingLevel = $this->severityOrder[$finding[
'severity
'] ?? 
'unknown
'] ?? 0;
            if ($findingLevel >= $failLevel) {
                return true; // Found a vulnerability at or above the failure threshold
            }
        }

        return false;
    }

     public function getFilteredFindings(): array
     {
        return $this->filteredFindings;
     }
}

