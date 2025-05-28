<?php

namespace User\CustomAudit\Services\Audits;

use User\CustomAudit\Contracts\AuditServiceInterface;
use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Illuminate\Support\Facades\Log;

class NpmAuditService implements AuditServiceInterface
{
    protected string $name = 'NPM';
    protected array $findings = [];
    protected ?string $errorMessage = null;
    protected string $projectPath;

    public function __construct(string $projectPath = null)
    {
        // Default to the base path of the Laravel application if not provided
        $this->projectPath = $projectPath ?? base_path();
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function run(): bool
    {
        $this->findings = [];
        $this->errorMessage = null;

        // Check if npm is installed
        $checkProcess = new Process(["npm", "--version"]);
        try {
            $checkProcess->mustRun();
        } catch (ProcessFailedException $exception) {
            $this->errorMessage = 'npm command not found or failed. Please ensure Node.js and npm are installed and accessible.';
            Log::error($this->errorMessage);
            return false;
        }

        // Ensure package-lock.json exists
        if (!file_exists($this->projectPath . '/package-lock.json')) {
            $this->errorMessage = 'package-lock.json not found in ' . $this->projectPath . '. Cannot run NPM audit.';
            Log::warning($this->errorMessage); // Warning as it might be intentional
            return true; // Technically didn't fail, just nothing to audit
        }

        $command = [
            'npm',
            'audit',
            '--json',
            // npm audit runs in the current directory by default, need to execute in project path
        ];

        // Use cwd option for Process
        $process = new Process($command, $this->projectPath);

        try {
            // Increase timeout for potentially long-running audit
            $process->setTimeout(300);
            $process->run(); // Use run() instead of mustRun() as npm audit returns non-zero exit code for vulnerabilities

            $output = $process->getOutput();
            $errorOutput = $process->getErrorOutput();

            // Check if the process was successful or failed due to vulnerabilities
            if (!$process->isSuccessful() && empty($output)) {
                 // If output is empty and process failed, it's likely a real error
                 throw new ProcessFailedException($process);
            }
            
            // If output is present, try parsing even if exit code is non-zero
            if (!empty($output)) {
                 $this->findings = $this->parseOutput($output);
            } else {
                // Handle cases where npm might output errors to stderr but no JSON to stdout
                if (!empty($errorOutput)) {
                    $this->errorMessage = 'NPM audit completed with errors: ' . $errorOutput;
                    Log::error($this->errorMessage);
                    // Decide if this constitutes a failure based on error content if needed
                }
                // If no output and no significant error, assume no vulnerabilities
                $this->findings = [];
            }

            return true; // Considered successful run even if vulnerabilities found

        } catch (ProcessFailedException $exception) {
            $this->errorMessage = 'NPM audit command failed: ' . $exception->getMessage();
            Log::error($this->errorMessage, ['output' => $exception->getProcess()->getOutput(), 'error_output' => $exception->getProcess()->getErrorOutput()]);
            $this->findings = [];
            return false;
        } catch (\JsonException $jsonException) {
            // Handle cases where output wasn't valid JSON
            $this->errorMessage = 'NPM audit output could not be parsed as JSON: ' . $jsonException->getMessage();
            Log::error($this->errorMessage, ['output' => $output ?? 'N/A']);
            $this->findings = [];
            return false;
        } catch (\Exception $e) {
            $this->errorMessage = 'An unexpected error occurred during NPM audit: ' . $e->getMessage();
            Log::error($this->errorMessage);
            $this->findings = [];
            return false;
        }
    }

    protected function parseOutput(string $output): array
    {
        $decoded = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        // Structure: {"vulnerabilities": {"package_name": {"name": ..., "severity": ..., "via": [...], "effects": [...], "range": ..., "nodes": [...], "fixAvailable": ...}}}
        // Or sometimes {"advisories": {"advisory_id": {...}}}
        
        $vulnerabilities = [];
        if (isset($decoded['vulnerabilities'])) {
            foreach ($decoded['vulnerabilities'] as $packageName => $details) {
                 $vulnerabilities[] = [
                    'audit_type' => $this->getName(),
                    'package_name' => $details['name'] ?? $packageName,
                    'title' => $this->generateTitle($details), // NPM JSON doesn't have a simple title
                    'cve' => $this->findCve($details['via'] ?? []), // CVE might be nested
                    'link' => $this->findLink($details['via'] ?? []), // Link might be nested
                    'affected_versions' => $details['range'] ?? 'N/A',
                    'severity' => $details['severity'] ?? 'unknown',
                    'fix_available' => $details['fixAvailable'] ? ($details['fixAvailable']['name'] . '@' . $details['fixAvailable']['version']) : false,
                    'raw_data' => $details // Keep raw data
                ];
            }
        } elseif (isset($decoded['advisories'])) {
             foreach ($decoded['advisories'] as $advisoryId => $details) {
                 $vulnerabilities[] = [
                    'audit_type' => $this->getName(),
                    'package_name' => $details['module_name'] ?? 'N/A',
                    'title' => $details['title'] ?? 'N/A',
                    'cve' => $details['cves'][0] ?? null, // Take the first CVE if available
                    'link' => $details['url'] ?? null,
                    'affected_versions' => $details['vulnerable_versions'] ?? 'N/A',
                    'severity' => $details['severity'] ?? 'unknown',
                    'fix_available' => $details['patched_versions'] ?? false, // Different structure
                    'raw_data' => $details // Keep raw data
                ];
            }
        }

        return $vulnerabilities;
    }
    
    // Helper to generate a title if one isn't directly available
    protected function generateTitle(array $details): string
    {
        if (!empty($details['via']) && is_array($details['via'])) {
            $sources = array_map(function($item) {
                return is_string($item) ? $item : ($item['title'] ?? $item['name'] ?? null);
            }, $details['via']);
            $sources = array_filter($sources);
            if (!empty($sources)) {
                return implode(', ', $sources);
            }
        }
        return $details['name'] ?? 'Unknown Vulnerability';
    }

    // Helper to find CVE if nested in 'via'
    protected function findCve(array $via): ?string
    {
        foreach ($via as $item) {
            if (is_array($item) && !empty($item['cve'])) {
                return $item['cve'];
            }
            // Look for CVE patterns in URLs or titles if direct field is missing
            if (is_array($item) && !empty($item['url']) && preg_match('/(CVE-\d{4}-\d{4,})/i', $item['url'], $matches)) {
                return $matches[1];
            }
             if (is_array($item) && !empty($item['title']) && preg_match('/(CVE-\d{4}-\d{4,})/i', $item['title'], $matches)) {
                return $matches[1];
            }
        }
        return null;
    }
    
     // Helper to find Link if nested in 'via'
    protected function findLink(array $via): ?string
    {
        foreach ($via as $item) {
            if (is_array($item) && !empty($item['url'])) {
                return $item['url'];
            }
        }
        return null;
    }

    public function getFindings(): array
    {
        // Already formatted in parseOutput
        return $this->findings;
    }

    public function handleFailure(): void
    {
        Log::error("NPM Audit Service failed: " . $this->errorMessage);
    }

    public function getErrorMessage(): ?string
    {
        return $this->errorMessage;
    }
}

