<?php

namespace CyberSentry\Services;

use Symfony\Component\Process\Process;

class ComposerAuditService
{
    public function audit(): array
    {
        $process = new Process(['composer', 'audit', '--format=json']);
        $process->run();

        if ($process->getExitCode() === 0) {
            return []; // No vulnerabilities found
        }

        $output = $process->getOutput();

        if (empty($output)) {
            throw new \RuntimeException('Failed to get composer audit output');
        }

        return $this->parseComposerAuditOutput($output);
    }

    private function parseComposerAuditOutput(string $output): array
    {
        $data = json_decode($output, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException('Failed to parse composer audit JSON output');
        }

        $vulnerabilities = [];

        if (!isset($data['advisories'])) {
            return $vulnerabilities;
        }

        foreach ($data['advisories'] as $packageName => $advisories) {
            foreach ($advisories as $advisory) {
                $vulnerabilities[] = $this->mapAdvisoryToVulnerability($packageName, $advisory);
            }
        }

        return $vulnerabilities;
    }

    private function mapAdvisoryToVulnerability(string $packageName, array $advisory): array
    {
        return [
            'package' => $packageName,
            'cve' => $advisory['cve'] ?? $advisory['advisoryId'] ?? 'N/A',
            'title' => $advisory['title'] ?? 'Unknown vulnerability',
            'severity' => $this->normalizeSeverity($advisory['severity'] ?? 'unknown'),
            'affected_versions' => $advisory['affectedVersions'] ?? 'Unknown',
            'link' => $advisory['link'] ?? null,
            'reported_at' => $advisory['reportedAt'] ?? null,
            'sources' => $advisory['sources'] ?? [],
        ];
    }

    private function normalizeSeverity(string $severity): string
    {
        return match(strtolower($severity)) {
            'critical' => 'critical',
            'high' => 'high',
            'medium', 'moderate' => 'medium',
            'low', 'minor' => 'low',
            default => 'unknown'
        };
    }
}