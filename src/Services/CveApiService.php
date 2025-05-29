<?php

namespace CyberSentry\Services;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Facades\Cache;

class CveApiService
{
    private Client $client;
    private string $baseUrl;
    private string $apiKey;

    public function __construct(string $baseUrl, string $apiKey)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->apiKey = $apiKey;

        $this->client = new Client([
            'timeout' => config('cybersentry.api.timeout', 30),
            'headers' => [
                'Authorization' => 'Bearer ' . $this->apiKey,
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
            ],
        ]);
    }

    /**
     * Get AI analysis for a specific CVE
     */
    public function getAiAnalysis(string $cveId): array
    {
        $cacheKey = "cybersentry.cve.{$cveId}";

        return Cache::remember($cacheKey, now()->addHours(24), function () use ($cveId) {
            return $this->fetchAiAnalysis($cveId);
        });
    }

    /**
     * Get bulk AI analysis for multiple CVEs
     */
    public function getBulkAiAnalysis(array $cveIds): array
    {
        try {
            $response = $this->client->post($this->baseUrl . '/cves/bulk-analysis', [
                'json' => ['cve_ids' => $cveIds]
            ]);

            $data = json_decode($response->getBody()->getContents(), true);

            if (!$data || !isset($data['success']) || !$data['success']) {
                throw new \RuntimeException('Invalid API response for bulk analysis');
            }

            return $data['data'] ?? [];

        } catch (GuzzleException $e) {
            throw new \RuntimeException("Failed to fetch bulk AI analysis: {$e->getMessage()}");
        }
    }

    /**
     * Search CVEs by package name
     */
    public function searchByPackage(string $packageName): array
    {
        try {
            $response = $this->client->get($this->baseUrl . '/cves/search', [
                'query' => ['package' => $packageName]
            ]);

            $data = json_decode($response->getBody()->getContents(), true);

            if (!$data || !isset($data['success']) || !$data['success']) {
                throw new \RuntimeException('Invalid API response for package search');
            }

            return $data['data'] ?? [];

        } catch (GuzzleException $e) {
            throw new \RuntimeException("Failed to search CVEs for package {$packageName}: {$e->getMessage()}");
        }
    }

    /**
     * Get CVE details with AI analysis
     */
    public function getCveDetails(string $cveId): array
    {
        try {
            $response = $this->client->get($this->baseUrl . "/cves/{$cveId}");

            $data = json_decode($response->getBody()->getContents(), true);

            if (!$data || !isset($data['success']) || !$data['success']) {
                throw new \RuntimeException('Invalid API response for CVE details');
            }

            return $data['data'] ?? [];

        } catch (GuzzleException $e) {
            throw new \RuntimeException("Failed to fetch CVE details for {$cveId}: {$e->getMessage()}");
        }
    }

    /**
     * Submit feedback for AI analysis improvement
     */
    public function submitFeedback(string $cveId, string $feedback, int $rating = null): bool
    {
        try {
            $payload = [
                'cve_id' => $cveId,
                'feedback' => $feedback
            ];

            if ($rating !== null) {
                $payload['rating'] = $rating;
            }

            $response = $this->client->post($this->baseUrl . '/feedback', [
                'json' => $payload
            ]);

            $data = json_decode($response->getBody()->getContents(), true);

            return isset($data['success']) && $data['success'];

        } catch (GuzzleException $e) {
            throw new \RuntimeException("Failed to submit feedback: {$e->getMessage()}");
        }
    }

    private function fetchAiAnalysis(string $cveId): array
    {
        try {
            $response = $this->client->get($this->baseUrl . "/cves/{$cveId}/ai-analysis");

            $data = json_decode($response->getBody()->getContents(), true);

            if (!$data || !isset($data['success']) || !$data['success']) {
                throw new \RuntimeException('Invalid API response for AI analysis');
            }

            return [
                'explanation' => $data['data']['ai_explanation'] ?? null,
                'solution' => $data['data']['ai_solution'] ?? null,
                'risk_assessment' => $data['data']['ai_risk_assessment'] ?? null,
                'mitigation_steps' => $data['data']['mitigation_steps'] ?? [],
                'severity_justification' => $data['data']['severity_justification'] ?? null,
                'exploit_likelihood' => $data['data']['exploit_likelihood'] ?? null,
            ];

        } catch (GuzzleException $e) {
            throw new \RuntimeException("Failed to fetch AI analysis for {$cveId}: {$e->getMessage()}");
        }
    }
}