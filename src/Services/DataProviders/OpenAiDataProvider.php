<?php

namespace User\CustomAudit\Services\DataProviders;

use User\CustomAudit\Contracts\VulnerabilityDataProviderInterface;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

class OpenAiDataProvider implements VulnerabilityDataProviderInterface
{
    protected ?HttpClient $httpClient = null;
    protected ?string $apiKey = null;

    public function __construct()
    {
        $this->apiKey = Config::get(
'custom-audit.openai_api_key
');
        if ($this->apiKey) {
            $this->httpClient = new HttpClient([
                
'base_uri
' => 
'https://api.openai.com/
',
                
'timeout
'  => 60, // Increased timeout for potentially long AI responses
            ]);
        }
    }

    public function getExplanation(array $vulnerabilityData): ?string
    {
        if (!$this->httpClient || !$this->apiKey) {
            Log::warning(
'OpenAI Data Provider is not configured or API key is missing.
');
            return null;
        }

        // Construct a prompt for OpenAI
        $prompt = $this->buildPrompt($vulnerabilityData);

        try {
            $response = $this->httpClient->post(
'v1/chat/completions
', [
                
'headers
' => [
                    
'Authorization
' => 
'Bearer 
' . $this->apiKey,
                    
'Content-Type
' => 
'application/json
',
                ],
                
'json
' => [
                    
'model
' => Config::get(
'custom-audit.openai_model
', 
'gpt-3.5-turbo
'), // Allow model override via config
                    
'messages
' => [
                        [
'role
' => 
'system
', 
'content
' => 
'You are a security assistant. Explain the following vulnerability concisely for a developer, focusing on the impact and how it might be exploited. Provide a brief suggestion for mitigation if possible.
'],
                        [
'role
' => 
'user
', 
'content
' => $prompt]
                    ],
                    
'max_tokens
' => 150, // Limit response length
                    
'temperature
' => 0.5, // Control creativity
                ],
            ]);

            $body = json_decode($response->getBody()->getContents(), true);

            if (isset($body[
'choices
'][0][
'message
'][
'content
'])) {
                return trim($body[
'choices
'][0][
'message
'][
'content
']);
            }

            Log::warning(
'OpenAI API response did not contain expected content.
', [
'response
' => $body]);
            return null;

        } catch (RequestException $e) {
            $errorMessage = 
'Error calling OpenAI API: 
' . $e->getMessage();
            if ($e->hasResponse()) {
                $errorMessage .= 
' | Response: 
' . $e->getResponse()->getBody()->getContents();
            }
            Log::error($errorMessage);
            return null;
        } catch (\Exception $e) {
            Log::error(
'Unexpected error in OpenAiDataProvider: 
' . $e->getMessage());
            return null;
        }
    }

    protected function buildPrompt(array $vulnerabilityData): string
    {
        $prompt = "Vulnerability found in package: " . ($vulnerabilityData[
'package_name
'] ?? 
'N/A
') . "\n";
        $prompt .= "Title: " . ($vulnerabilityData[
'title
'] ?? 
'N/A
') . "\n";
        if (!empty($vulnerabilityData[
'cve
'])) {
            $prompt .= "CVE: " . $vulnerabilityData[
'cve
'] . "\n";
        }
        $prompt .= "Affected Versions: " . ($vulnerabilityData[
'affected_versions
'] ?? 
'N/A
') . "\n";
        if (!empty($vulnerabilityData[
'link
'])) {
            $prompt .= "Link: " . $vulnerabilityData[
'link
'] . "\n";
        }
        // Include raw description if available and potentially useful
        if (!empty($vulnerabilityData[
'raw_data
'][
'description
'])) {
             $prompt .= "Description: " . substr($vulnerabilityData[
'raw_data
'][
'description
'], 0, 500) . "...\n"; // Limit length
        }
         if (!empty($vulnerabilityData[
'raw_data
'][
'overview
'])) { // For NPM advisories
             $prompt .= "Overview: " . substr($vulnerabilityData[
'raw_data
'][
'overview
'], 0, 500) . "...\n"; // Limit length
        }

        return $prompt;
    }

    // This provider specifically handles OpenAI explanations, not custom CVE info
    public function getCustomCveInfo(string $cveId): ?array
    {
        return null;
    }
}

