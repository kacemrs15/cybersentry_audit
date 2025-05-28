<?php

namespace User\CustomAudit\Services\DataProviders;

use User\CustomAudit\Contracts\ComposerVulnerabilityDataProviderInterface;
use User\CustomAudit\Contracts\VulnerabilityEnrichmentProviderInterface; // Keep for potential explanation fallback
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\File;
use Exception;

class CustomCveApiDataProvider implements ComposerVulnerabilityDataProviderInterface, VulnerabilityEnrichmentProviderInterface
{
    protected string $apiUrl;
    protected ?string $apiToken;
    protected string $authType;

    public function __construct()
    {
        // Ensure configuration values are loaded correctly
        $this->apiUrl = Config::get(
			custom-audit.custom_cve_api.url
			);
        $this->apiToken = Config::get(
			custom-audit.custom_cve_api.auth_token
			);
        $this->authType = Config::get(
			custom-audit.custom_cve_api.auth_type
			, 
			bearer
			);

        if (empty($this->apiUrl)) {
            Log::warning(
				Custom CVE API provider disabled: API URL is not configured.
				);
            // Or throw an exception if this provider is explicitly selected but not configured
        }
    }

    /**
     * Get vulnerabilities by parsing composer.lock and querying the custom API.
     *
     * @param string $projectPath The absolute path to the project root containing composer.lock.
     * @return array An array of vulnerability data, structured similarly to composer audit output.
     * @throws \Exception If the lock file cannot be read or the API request fails.
     */
    public function getVulnerabilities(string $projectPath): array
    {
        if (empty($this->apiUrl)) {
            return []; // Not configured, return empty
        }

        $lockFilePath = rtrim($projectPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 
			composer.lock
			;

        if (!File::exists($lockFilePath)) {
            Log::warning(
				Custom CVE API check skipped: composer.lock not found at {$lockFilePath}
				);
            return [];
        }

        try {
            $lockFileContent = File::get($lockFilePath);
            $lockData = json_decode($lockFileContent, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception(
					Failed to decode composer.lock: 
					 . json_last_error_msg());
            }

            $packages = $lockData[
				packages
				] ?? [];
            $packagesDev = $lockData[
				packages-dev
				] ?? [];
            $allPackages = array_merge($packages, $packagesDev);

            if (empty($allPackages)) {
                Log::info(
					No packages found in composer.lock for Custom CVE API check.
					);
                return [];
            }

            $vulnerabilities = [];
            $httpClient = $this->buildHttpClient();

            // --- Querying Logic --- 
            // This part is highly dependent on the custom API structure.
            // Assumption: API accepts POST request with package name and version, 
            // or maybe a bulk request.
            // Example: Querying one by one (can be inefficient)
            foreach ($allPackages as $package) {
                $packageName = $package[
					name
					] ?? null;
                $packageVersion = $package[
					version
					] ?? null;

                if (!$packageName || !$packageVersion) {
                    continue;
                }

                try {
                    // Adjust the request based on the actual API requirements
                    $response = $httpClient->post($this->apiUrl, [
                        
							package
							 => $packageName,
                        
							version
							 => $packageVersion,
                    ]);

                    if ($response->successful()) {
                        $apiVulnerabilities = $response->json(); // Assuming API returns JSON
                        
                        // --- Response Mapping --- 
                        // Map the API response structure to the format expected by ReportService
                        // (similar to composer audit: {"advisories": {"package/name": [...]}})
                        if (!empty($apiVulnerabilities) && is_array($apiVulnerabilities)) {
                            // Example mapping (adjust based on actual API response)
                            if (!isset($vulnerabilities[$packageName])) {
                                $vulnerabilities[$packageName] = [];
                            }
                            foreach ($apiVulnerabilities as $vuln) {
                                $vulnerabilities[$packageName][] = [
                                    
										title
										 => $vuln[
											title
											] ?? 
											Unknown Vulnerability
											,
                                    
										link
										 => $vuln[
											link
											] ?? 
											#
											,
                                    
										cve
										 => $vuln[
											cve
											] ?? null,
                                    
										affectedVersions
										 => $vuln[
											affected_versions
											] ?? 
											*
											, // Needs proper mapping
                                    // Map other relevant fields like severity if available
                                ];
                            }
                        }
                    } else {
                        Log::warning(
							Custom CVE API request failed for package {$packageName}
							, [
                            
								status
								 => $response->status(),
                            
								body
								 => $response->body(),
                        ]);
                    }
                } catch (Exception $e) {
                    Log::error(
						Error querying Custom CVE API for package {$packageName}
						, [
							
							exception
								 => $e->getMessage()
								]);
                    // Decide whether to continue or rethrow
                }
            }
            
            // Return in the expected format
            return [
				advisories
				 => $vulnerabilities];

        } catch (Exception $e) {
            Log::error(
				Error processing composer.lock or querying Custom CVE API.
				, [
					
					exception
						 => $e->getMessage()
						]);
            throw new Exception(
				Error in Custom CVE API Data Provider: 
				 . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Get explanation for a vulnerability (potentially from the custom API if it provides it).
     * This method remains from the previous design, might need adjustment.
     *
     * @param array $vulnerabilityData Standardized vulnerability data array.
     * @return string|null Explanation text or null.
     */
    public function getExplanation(array $vulnerabilityData): ?string
    {
        // If the custom API response included an explanation during the getVulnerabilities call,
        // it should ideally be stored within the $vulnerabilityData array passed here.
        // Otherwise, this provider might not be suitable for explanations unless it makes another API call.
        
        // Example: Check if explanation was included from the getVulnerabilities mapping
        return $vulnerabilityData[
			custom_explanation
			] ?? null; 
        
        // Alternatively, make a specific API call for explanation if the API supports it
        // $cve = $vulnerabilityData[
		// 	cve
		// 	] ?? null;
        // if ($cve && !empty($this->apiUrl)) {
        //     try {
        //         $httpClient = $this->buildHttpClient();
        //         // Adjust endpoint/request for explanation
        //         $response = $httpClient->get($this->apiUrl . 
		// 			/explanation/
		// 			 . $cve);
        //         if ($response->successful()) {
        //             return $response->json(
		// 				explanation
		// 				);
        //         }
        //     } catch (Exception $e) {
        //         Log::error(
		// 			Error fetching explanation from Custom CVE API for CVE {$cve}
		// 			, [
		// 				
		// 				exception
		// 					 => $e->getMessage()
		// 					]);
        //     }
        // }
        
        // return null;
    }
    
    /**
     * Get custom CVE info (remains from previous design, might be redundant 
     * if info is included in getVulnerabilities response mapping).
     *
     * @param string $cve
     * @return array|null
     */
    public function getCustomCveInfo(string $cve): ?array
    {
         if (empty($this->apiUrl)) {
            return null;
        }
        // This might be redundant if getVulnerabilities already fetches all needed info.
        // If separate call is needed:
        try {
            $httpClient = $this->buildHttpClient();
            // Adjust endpoint/request for specific CVE info
            $response = $httpClient->get($this->apiUrl . 
				/cve/
				 . $cve); 
            if ($response->successful()) {
                return $response->json(); // Return the raw custom info
            }
        } catch (Exception $e) {
             Log::error(
				 Error fetching custom info from Custom CVE API for CVE {$cve}
				 , [
				 	
				 	exception
				 		 => $e->getMessage()
				 		 ]);
        }
        return null;
    }

    /**
     * Builds the HTTP client with appropriate headers and authentication.
     *
     * @return \Illuminate\Http\Client\PendingRequest
     */
    protected function buildHttpClient(): \Illuminate\Http\Client\PendingRequest
    {
        $client = Http::acceptJson()->timeout(60); // Default timeout

        if (!empty($this->apiToken)) {
            if (strtolower($this->authType) === 
				bearer
				) {
                $client = $client->withToken($this->apiToken);
            } elseif (strtolower($this->authType) === 
				header
				) {
                // Assuming a common header like X-API-KEY, adjust if needed
                $client = $client->withHeaders([
                    
					X-API-KEY
					 => $this->apiToken
					]);
            } // Add other auth types if necessary
        }

        return $client;
    }
}

