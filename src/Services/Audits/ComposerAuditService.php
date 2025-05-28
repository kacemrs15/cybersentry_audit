<?php

namespace User\CustomAudit\Services\Audits;

use User\CustomAudit\Contracts\AuditServiceInterface;
use User\CustomAudit\Contracts\ComposerVulnerabilityDataProviderInterface;
use Illuminate\Support\Facades\Log;
use Exception;

class ComposerAuditService implements AuditServiceInterface
{
    protected ComposerVulnerabilityDataProviderInterface $dataProvider;
    protected array $findings = [];
    protected ?string $errorMessage = null;
    protected string $projectPath;

    public function __construct(ComposerVulnerabilityDataProviderInterface $dataProvider, string $projectPath)
    {
        $this->dataProvider = $dataProvider;
        $this->projectPath = $projectPath;
    }

    /**
     * Run the audit using the configured data provider.
     *
     * @return bool True if the audit ran successfully (even if vulnerabilities were found), false otherwise.
     */
    public function run(): bool
    {
        $this->findings = [];
        $this->errorMessage = null;

        try {
            $this->findings = $this->dataProvider->getVulnerabilities($this->projectPath);
            // Assuming the provider returns the vulnerabilities in the desired format {"advisories": ...}
            // Or adjust the provider interface/implementations to return a more structured object/array
            return true;
        } catch (Exception $e) {
            $this->errorMessage = "Failed to get Composer vulnerabilities: " . $e->getMessage();
            Log::error("Composer Audit Service failed.", ["exception" => $e]);
            return false;
        }
    }

    /**
     * Get the findings from the last audit run.
     *
     * @return array
     */
    public function getFindings(): array
    {
        // Return the raw findings from the provider (expected format: {"advisories": ...})
        // The ReportService will handle the structure.
        return $this->findings;
    }

    /**
     * Get the error message if the last audit run failed.
     *
     * @return string|null
     */
    public function getErrorMessage(): ?string
    {
        return $this->errorMessage;
    }
}

