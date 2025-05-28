<?php

namespace User\CustomAudit\Services\DataProviders;

use User\CustomAudit\Contracts\ComposerVulnerabilityDataProviderInterface;
use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\File;

class ComposerAuditDataProvider implements ComposerVulnerabilityDataProviderInterface
{
    /**
     * Get vulnerabilities using the `composer audit --json` command.
     *
     * @param string $projectPath The absolute path to the project root containing composer.lock.
     * @return array An array of vulnerability data.
     * @throws \Exception If the audit process fails or the output cannot be parsed.
     */
    public function getVulnerabilities(string $projectPath): array
    {
        $lockFilePath = rtrim($projectPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'composer.lock';

        if (!File::exists($lockFilePath)) {
            Log::warning("Composer audit skipped: composer.lock not found at {$lockFilePath}");
            // Return empty array or throw specific exception based on desired behavior
            return []; 
        }

        // Ensure composer is available (basic check)
        // A more robust check might involve `command -v composer` or similar
        $process = new Process(['composer', '--version'], $projectPath);
        try {
            $process->mustRun();
        } catch (ProcessFailedException $exception) {
            Log::error('Composer command not found or failed to execute.', ['exception' => $exception->getMessage()]);
            throw new \Exception('Composer command is not available or failed.', 0, $exception);
        }

        // Run composer audit
        $process = new Process(['composer', 'audit', '--json'], $projectPath);
        
        try {
            // Increase timeout if necessary for large projects
            $process->setTimeout(300); // 5 minutes timeout
            $process->run();

            // Composer audit returns non-zero exit code if vulnerabilities are found.
            // We should not treat this as a failure of the command itself.
            // We only throw an exception if the command truly failed to execute (e.g., syntax error, killed).
            if (!$process->isSuccessful() && $process->getExitCode() !== 1) { 
                 // Exit code 1 usually means vulnerabilities found, which is expected.
                 // Other non-zero codes might indicate actual errors.
                 // Log the error output for debugging
                 Log::error('Composer audit command failed unexpectedly.', [
                    'exit_code' => $process->getExitCode(),
                    'error_output' => $process->getErrorOutput(),
                    'output' => $process->getOutput(),
                 ]);
                 // Consider throwing a more specific exception
                 throw new ProcessFailedException($process); 
            }

            $output = $process->getOutput();
            $decoded = json_decode($output, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                Log::error('Failed to decode JSON output from composer audit.', ['output' => $output, 'error' => json_last_error_msg()]);
                throw new \Exception('Failed to decode JSON output from composer audit: ' . json_last_error_msg());
            }

            // Standardize the output format if necessary, here we assume the structure is usable
            // The structure is typically {"advisories": {"package/name": [{"title": ..., "link": ..., "cve": ..., "affectedVersions": ..., "sources": [...]}]}}
            return $decoded['advisories'] ?? [];

        } catch (ProcessFailedException $exception) {
            Log::error('Composer audit process failed.', ['exception' => $exception->getMessage()]);
            // Rethrow or handle as appropriate
            throw new \Exception('Composer audit process failed: ' . $exception->getMessage(), 0, $exception);
        }
    }
}

