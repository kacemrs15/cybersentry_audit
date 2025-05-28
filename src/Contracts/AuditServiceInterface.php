<?php

namespace User\CustomAudit\Contracts;

interface AuditServiceInterface
{
    /**
     * Get the name of the audit service.
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Run the audit process.
     *
     * @return bool True on success, false on failure.
     */
    public function run(): bool;

    /**
     * Get the findings from the audit.
     *
     * @return array An array of vulnerability data.
     */
    public function getFindings(): array;

    /**
     * Handle audit failure.
     *
     * @return void
     */
    public function handleFailure(): void;

    /**
     * Get any error messages from the audit process.
     *
     * @return string|null
     */
    public function getErrorMessage(): ?string;
}

