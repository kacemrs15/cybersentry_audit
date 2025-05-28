<?php

// config/custom-audit.php

return [

    /*
    |--------------------------------------------------------------------------
    | Enabled Audits
    |--------------------------------------------------------------------------
    |
    | Specify which package managers should be audited by default.
    | Available options: 'composer', 'npm'.
    |
    */
    'enabled_audits' => [
        'composer',
        // 'npm', // Uncomment to enable NPM audit by default
    ],

    /*
    |--------------------------------------------------------------------------
    | Composer Vulnerability Data Source
    |--------------------------------------------------------------------------
    |
    | Select the primary source for fetching Composer vulnerability data.
    | - 'composer_audit': Uses the built-in `composer audit --json` command.
    |                     This is the recommended default.
    | - 'custom_cve_api': Uses your configured custom CVE API.
    |                     Requires 'custom_cve_api.enabled' to be true and
    |                     'custom_cve_api.url' to be set.
    |
    */
    'composer_data_source' => env('CUSTOM_AUDIT_COMPOSER_SOURCE', 'composer_audit'), // Default to composer audit

    /*
    |--------------------------------------------------------------------------
    | Reporting Severity Threshold
    |--------------------------------------------------------------------------
    |
    | Minimum severity level for vulnerabilities to be included in the report.
    | Options: 'low', 'medium', 'high', 'critical'.
    |
    */
    'report_severity_threshold' => env('CUSTOM_AUDIT_REPORT_SEVERITY', 'medium'),

    /*
    |--------------------------------------------------------------------------
    | Fail on Severity Threshold
    |--------------------------------------------------------------------------
    |
    | Minimum severity level that should cause the audit command to return
    | a non-zero exit code (failure). Useful for CI/CD pipelines.
    | Options: 'low', 'medium', 'high', 'critical', or null to disable failing.
    |
    */
    'fail_on_severity' => env('CUSTOM_AUDIT_FAIL_SEVERITY', 'high'),

    /*
    |--------------------------------------------------------------------------
    | OpenAI Integration (for Explanations)
    |--------------------------------------------------------------------------
    */
    'openai' => [
        'enabled' => env('CUSTOM_AUDIT_OPENAI_ENABLED', false),
        'api_key' => env('OPENAI_API_KEY'),
        // Optional: Specify model, prompt details if needed
        // 'model' => env('OPENAI_MODEL', 'text-davinci-003'), 
        // 'prompt_template' => "Explain the security vulnerability {cve} ({title}) affecting {package} version {version}.",
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom CVE Database API Integration
    |--------------------------------------------------------------------------
    |
    | Configure your custom CVE API. This can be used as the primary
    | composer_data_source or as an enrichment source.
    |
    */
    'custom_cve_api' => [
        // Enable this if using as a source OR enrichment provider
        'enabled' => env('CUSTOM_AUDIT_CVE_API_ENABLED', false),
        
        // Required if enabled=true
        'url' => env('CUSTOM_CVE_API_URL'), 
        
        // Optional: Authentication details
        'auth_token' => env('CUSTOM_CVE_API_TOKEN'),
        'auth_type' => env('CUSTOM_CVE_API_AUTH_TYPE', 'bearer'), // e.g., 'bearer', 'header' (uses X-API-KEY), 'none'
    ],

    /*
    |--------------------------------------------------------------------------
    | Notification Settings (Placeholder - Not fully implemented in provided code)
    |--------------------------------------------------------------------------
    */
    'notifications' => [
        'enabled' => env('CUSTOM_AUDIT_NOTIFICATIONS_ENABLED', false),
        'channel' => env('CUSTOM_AUDIT_NOTIFICATION_CHANNEL', 'log'), // e.g., 'log', 'webhook', 'mail'
        'webhook_url' => env('CUSTOM_AUDIT_WEBHOOK_URL'),
        'email_recipients' => env('CUSTOM_AUDIT_EMAIL_RECIPIENTS'), // Comma-separated
    ],

];

