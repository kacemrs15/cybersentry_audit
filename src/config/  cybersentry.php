<?php

return [
    /*
    |--------------------------------------------------------------------------
    | CyberSentry API Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for your CVE database API
    |
    */
    'api' => [
        'base_url' => env('CYBERSENTRY_API_URL', 'https://your-api.example.com/api'),
        'api_key' => env('CYBERSENTRY_API_KEY'),
        'timeout' => env('CYBERSENTRY_API_TIMEOUT', 30),
    ],

    /*
    |--------------------------------------------------------------------------
    | Notification Settings
    |--------------------------------------------------------------------------
    |
    | Configure how you want to receive vulnerability notifications
    |
    */
    'notifications' => [
        'webhook' => [
            'enabled' => env('CYBERSENTRY_WEBHOOK_ENABLED', false),
            'url' => env('CYBERSENTRY_WEBHOOK_URL'),
        ],
        'email' => [
            'enabled' => env('CYBERSENTRY_EMAIL_ENABLED', false),
            'recipients' => explode(',', env('CYBERSENTRY_EMAIL_RECIPIENTS', '')),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit Settings
    |--------------------------------------------------------------------------
    |
    | Configure audit behavior
    |
    */
    'audit' => [
        'fail_on_vulnerabilities' => env('CYBERSENTRY_FAIL_ON_VULNERABILITIES', true),
        'ignore_abandoned' => env('CYBERSENTRY_IGNORE_ABANDONED', false),
        'severity_threshold' => env('CYBERSENTRY_SEVERITY_THRESHOLD', 'low'), // low, medium, high, critical
        'include_ai_analysis' => env('CYBERSENTRY_INCLUDE_AI_ANALYSIS', true),
    ],
];