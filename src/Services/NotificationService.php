<?php

namespace CyberSentry\Services;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Log;

class NotificationService
{
    public function notify(array $vulnerabilities): void
    {
        if (empty($vulnerabilities)) {
            return;
        }

        $report = $this->generateReport($vulnerabilities);

        if (config('cybersentry.notifications.webhook.enabled')) {
            $this->sendWebhookNotification($report);
        }

        if (config('cybersentry.notifications.email.enabled')) {
            $this->sendEmailNotification($report);
        }
    }

    private function generateReport(array $vulnerabilities): array
    {
        $severityCounts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
        ];

        foreach ($vulnerabilities as $vuln) {
            $severity = $vuln['severity'] ?? 'low';
            if (isset($severityCounts[$severity])) {
                $severityCounts[$severity]++;
            }
        }

        return [
            'timestamp' => now()->toISOString(),
            'total_vulnerabilities' => count($vulnerabilities),
            'severity_breakdown' => $severityCounts,
            'vulnerabilities' => $vulnerabilities,
            'summary' => $this->generateSummary($vulnerabilities, $severityCounts),
        ];
    }

    private function generateSummary(array $vulnerabilities, array $severityCounts): string
    {
        $total = count($vulnerabilities);
        $critical = $severityCounts['critical'];
        $high = $severityCounts['high'];

        if ($critical > 0) {
            return "🚨 CRITICAL: Found {$total} vulnerabilities including {$critical} critical issues that require immediate attention!";
        }

        if ($high > 0) {
            return "⚠️ HIGH PRIORITY: Found {$total} vulnerabilities including {$high} high-severity issues that should be addressed quickly.";
        }

        return "ℹ️ Found {$total} vulnerabilities that should be reviewed and addressed.";
    }

    private function sendWebhookNotification(array $report): void
    {
        try {
            $webhookUrl = config('cybersentry.notifications.webhook.url');

            if (empty($webhookUrl)) {
                return;
            }

            $client = new Client(['timeout' => 10]);

            $client->post($webhookUrl, [
                'json' => [
                    'event' => 'cybersentry.vulnerabilities_found',
                    'data' => $report,
                ],
                'headers' => [
                    'Content-Type' => 'application/json',
                    'User-Agent' => 'CyberSentry/1.0',
                ]
            ]);

            Log::info('CyberSentry webhook notification sent successfully');

        } catch (\Exception $e) {
            Log::error('Failed to send CyberSentry webhook notification: ' . $e->getMessage());
        }
    }

    private function sendEmailNotification(array $report): void
    {
        try {
            $recipients = config('cybersentry.notifications.email.recipients', []);

            if (empty($recipients)) {
                return;
            }

            $subject = "🚨 CyberSentry Security Alert - {$report['total_vulnerabilities']} Vulnerabilities Found";

            foreach ($recipients as $recipient) {
                if (empty(trim($recipient))) {
                    continue;
                }

                Mail::html(
                    $this->generateEmailBody($report),
                    function ($message) use ($recipient, $subject) {
                        $message->to(trim($recipient))
                            ->subject($subject);
                    }
                );
            }

            Log::info('CyberSentry email notifications sent successfully');

        } catch (\Exception $e) {
            Log::error('Failed to send CyberSentry email notification: ' . $e->getMessage());
        }
    }

    private function generateEmailBody(array $report): string
    {
        $html = '<html><body>';
        $html .= '<h2>🔒 CyberSentry Security Report</h2>';
        $html .= '<p><strong>Generated:</strong> ' . $report['timestamp'] . '</p>';
        $html .= '<p><strong>Summary:</strong> ' . htmlspecialchars($report['summary']) . '</p>';

        $html .= '<h3>Severity Breakdown</h3>';
        $html .= '<ul>';
        foreach ($report['severity_breakdown'] as $severity => $count) {
            if ($count > 0) {
                $emoji = match($severity) {
                    'critical' => '🔴',
                    'high' => '🟠',
                    'medium' => '🟡',
                    'low' => '🔵',
                    default => '⚪'
                };
                $html .= "<li>{$emoji} <strong>" . ucfirst($severity) . ":</strong> {$count}</li>";
            }
        }
        $html .= '</ul>';

        $html .= '<h3>Vulnerability Details</h3>';
        foreach ($report['vulnerabilities'] as $vuln) {
            $html .= '<div style="border: 1px solid #ddd; padding: 10px; margin: 10px 0;">';
            $html .= '<h4>' . htmlspecialchars($vuln['package']) . '</h4>';
            $html .= '<p><strong>CVE:</strong> ' . htmlspecialchars($vuln['cve']) . '</p>';
            $html .= '<p><strong>Severity:</strong> ' . ucfirst($vuln['severity']) . '</p>';
            $html .= '<p><strong>Title:</strong> ' . htmlspecialchars($vuln['title']) . '</p>';

            if (!empty($vuln['ai_explanation'])) {
                $html .= '<p><strong>AI Explanation:</strong> ' . htmlspecialchars($vuln['ai_explanation']) . '</p>';
            }

            if (!empty($vuln['ai_solution'])) {
                $html .= '<p><strong>AI Solution:</strong> ' . htmlspecialchars($vuln['ai_solution']) . '</p>';
            }

            $html .= '</div>';
        }

        $html .= '<hr>';
        $html .= '<p><small>This report was generated by CyberSentry. Please review and address these vulnerabilities promptly.</small></p>';
        $html .= '</body></html>';

        return $html;
    }
}