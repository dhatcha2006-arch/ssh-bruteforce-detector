#!/usr/bin/env php
<?php

define('RED',    "\033[1;31m");
define('GREEN',  "\033[1;32m");
define('YELLOW', "\033[1;33m");
define('CYAN',   "\033[1;36m");
define('WHITE',  "\033[1;37m");
define('RESET',  "\033[0m");

$config = [
    'log_file'        => '/var/log/secure',
    'block_threshold' => 5,
    'history_file'    => __DIR__ . '/blocked_history.log',
    'poll_interval'   => 500000,
    'whitelist'       => [
        '127.0.0.1',
        '::1',
    ],
];

$failedAttempts = [];
$blockedIPs     = [];
$startTime      = time();

function logMessage(string $color, string $tag, string $message): void
{
    $timestamp = date('Y-m-d H:i:s');
    echo $color . "[{$timestamp}] [{$tag}]" . RESET . " {$message}\n";
}

function writeHistory(string $ip, string $histFile): void
{
    $line = date('Y-m-d H:i:s') . " | BLOCKED | {$ip}\n";
    file_put_contents($histFile, $line, FILE_APPEND | LOCK_EX);
}

function blockIP(string $ip): bool
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        logMessage(YELLOW, 'WARN', "Invalid IP skipped: {$ip}");
        return false;
    }
    $cmd    = "iptables -A INPUT -s " . escapeshellarg($ip) . " -j DROP 2>&1";
    $output = shell_exec($cmd);
    return ($output === null || trim($output) === '');
}

function printSummary(array $blockedIPs, int $startTime): void
{
    $elapsed = time() - $startTime;
    $runtime = sprintf('%02d:%02d:%02d',
        intdiv($elapsed, 3600),
        intdiv($elapsed % 3600, 60),
        $elapsed % 60
    );
    $total = count($blockedIPs);

    echo "\n";
    echo CYAN . "╔══════════════════════════════════════╗" . RESET . "\n";
    echo CYAN . "║         SESSION SUMMARY              ║" . RESET . "\n";
    echo CYAN . "╚══════════════════════════════════════╝" . RESET . "\n";
    echo WHITE . "  Runtime    : " . RESET . $runtime . "\n";
    echo WHITE . "  IPs Blocked: " . RESET . RED . $total . RESET . "\n";

    if ($total > 0) {
        foreach ($blockedIPs as $ip) {
            echo RED . "    x {$ip}" . RESET . "\n";
        }
    } else {
        echo GREEN . "  No threats detected this session." . RESET . "\n";
    }
    echo "\n";
}

if (function_exists('posix_getuid') && posix_getuid() !== 0) {
    echo RED . "[ERROR] Run as root: sudo php " . basename(__FILE__) . RESET . "\n";
    exit(1);
}

if (!file_exists($config['log_file'])) {
    echo RED . "[ERROR] Log file not found: {$config['log_file']}" . RESET . "\n";
    exit(1);
}

if (!is_readable($config['log_file'])) {
    echo RED . "[ERROR] Cannot read: {$config['log_file']} - Permission denied." . RESET . "\n";
    exit(1);
}

echo "\n";
echo GREEN . "╔══════════════════════════════════════════════════════╗" . RESET . "\n";
echo GREEN . "║      SSH BRUTE-FORCE DETECTOR  -  PHP Edition        ║" . RESET . "\n";
echo GREEN . "║      Monitoring : " . WHITE . $config['log_file'] . str_repeat(' ', 35 - strlen($config['log_file'])) . GREEN . "║" . RESET . "\n";
echo GREEN . "║      Threshold  : " . WHITE . $config['block_threshold'] . " failed attempts" . str_repeat(' ', 20) . GREEN . "║" . RESET . "\n";
echo GREEN . "╚══════════════════════════════════════════════════════╝" . RESET . "\n\n";

logMessage(GREEN, 'START', "Detector is now active. Watching for attacks...");
logMessage(CYAN,  'INFO',  "Whitelist: " . implode(', ', $config['whitelist']));
logMessage(CYAN,  'INFO',  "Press Ctrl+C to stop and view session summary.");
echo "\n";

if (function_exists('pcntl_signal')) {
    pcntl_signal(SIGINT, function () use (&$blockedIPs, $startTime) {
        echo "\n";
        logMessage(YELLOW, 'SIGNAL', "Ctrl+C received. Stopping...");
        printSummary($blockedIPs, $startTime);
        exit(0);
    });
}

$handle = fopen($config['log_file'], 'r');
if ($handle === false) {
    echo RED . "[ERROR] Could not open log file." . RESET . "\n";
    exit(1);
}

fseek($handle, 0, SEEK_END);

while (true) {

    if (function_exists('pcntl_signal_dispatch')) {
        pcntl_signal_dispatch();
    }

    clearstatcache();

    while (($line = fgets($handle)) !== false) {

        if (preg_match('/Failed password.*from\s+([\d\.]+|[\da-f:]+)/i', $line, $matches)) {

            $ip = trim($matches[1]);

            if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
                continue;
            }

            if (in_array($ip, $config['whitelist'], true)) {
                logMessage(YELLOW, 'WHITELIST', "Trusted IP ignored: {$ip}");
                continue;
            }

            $failedAttempts[$ip] = ($failedAttempts[$ip] ?? 0) + 1;
            $count = $failedAttempts[$ip];

            logMessage(YELLOW, 'ATTEMPT',
                "Failed login from {$ip}  (attempt {$count}/{$config['block_threshold']})");

            if ($count >= $config['block_threshold'] && !in_array($ip, $blockedIPs, true)) {

                logMessage(RED, 'BLOCKING', "Blocking {$ip} now...");

                if (blockIP($ip)) {
                    $blockedIPs[] = $ip;
                    writeHistory($ip, $config['history_file']);
                    logMessage(RED, 'BLOCKED',
                        "IP {$ip} is BLOCKED. Total blocked: " . count($blockedIPs));
                } else {
                    logMessage(YELLOW, 'WARN',
                        "iptables failed for {$ip}. Is iptables installed?");
                }
            }
        }
    }

    usleep($config['poll_interval']);
}
