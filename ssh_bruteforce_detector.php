#!/usr/bin/env php
<?php
/**
 * ============================================================
 *  SSH Brute-Force Detector & Auto-Blocker
 *  File    : ssh_bruteforce_detector.php
 *  Platform: CentOS (reads /var/log/secure)
 *  Author  : Security Project — PHP Edition
 *  Run as  : sudo php ssh_bruteforce_detector.php
 * ============================================================
 *
 * HOW IT WORKS (for project viva):
 * 1. Opens /var/log/secure and moves to the END of the file
 *    so we only process NEW lines (just like `tail -f`).
 * 2. In an infinite loop it reads any newly appended lines.
 * 3. Each line is checked with a regex for "Failed password"
 *    — if matched, we extract the source IP.
 * 4. We keep a counter per IP in an associative array.
 * 5. Once an IP hits the threshold (default: 5 failures)
 *    we block it via iptables and log it to a file.
 * 6. A whitelist prevents us from ever blocking trusted IPs
 *    (e.g. our own management IP).
 */

// ─────────────────────────────────────────────
//  ANSI COLOR CONSTANTS  (for pretty CLI output)
// ─────────────────────────────────────────────
define('RED',    "\033[1;31m");
define('GREEN',  "\033[1;32m");
define('YELLOW', "\033[1;33m");
define('CYAN',   "\033[1;36m");
define('WHITE',  "\033[1;37m");
define('RESET',  "\033[0m");

// ─────────────────────────────────────────────
//  CONFIGURATION  (edit these to suit your server)
// ─────────────────────────────────────────────
$config = [
    // Log file to monitor (CentOS SSH auth log)
    'log_file'        => '/var/log/secure',

    // How many failures before we block an IP
    'block_threshold' => 5,

    // File where we permanently record blocked IPs
    'history_file'    => __DIR__ . '/blocked_history.log',

    // Sleep interval between log polls (microseconds)
    // 500 000 µs = 0.5 seconds — low CPU, near-real-time
    'poll_interval'   => 500000,

    // ── WHITELIST ──────────────────────────────────
    // Add IPs you NEVER want to block (your office IP,
    // VPN gateway, monitoring server, etc.)
    'whitelist'       => [
        '127.0.0.1',
        '::1',
        // '203.0.113.10',   // <-- example: add your IP here
    ],
];

// ─────────────────────────────────────────────
//  RUNTIME STATE
// ─────────────────────────────────────────────
$failedAttempts = [];   // [ 'ip' => count ]  — in-memory counter
$blockedIPs     = [];   // IPs blocked in THIS session
$startTime      = time();

// ─────────────────────────────────────────────
//  HELPER FUNCTIONS
// ─────────────────────────────────────────────

/**
 * Print a timestamped, coloured message to STDOUT.
 *
 * @param string $color   One of the ANSI constants above
 * @param string $tag     Short label shown in brackets, e.g. "BLOCKED"
 * @param string $message The message body
 */
function logMessage(string $color, string $tag, string $message): void
{
    $timestamp = date('Y-m-d H:i:s');
    echo $color . "[{$timestamp}] [{$tag}]" . RESET . " {$message}\n";
}

/**
 * Append a line to the on-disk blocked-IP history file.
 *
 * @param string $ip        The blocked IP address
 * @param string $histFile  Path to the log file
 */
function writeHistory(string $ip, string $histFile): void
{
    $line = date('Y-m-d H:i:s') . " | BLOCKED | {$ip}\n";
    // FILE_APPEND is atomic-enough for our use case
    file_put_contents($histFile, $line, FILE_APPEND | LOCK_EX);
}

/**
 * Block an IP using iptables.
 * Returns true on (apparent) success, false on failure.
 *
 * NOTE: shell_exec needs the process to run as root.
 *
 * @param string $ip
 * @return bool
 */
function blockIP(string $ip): bool
{
    // Validate IP before passing to shell (security hygiene!)
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        logMessage(YELLOW, 'WARN', "Invalid IP skipped: {$ip}");
        return false;
    }

    // Drop all inbound packets from this IP
    $cmd    = "iptables -A INPUT -s " . escapeshellarg($ip) . " -j DROP 2>&1";
    $output = shell_exec($cmd);

    // iptables prints nothing on success; any output = error
    return ($output === null || trim($output) === '');
}

/**
 * Print the summary banner — called on Ctrl-C (SIGINT) or
 * whenever you want a mid-run report.
 *
 * @param array  $blockedIPs  List of IPs blocked this session
 * @param int    $startTime   Unix timestamp when script started
 */
function printSummary(array $blockedIPs, int $startTime): void
{
    $elapsed = time() - $startTime;
    $hms     = sprintf('%02d:%02d:%02d',
        intdiv($elapsed, 3600),
        intdiv($elapsed % 3600, 60),
        $elapsed % 60
    );
    $count   = count($blockedIPs);

    echo "\n";
    echo CYAN . "╔══════════════════════════════════════════╗" . RESET . "\n";
    echo CYAN . "║         SESSION SUMMARY                  ║" . RESET . "\n";
    echo CYAN . "╚══════════════════════════════════════════╝" . RESET . "\n";
    echo WHITE . "  Runtime   : " . RESET . $hms . "\n";
    echo WHITE . "  IPs Blocked: " . RESET . RED . $count . RESET . "\n";

    if ($count > 0) {
        echo WHITE . "  Blocked IPs:\n" . RESET;
        foreach ($blockedIPs as $ip) {
            echo "    " . RED . "✗ {$ip}" . RESET . "\n";
        }
    } else {
        echo GREEN . "  No threats detected this session." . RESET . "\n";
    }
    echo "\n";
}

// ─────────────────────────────────────────────
//  STARTUP CHECKS
// ─────────────────────────────────────────────

// 1. Root privilege check
//    posix_getuid() returns 0 for root; any other value = non-root
if (function_exists('posix_getuid') && posix_getuid() !== 0) {
    echo RED . "[ERROR] This script must be run as root (sudo)." . RESET . "\n";
    echo "  Usage: sudo php " . basename(__FILE__) . "\n";
    exit(1);
}

// 2. Log file existence check
if (!file_exists($config['log_file'])) {
    echo RED . "[ERROR] Log file not found: {$config['log_file']}" . RESET . "\n";
    echo "  On CentOS, make sure sshd is running and the file exists.\n";
    exit(1);
}

// 3. Log file readability check
if (!is_readable($config['log_file'])) {
    echo RED . "[ERROR] Cannot read {$config['log_file']} — permission denied." . RESET . "\n";
    exit(1);
}

// ─────────────────────────────────────────────
//  BANNER
// ─────────────────────────────────────────────
echo "\n";
echo GREEN . "╔══════════════════════════════════════════════════════╗" . RESET . "\n";
echo GREEN . "║      SSH BRUTE-FORCE DETECTOR  —  PHP Edition        ║" . RESET . "\n";
echo GREEN . "║      Monitoring: " . WHITE . $config['log_file'] . str_repeat(' ', 35 - strlen($config['log_file'])) . GREEN . "║" . RESET . "\n";
echo GREEN . "║      Threshold : " . WHITE . $config['block_threshold'] . " failed attempts" . str_repeat(' ', 20) . GREEN . "║" . RESET . "\n";
echo GREEN . "╚══════════════════════════════════════════════════════╝" . RESET . "\n\n";

logMessage(GREEN, 'START', "Detector active. Waiting for new log entries…");
logMessage(CYAN,  'INFO',  "Whitelist: " . implode(', ', $config['whitelist']));
echo "\n";

// ─────────────────────────────────────────────
//  SIGNAL HANDLER  (Ctrl-C = print summary then exit)
// ─────────────────────────────────────────────
if (function_exists('pcntl_signal')) {
    // We need to pass $blockedIPs and $startTime into the closure
    pcntl_signal(SIGINT, function () use (&$blockedIPs, $startTime) {
        echo "\n";
        logMessage(YELLOW, 'SIGNAL', "Ctrl-C received. Shutting down…");
        printSummary($blockedIPs, $startTime);
        exit(0);
    });
}

// ─────────────────────────────────────────────
//  OPEN LOG FILE & SEEK TO END
//  This means we only process lines written AFTER
//  the script started — just like `tail -f`.
// ─────────────────────────────────────────────
$handle = fopen($config['log_file'], 'r');
if ($handle === false) {
    echo RED . "[ERROR] Could not open {$config['log_file']}." . RESET . "\n";
    exit(1);
}

// Move file pointer to the very end
fseek($handle, 0, SEEK_END);

// ─────────────────────────────────────────────
//  MAIN MONITORING LOOP
// ─────────────────────────────────────────────
while (true) {

    // Dispatch any pending signals (e.g., Ctrl-C)
    if (function_exists('pcntl_signal_dispatch')) {
        pcntl_signal_dispatch();
    }

    // PHP caches file metadata; clear cache so fgets sees new data
    clearstatcache();

    // Read every new line appended since last iteration
    while (($line = fgets($handle)) !== false) {

        // ── PATTERN MATCHING ─────────────────────────────────
        // We look for lines like:
        //   Apr 13 10:22:01 server sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2
        //
        // Regex breakdown:
        //   Failed password   — literal text in the log
        //   .*from\s+         — anything, then "from " with whitespace
        //   ([\d\.]+)         — capture group: the IPv4 address
        //   |\s+([\da-f:]+)   — OR an IPv6 address (hex + colons)
        if (preg_match('/Failed password.*from\s+([\d\.]+|[\da-f:]+)/i', $line, $matches)) {

            $ip = trim($matches[1]);

            // Skip empty or non-IP results
            if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
                continue;
            }

            // ── WHITELIST CHECK ──────────────────────────────
            if (in_array($ip, $config['whitelist'], true)) {
                logMessage(YELLOW, 'WHITELIST', "Ignored attempt from trusted IP: {$ip}");
                continue;
            }

            // ── INCREMENT COUNTER ────────────────────────────
            // PHP associative arrays are perfect for this:
            // key = IP string, value = integer count
            if (!isset($failedAttempts[$ip])) {
                $failedAttempts[$ip] = 0;
            }
            $failedAttempts[$ip]++;

            $count = $failedAttempts[$ip];

            logMessage(YELLOW, 'ATTEMPT',
                "Failed login from {$ip}  (attempt {$count}/{$config['block_threshold']})");

            // ── THRESHOLD CHECK & BLOCK ───────────────────────
            if ($count >= $config['block_threshold'] && !in_array($ip, $blockedIPs, true)) {

                logMessage(RED, 'BLOCKING', "Threshold exceeded for {$ip} — adding iptables rule…");

                if (blockIP($ip)) {
                    $blockedIPs[] = $ip;
                    writeHistory($ip, $config['history_file']);
                    logMessage(RED, 'BLOCKED',
                        "IP {$ip} has been BLOCKED. "
                        . "Total blocked this session: " . count($blockedIPs));
                } else {
                    logMessage(YELLOW, 'WARN',
                        "iptables command failed for {$ip}. Is iptables installed?");
                }
            }
        }
        // (Lines not matching "Failed password" are silently ignored)
    }

    // No more new lines — sleep before polling again
    usleep($config['poll_interval']);
}

// (Unreachable — loop is infinite; exit via Ctrl-C)
