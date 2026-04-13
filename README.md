# SSH Brute-Force Detector — PHP Edition
### CentOS / RHEL  •  CLI Tool  •  Project README

---

## What This Tool Does

Monitors `/var/log/secure` in real time for repeated SSH login
failures. When a single IP exceeds the threshold (default: 5), it is
automatically blocked via `iptables` and logged to `blocked_history.log`.

---

## File Structure

```
project/
├── ssh_bruteforce_detector.php   ← main script
├── blocked_history.log           ← auto-created on first block
└── README.md                     ← this file
```

---

## Requirements

| Requirement | Check command |
|---|---|
| CentOS 7 / 8 / Stream | `cat /etc/redhat-release` |
| PHP ≥ 7.4 (CLI) | `php -v` |
| iptables | `which iptables` |
| Root access | `sudo -v` |

### Install PHP on CentOS (if needed)
```bash
sudo yum install php-cli -y       # CentOS 7
sudo dnf install php-cli -y       # CentOS 8 / Stream
```

---

## Quick Deployment (4 steps)

### Step 1 — Copy the script to your server
```bash
# Option A: copy manually via SCP
scp ssh_bruteforce_detector.php user@yourserver:/opt/ssh-detector/

# Option B: create the directory and paste locally
sudo mkdir -p /opt/ssh-detector
sudo cp ssh_bruteforce_detector.php /opt/ssh-detector/
```

### Step 2 — Set permissions
```bash
sudo chmod 700 /opt/ssh-detector/ssh_bruteforce_detector.php
sudo chown root:root /opt/ssh-detector/ssh_bruteforce_detector.php
```

### Step 3 — Run it
```bash
cd /opt/ssh-detector
sudo php ssh_bruteforce_detector.php
```

You should see:
```
╔══════════════════════════════════════════════════════╗
║      SSH BRUTE-FORCE DETECTOR  —  PHP Edition        ║
╚══════════════════════════════════════════════════════╝
[2025-06-01 10:00:00] [START] Detector active. Waiting for new log entries…
```

### Step 4 — Test it (in a second terminal)
```bash
# Simulate failed SSH logins from a test IP
for i in {1..6}; do
    sudo logger -p auth.info \
      "sshd[9999]: Failed password for root from 10.0.0.99 port 22222 ssh2"
    sleep 0.2
done
```
After the 5th injection you should see the BLOCKED message.

---

## Run as a Background Service (systemd)

Create `/etc/systemd/system/ssh-detector.service`:

```ini
[Unit]
Description=SSH Brute-Force Detector
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/php /opt/ssh-detector/ssh_bruteforce_detector.php
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Then enable and start it:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ssh-detector
sudo systemctl start  ssh-detector
sudo systemctl status ssh-detector
```

View live logs from the service:
```bash
sudo journalctl -u ssh-detector -f
```

---

## Configuration (inside the script)

| Variable | Default | Purpose |
|---|---|---|
| `log_file` | `/var/log/secure` | Log file to monitor |
| `block_threshold` | `5` | Failures before blocking |
| `history_file` | `./blocked_history.log` | Where blocks are recorded |
| `poll_interval` | `500000` µs | How often to read new lines |
| `whitelist` | `127.0.0.1`, `::1` | IPs that are NEVER blocked |

To add your management IP to the whitelist, edit the script:
```php
'whitelist' => [
    '127.0.0.1',
    '::1',
    '203.0.113.10',   // ← your office / VPN IP
],
```

---

## Viewing Blocked History

```bash
cat /opt/ssh-detector/blocked_history.log
```
Output format:
```
2025-06-01 10:05:22 | BLOCKED | 192.168.1.55
2025-06-01 10:07:44 | BLOCKED | 45.33.32.156
```

---

## Unblocking an IP Manually

```bash
sudo iptables -D INPUT -s 192.168.1.55 -j DROP
```

To list all current iptables rules:
```bash
sudo iptables -L INPUT -n --line-numbers
```

---

## Stopping the Script

Press `Ctrl + C` — the signal handler will print a session summary:
```
╔══════════════════════════════════════════╗
║         SESSION SUMMARY                  ║
╚══════════════════════════════════════════╝
  Runtime   : 00:12:34
  IPs Blocked: 3
  Blocked IPs:
    ✗ 45.33.32.156
    ✗ 192.168.100.5
    ✗ 10.0.0.99
```

---

## Key PHP Concepts Used (Viva Notes)

| Concept | Where used |
|---|---|
| **Associative array** | `$failedAttempts['ip'] = count` — O(1) lookup |
| **`preg_match()`** | Regex to extract IP from log lines |
| **`fseek()` + `fgets()`** | Tail-like real-time log following |
| **`clearstatcache()`** | Prevents PHP from caching stale file size |
| **`posix_getuid()`** | Root privilege verification |
| **`shell_exec()`** | Runs iptables to block IPs |
| **`escapeshellarg()`** | Sanitises IP before passing to shell |
| **`filter_var(FILTER_VALIDATE_IP)`** | Validates IP before using it |
| **`pcntl_signal(SIGINT)`** | Graceful Ctrl-C with summary output |
| **`usleep()`** | Polling delay — keeps CPU usage near zero |
