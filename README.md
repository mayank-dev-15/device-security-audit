# 🔒 Device Security Audit Script

A comprehensive Python security scanner that audits the overall security posture of your local device — Windows or Linux.

![Security](https://img.shields.io/badge/Security-Audit-red?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## 🎯 What It Checks

| # | Module | What It Scans |
|---|--------|---------------|
| 1 | **OS Information** | OS version, architecture, uptime |
| 2 | **Firewall** | Windows Firewall / UFW / iptables status & rules |
| 3 | **Open Ports** | Listening ports, risky port detection (FTP, Telnet, SMB, RDP, VNC) |
| 4 | **Antivirus / EDR** | Windows Defender, third-party AV, ClamAV, signature age |
| 5 | **User Accounts** | Local users, admin count, Guest account status |
| 6 | **Password Policy** | Min length, expiry, complexity requirements |
| 7 | **Disk Encryption** | BitLocker (Windows) / LUKS (Linux) |
| 8 | **Running Services** | Risky services (telnet, FTP, VNC, SNMP, TFTP) |
| 9 | **Network Connections** | Established connections, unusual remote ports |
| 10 | **Startup Items** | Registry startup, scheduled tasks, systemd, crontab |
| 11 | **OS Updates** | Pending updates, auto-update configuration |
| 12 | **Browser Security** | Chrome, Firefox, Edge detection & version |
| 13 | **Sharing & Remote** | Network shares, RDP, SSH config, password auth |
| 14 | **System Integrity** | UAC, DEP, SmartScreen, SELinux/AppArmor, ASLR |

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip

### Install Dependencies
```bash
pip install psutil requests
```

### Run the Audit
```bash
# Basic run (prints report + saves JSON)
python device_security_audit.py

# Save to specific file
python device_security_audit.py --output my_report.json

# Verbose mode
python device_security_audit.py --verbose
```

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║          🔒  DEVICE SECURITY AUDIT SCRIPT  🔒               ║
║          Comprehensive Local Security Scanner                ║
╚══════════════════════════════════════════════════════════════╝

[1/14] OS Information
  OS: Windows 11 (10.0.22631)
  Architecture: AMD64
  Hostname: DESKTOP-ABC123

[2/14] Firewall Status
  ✅ Firewall is ENABLED
  Active rules: 47

[3/14] Open Ports & Listening Services
  Total listening ports: 12
  ✅ No commonly risky ports detected

...

════════════════════════════════════════════════════════════════
  📊  SECURITY AUDIT SUMMARY
════════════════════════════════════════════════════════════════

  Total Checks:    32
  Passed:           28
  Failed:           4

  Severity Breakdown:
       CRITICAL: 1
           HIGH: 2
         MEDIUM: 1

  Overall Security Score: 72/100 (Grade: B)

  Failed Checks:
    [CRITICAL] BitLocker C:: Not encrypted
    [HIGH] Defender Real-Time: Disabled
    [HIGH] Pending Updates: 127 packages need updating
    [MEDIUM] Startup Items: 14 startup items (high)

  Recommendations:
    1. 🔧 Enable and configure the system firewall
    2. 🛡️  Enable real-time antivirus protection
    3. 🔐 Enable full-disk encryption (BitLocker/LUKS)
    4. 🔄 Install all pending OS and software updates
    5. 🚀 Review and minimize startup items

  📄 JSON report saved to: security_audit_DESKTOP-ABC123_20260606_143022.json
```

## 📄 JSON Report Structure

```json
{
  "timestamp": "2026-06-06T14:30:22.123456",
  "hostname": "DESKTOP-ABC123",
  "platform": "Windows",
  "total_checks": 32,
  "passed": 28,
  "failed": 4,
  "severity_breakdown": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 1
  },
  "overall_score": 72,
  "grade": "B",
  "results": [
    {
      "name": "Windows Firewall",
      "status": "PASS",
      "severity": "PASS",
      "detail": "All profiles ON",
      "score": 0
    }
  ]
}
```

## 🛡️ Security Grades

| Score | Grade | Meaning |
|-------|-------|---------|
| 90–100 | A+ | Excellent security posture |
| 80–89 | A | Very good |
| 70–79 | B | Good, minor issues |
| 60–69 | C | Fair, needs attention |
| 50–59 | D | Poor, significant risks |
| 0–49 | F | Critical — immediate action needed |

## ⚠️ Disclaimer

This script is for **educational and authorized security auditing purposes only**. Only run it on devices you own or have explicit permission to test. The authors are not responsible for any misuse.

## 📝 License

MIT License — feel free to use, modify, and distribute.

## 👤 Author

**Mayank Basena** ([@mayank-dev-15](https://github.com/mayank-dev-15))
