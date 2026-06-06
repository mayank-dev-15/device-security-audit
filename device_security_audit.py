"""
Device Security Audit Script
============================
A comprehensive Python script that audits the security posture of the local device.
Checks: open ports, firewall status, OS updates, antivirus, user accounts,
password policy, disk encryption, running services, network connections,
browser security, startup items, scheduled tasks, and more.

Usage:
    python device_security_audit.py [--output report.json] [--verbose]

Requirements:
    pip install psutil requests
"""

import os
import sys
import json
import socket
import subprocess
import platform
import datetime
import argparse
import hashlib
import re
from pathlib import Path

try:
    import psutil
except ImportError:
    print("[!] psutil not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "-q"])
    import psutil

try:
    import requests
except ImportError:
    requests = None  # Optional dependency


# ─── ANSI Colors ───────────────────────────────────────────────────────────────

class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║          🔒  DEVICE SECURITY AUDIT SCRIPT  🔒               ║
║          Comprehensive Local Security Scanner                ║
╚══════════════════════════════════════════════════════════════╝}
{C.RESET}""")


# ─── Helpers ───────────────────────────────────────────────────────────────────

def run_cmd(cmd, shell=True, timeout=30):
    """Run a shell command and return stdout, stderr, returncode."""
    try:
        r = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True,
            timeout=timeout, errors="replace"
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1


def severity(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    return "INFO"


def color_for_severity(sev):
    return {
        "CRITICAL": C.RED,
        "HIGH": C.RED,
        "MEDIUM": C.YELLOW,
        "LOW": C.CYAN,
        "INFO": C.GREEN,
    }.get(sev, C.RESET)


def check(name, passed, detail="", score=0):
    """Create a check result dict."""
    sev = severity(score) if not passed else "PASS"
    return {
        "name": name,
        "status": "PASS" if passed else "FAIL",
        "severity": sev,
        "detail": detail,
        "score": score,
    }


# ─── Audit Modules ─────────────────────────────────────────────────────────────

def audit_os_info():
    """Gather basic OS information."""
    print(f"\n{C.BOLD}{C.BLUE}[1/14] OS Information{C.RESET}")
    results = []

    system = platform.system()
    release = platform.release()
    version = platform.version()
    machine = platform.machine()
    hostname = socket.gethostname()

    print(f"  OS: {system} {release} ({version})")
    print(f"  Architecture: {machine}")
    print(f"  Hostname: {hostname}")
    print(f"  Python: {platform.python_version()}")

    # Check if OS is Windows 10/11 or Linux
    is_modern = False
    if system == "Windows":
        try:
            build = int(release)
            is_modern = build >= 10240
        except ValueError:
            pass
    elif system == "Linux":
        is_modern = True

    results.append(check("OS Version", is_modern,
                         f"{system} {release}", 0 if is_modern else 40))

    # Check last boot time
    try:
        boot = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.datetime.now() - boot
        print(f"  Last Boot: {boot:%Y-%m-%d %H:%M:%S} ({uptime.days}d {uptime.seconds//3600}h ago)")
        results.append(check("System Uptime", True,
                             f"Uptime: {uptime.days}d {uptime.seconds//3600}h", 0))
    except Exception as e:
        results.append(check("System Uptime", False, str(e), 10))

    return results


def audit_firewall():
    """Check firewall status."""
    print(f"\n{C.BOLD}{C.BLUE}[2/14] Firewall Status{C.RESET}")
    results = []
    system = platform.system()

    if system == "Windows":
        out, _, rc = run_cmd(
            'netsh advfirewall show allprofiles state'
        )
        if "ON" in out.upper():
            print(f"  {C.GREEN}✅ Firewall is ENABLED{C.RESET}")
            results.append(check("Windows Firewall", True, "All profiles ON", 0))
        else:
            print(f"  {C.RED}❌ Firewall is DISABLED{C.RESET}")
            results.append(check("Windows Firewall", False, "Firewall is OFF", 80))

        # Check firewall rules count
        out2, _, _ = run_cmd('netsh advfirewall firewall show rule name=all | findstr "Rule Name"')
        rule_count = len(out2.splitlines()) if out2 else 0
        print(f"  Active rules: {rule_count}")
        results.append(check("Firewall Rules", rule_count > 0,
                             f"{rule_count} rules configured", 0 if rule_count > 0 else 30))

    elif system == "Linux":
        # Check ufw
        out, _, rc = run_cmd("ufw status 2>/dev/null")
        if rc == 0 and "active" in out.lower():
            print(f"  {C.GREEN}✅ UFW is ACTIVE{C.RESET}")
            results.append(check("UFW Firewall", True, "UFW is active", 0))
        else:
            # Check iptables
            out2, _, rc2 = run_cmd("iptables -L -n 2>/dev/null | head -5")
            if rc2 == 0 and out2:
                print(f"  {C.YELLOW}⚠️  iptables rules found but UFW inactive{C.RESET}")
                results.append(check("Linux Firewall", True, "iptables rules present", 20))
            else:
                print(f"  {C.RED}❌ No active firewall detected{C.RESET}")
                results.append(check("Linux Firewall", False, "No firewall active", 80))

    return results


def audit_open_ports():
    """Scan for listening ports."""
    print(f"\n{C.BOLD}{C.BLUE}[3/14] Open Ports & Listening Services{C.RESET}")
    results = []
    risky_ports = {21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS",
                   445: "SMB", 1433: "MSSQL", 3389: "RDP", 5900: "VNC"}

    listeners = []
    risky = []

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            port = conn.laddr.port
            pid = conn.pid
            try:
                proc = psutil.Process(pid).name() if pid else "Unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc = "Unknown"
            listeners.append((port, proc))
            if port in risky_ports:
                risky.append((port, risky_ports[port], proc))

    print(f"  Total listening ports: {len(listeners)}")

    for port, proc in sorted(listeners):
        flag = " ⚠️" if port in risky_ports else ""
        print(f"    Port {port:>5} — {proc}{flag}")

    if risky:
        print(f"\n  {C.RED}⚠️  Risky ports detected:{C.RESET}")
        for port, svc, proc in risky:
            print(f"    Port {port} ({svc}) — {proc}")
        results.append(check("Risky Ports", False,
                             f"{len(risky)} risky ports open: {[p[0] for p in risky]}", 70))
    else:
        print(f"  {C.GREEN}✅ No commonly risky ports detected{C.RESET}")
        results.append(check("Risky Ports", True, "No risky ports open", 0))

    # Check for too many open ports
    if len(listeners) > 50:
        results.append(check("Port Count", False,
                             f"{len(listeners)} listening ports (high)", 40))
    else:
        results.append(check("Port Count", True,
                             f"{len(listeners)} listening ports", 0))

    return results


def audit_antivirus():
    """Check antivirus / Windows Defender status."""
    print(f"\n{C.BOLD}{C.BLUE}[4/14] Antivirus / EDR Status{C.RESET}")
    results = []
    system = platform.system()

    if system == "Windows":
        # Windows Defender
        out, _, rc = run_cmd(
            'powershell -Command "Get-MpComputerStatus | Select-Object '
            'RealTimeProtectionEnabled, AntivirusEnabled, AntivirusSignatureLastUpdated | Format-List"'
        )
        if "True" in out:
            print(f"  {C.GREEN}✅ Windows Defender Real-Time Protection: ON{C.RESET}")
            results.append(check("Defender Real-Time", True, "Enabled", 0))
        else:
            print(f"  {C.RED}❌ Windows Defender Real-Time Protection: OFF{C.RESET}")
            results.append(check("Defender Real-Time", False, "Disabled", 80))

        # Check for other AV via WMI
        out2, _, rc2 = run_cmd(
            'powershell -Command "Get-CimInstance -Namespace root/SecurityCenter2 '
            '-ClassName AntiVirusProduct | Select-Object displayName | Format-List"'
        )
        av_names = [line.split(":")[-1].strip() for line in out2.splitlines() if ":" in line]
        if av_names:
            for av in av_names:
                print(f"  🛡️  AV Product: {av}")
            results.append(check("Antivirus Installed", True,
                                 f"Found: {', '.join(av_names)}", 0))
        else:
            print(f"  {C.YELLOW}⚠️  No third-party AV detected{C.RESET}")
            results.append(check("Antivirus Installed", False,
                                 "No AV products found", 60))

        # Check signature age
        out3, _, _ = run_cmd(
            'powershell -Command "(Get-MpComputerStatus).AntivirusSignatureLastUpdated"'
        )
        if out3:
            print(f"  Last signature update: {out3.strip()}")
            results.append(check("AV Signatures", True,
                                 f"Updated: {out3.strip()}", 0))

    elif system == "Linux":
        # Check for ClamAV
        out, _, rc = run_cmd("clamdscan --version 2>/dev/null")
        if rc == 0:
            print(f"  {C.GREEN}✅ ClamAV detected: {out}{C.RESET}")
            results.append(check("Antivirus", True, f"ClamAV: {out}", 0))
        else:
            print(f"  {C.YELLOW}⚠️  No ClamAV detected (Linux — less critical){C.RESET}")
            results.append(check("Antivirus", True,
                                 "No AV (Linux — acceptable)", 10))

    return results


def audit_user_accounts():
    """Check user accounts and privileges."""
    print(f"\n{C.BOLD}{C.BLUE}[5/14] User Accounts & Privileges{C.RESET}")
    results = []
    system = platform.system()

    if system == "Windows":
        # List local users
        out, _, _ = run_cmd('net user')
        users = [line.strip() for line in out.splitlines()
                 if line.strip() and not line.startswith("---")
                 and "command completed" not in line.lower()
                 and "User accounts" not in line]
        print(f"  Local users found: {len(users)}")
        for u in users:
            print(f"    👤 {u}")

        # Check admin group
        out2, _, _ = run_cmd('net localgroup administrators')
        admins = [line.strip() for line in out2.splitlines()
                  if line.strip() and not line.startswith("---")
                  and "command completed" not in line.lower()
                  and "Members" not in line and "Alias" not in line]
        print(f"\n  Administrators ({len(admins)}):")
        for a in admins:
            print(f"    🔑 {a}")

        if len(admins) > 2:
            results.append(check("Admin Count", False,
                                 f"{len(admins)} admin accounts (too many)", 50))
        else:
            results.append(check("Admin Count", True,
                                 f"{len(admins)} admin accounts", 0))

        # Check Guest account
        out3, _, _ = run_cmd('net user Guest')
        if "active yes" in out3.lower():
            print(f"  {C.RED}❌ Guest account is ACTIVE{C.RESET}")
            results.append(check("Guest Account", False, "Guest account is active", 60))
        else:
            print(f"  {C.GREEN}✅ Guest account is disabled{C.RESET}")
            results.append(check("Guest Account", True, "Guest account disabled", 0))

    elif system == "Linux":
        # Check /etc/passwd for users with shell
        try:
            with open("/etc/passwd") as f:
                shell_users = [line for line in f if line.strip()
                               and not line.startswith("#")
                               and ("/bin/bash" in line or "/bin/sh" in line)]
            print(f"  Users with shell access: {len(shell_users)}")
            for u in shell_users:
                print(f"    👤 {u.split(':')[0]}")
            results.append(check("Shell Users", len(shell_users) <= 5,
                                 f"{len(shell_users)} users with shell", 0 if len(shell_users) <= 5 else 30))
        except Exception as e:
            results.append(check("Shell Users", False, str(e), 10))

        # Check sudo users
        out, _, _ = run_cmd("getent group sudo 2>/dev/null || getent group wheel 2>/dev/null")
        if out:
            sudoers = out.split(":")[-1].strip().split(",")
            print(f"  Sudo users: {', '.join(sudoers)}")
            results.append(check("Sudo Users", len(sudoers) <= 3,
                                 f"{len(sudoers)} sudo users", 0 if len(sudoers) <= 3 else 30))

    return results


def audit_password_policy():
    """Check password policy."""
    print(f"\n{C.BOLD}{C.BLUE}[6/14] Password Policy{C.RESET}")
    results = []
    system = platform.system()

    if system == "Windows":
        out, _, _ = run_cmd('net accounts')
        print(f"  {out}")

        # Parse key values
        min_len = 0
        max_age = 0
        for line in out.splitlines():
            if "Minimum password length" in line:
                try:
                    min_len = int(line.split(":")[-1].strip())
                except ValueError:
                    pass
            if "Maximum password age" in line:
                val = line.split(":")[-1].strip()
                if val.lower() != "unlimited":
                    try:
                        max_age = int(val.split()[0])
                    except (ValueError, IndexError):
                        pass

        results.append(check("Min Password Length", min_len >= 8,
                             f"Minimum length: {min_len}", 0 if min_len >= 8 else 50))
        results.append(check("Password Expiry", max_age > 0 and max_age <= 90,
                             f"Max age: {max_age} days", 0 if 0 < max_age <= 90 else 40))

    elif system == "Linux":
        # Check /etc/login.defs
        try:
            with open("/etc/login.defs") as f:
                defs = f.read()
            pass_max_days = 0
            pass_min_days = 0
            pass_min_len = 0
            for line in defs.splitlines():
                if line.startswith("PASS_MAX_DAYS"):
                    try:
                        pass_max_days = int(line.split()[1])
                    except (ValueError, IndexError):
                        pass
                elif line.startswith("PASS_MIN_DAYS"):
                    try:
                        pass_min_days = int(line.split()[1])
                    except (ValueError, IndexError):
                        pass
                elif line.startswith("PASS_MIN_LEN"):
                    try:
                        pass_min_len = int(line.split()[1])
                    except (ValueError, IndexError):
                        pass

            print(f"  Max password age: {pass_max_days} days")
            print(f"  Min password age: {pass_min_days} days")
            print(f"  Min password length: {pass_min_len}")

            results.append(check("Max Password Age",
                                 pass_max_days > 0 and pass_max_days <= 90,
                                 f"{pass_max_days} days", 0 if 0 < pass_max_days <= 90 else 40))
            results.append(check("Min Password Length", pass_min_len >= 8,
                                 f"{pass_min_len} chars", 0 if pass_min_len >= 8 else 50))
        except Exception as e:
            results.append(check("Password Policy", False, str(e), 20))

    return results


def audit_disk_encryption():
    """Check disk encryption status."""
    print(f"\n{C.BOLD}{C.BLUE}[7/14] Disk Encryption{C.RESET}")
    results = []
    system = platform.system()

    if system == "Windows":
        out, _, rc = run_cmd('manage-bde -status C:')
        if "Protection On" in out or "Fully Encrypted" in out:
            print(f"  {C.GREEN}✅ BitLocker is ENABLED on C:{C.RESET}")
            results.append(check("BitLocker C:", True, "Encryption enabled", 0))
        elif rc == 0:
            print(f"  {C.RED}❌ BitLocker is NOT enabled on C:{C.RESET}")
            results.append(check("BitLocker C:", False, "Not encrypted", 70))
        else:
            print(f"  {C.YELLOW}⚠️  Could not determine BitLocker status{C.RESET}")
            results.append(check("BitLocker C:", False, "Status unknown", 30))

    elif system == "Linux":
        # Check LUKS
        out, _, rc = run_cmd("lsblk -o NAME,FSTYPE 2>/dev/null | grep crypto_LUKS")
        if rc == 0 and out.strip():
            print(f"  {C.GREEN}✅ LUKS encryption detected{C.RESET}")
            results.append(check("LUKS Encryption", True, "Encrypted volumes found", 0))
        else:
            # Check if root is on encrypted volume
            out2, _, _ = run_cmd("findmnt -n -o FSTYPE /")
            if "crypt" in out2.lower():
                print(f"  {C.GREEN}✅ Root filesystem is encrypted{C.RESET}")
                results.append(check("Root Encryption", True, "Encrypted root", 0))
            else:
                print(f"  {C.RED}❌ No disk encryption detected{C.RESET}")
                results.append(check("Disk Encryption", False, "No encryption found", 70))

    return results


def audit_running_services():
    """Check running services."""
    print(f"\n{C.BOLD}{C.BLUE}[8/14] Running Services{C.RESET}")
    results = []
    risky_services = {
        "telnet": "Telnet (insecure)",
        "ftp": "FTP (insecure)",
        "vnc": "VNC (remote access)",
        "sshd": "SSH (verify config)",
        "rdp": "Remote Desktop",
        "snmp": "SNMP (potential risk)",
        "tftp": "TFTP (insecure)",
    }

    running = []
    risky = []

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            running.append(name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    for svc, desc in risky_services.items():
        matches = [p for p in running if svc in p]
        if matches:
            risky.append((svc, desc, matches))

    total = len(set(running))
    print(f"  Total running processes: {total}")

    if risky:
        print(f"\n  {C.YELLOW}⚠️  Potentially risky services:{C.RESET}")
        for svc, desc, procs in risky:
            print(f"    {svc}: {desc} ({', '.join(set(procs))})")
        results.append(check("Risky Services", False,
                             f"{len(risky)} risky services running", 60))
    else:
        print(f"  {C.GREEN}✅ No commonly risky services detected{C.RESET}")
        results.append(check("Risky Services", True, "No risky services", 0))

    return results


def audit_network_connections():
    """Check active network connections."""
    print(f"\n{C.BOLD}{C.BLUE}[9/14] Active Network Connections{C.RESET}")
    results = []

    connections = psutil.net_connections(kind='inet')
    established = [c for c in connections if c.status == 'ESTABLISHED']
    listening = [c for c in connections if c.status == 'LISTEN']

    print(f"  Established: {len(established)}")
    print(f"  Listening:   {len(listening)}")

    # Check for connections to unusual ports
    unusual = []
    safe_remote = {80, 443, 53, 123, 8080, 8443}
    for c in established:
        if c.raddr and c.raddr.port not in safe_remote:
            unusual.append((c.laddr, c.raddr))

    if unusual:
        print(f"\n  {C.YELLOW}⚠️  Connections to non-standard ports:{C.RESET}")
        seen = set()
        for local, remote in unusual[:10]:
            key = f"{local} -> {remote}"
            if key not in seen:
                seen.add(key)
                print(f"    {local} → {remote}")
        results.append(check("Unusual Connections", False,
                             f"{len(unusual)} connections to non-standard ports", 40))
    else:
        results.append(check("Unusual Connections", True,
                             "All connections to standard ports", 0))

    return results


def audit_startup_items():
    """Check startup items and scheduled tasks."""
    print(f"\n{C.BOLD}{C.BLUE}[10/14] Startup Items & Scheduled Tasks{C.RESET}")
    results = []
    system = platform.system()

    if system == "Windows":
        # Registry startup
        out, _, _ = run_cmd(
            'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" 2>nul'
        )
        items = [line for line in out.splitlines() if line.strip() and "REG_" in line]
        print(f"  User startup items: {len(items)}")
        for item in items:
            print(f"    🚀 {item.strip()}")

        # Scheduled tasks
        out2, _, _ = run_cmd('schtasks /query /fo LIST 2>nul | findstr "TaskName"')
        tasks = [line for line in out2.splitlines() if line.strip()]
        print(f"  Scheduled tasks: {len(tasks)}")

        if len(items) > 10:
            results.append(check("Startup Items", False,
                                 f"{len(items)} startup items (high)", 30))
        else:
            results.append(check("Startup Items", True,
                                 f"{len(items)} startup items", 0))

    elif system == "Linux":
        # Check systemd services
        out, _, _ = run_cmd("systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -30")
        services = [line for line in out.splitlines() if "enabled" in line]
        print(f"  Enabled systemd services: {len(services)}")
        for s in services[:10]:
            print(f"    ⚙️  {s.split()[0]}")

        # Check crontab
        out2, _, _ = run_cmd("crontab -l 2>/dev/null")
        if out2:
            cron_lines = [l for l in out2.splitlines() if l.strip() and not l.startswith("#")]
            print(f"  Crontab entries: {len(cron_lines)}")
            results.append(check("Crontab", len(cron_lines) <= 10,
                                 f"{len(cron_lines)} cron entries", 0 if len(cron_lines) <= 10 else 20))

        results.append(check("Systemd Services", len(services) <= 30,
                             f"{len(services)} enabled services", 0 if len(services) <= 30 else 20))

    return results


def audit_updates():
    """Check for pending OS updates."""
    print(f"\n{C.BOLD}{C.BLUE}[11/14] OS Updates{C.RESET}")
    results = []
    system = platform.system()

    if system == "Windows":
        out, _, rc = run_cmd(
            'powershell -Command "Get-WmiObject -Class Win32_QuickFixEngineering | '
            'Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID, InstalledOn | Format-List"'
        )
        if out:
            print(f"  Recent updates:\n{out}")
            results.append(check("Recent Updates", True, "Updates found", 0))

        # Check for pending updates
        out2, _, _ = run_cmd(
            'powershell -Command "(New-Object -ComObject Microsoft.Update.AutoUpdate).Settings.NotificationLevel"'
        )
        if out2.strip() in ("1", "2"):
            print(f"  {C.YELLOW}⚠️  Auto-update notifications may be disabled{C.RESET}")
            results.append(check("Auto-Update", False, "Auto-update may be disabled", 40))
        else:
            print(f"  {C.GREEN}✅ Auto-update appears configured{C.RESET}")
            results.append(check("Auto-Update", True, "Auto-update configured", 0))

    elif system == "Linux":
        # Check apt updates
        out, _, rc = run_cmd("apt list --upgradable 2>/dev/null | wc -l")
        try:
            count = int(out.strip()) - 1 if out.strip().isdigit() else 0
            count = max(0, count)
        except ValueError:
            count = 0

        if count > 0:
            print(f"  {C.YELLOW}⚠️  {count} packages have pending updates{C.RESET}")
            results.append(check("Pending Updates", count < 50,
                                 f"{count} packages need updating", 50 if count >= 50 else 20))
        else:
            print(f"  {C.GREEN}✅ System is up to date{C.RESET}")
            results.append(check("Pending Updates", True, "System up to date", 0))

    return results


def audit_browser_security():
    """Check browser installations and basic security."""
    print(f"\n{C.BOLD}{C.BLUE}[12/14] Browser Security{C.RESET}")
    results = []
    system = platform.system()

    browsers = {
        "Chrome": {
            "win": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "lin": "/usr/bin/google-chrome",
        },
        "Firefox": {
            "win": r"C:\Program Files\Mozilla Firefox\firefox.exe",
            "lin": "/usr/bin/firefox",
        },
        "Edge": {
            "win": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "lin": "/usr/bin/microsoft-edge",
        },
    }

    found = []
    for name, paths in browsers.items():
        key = "win" if system == "Windows" else "lin"
        path = paths.get(key, "")
        if os.path.exists(path):
            found.append(name)
            print(f"  🌐 {name}: {path}")

            # Check if browser is outdated (basic version check)
            out, _, _ = run_cmd(f'"{path}" --version 2>nul' if system == "Windows"
                                else f"{path} --version 2>/dev/null")
            if out:
                print(f"     Version: {out.strip()}")

    if not found:
        print(f"  {C.YELLOW}⚠️  No common browsers found in default locations{C.RESET}")

    results.append(check("Browsers Found", len(found) > 0,
                         f"Found: {', '.join(found) if found else 'None'}", 0))

    return results


def audit_sharing_settings():
    """Check file/printer sharing settings."""
    print(f"\n{C.BOLD}{C.BLUE}[13/14] Sharing & Remote Access{C.RESET}")
    results = []
    system = platform.system()

    if system == "Windows":
        # Check network sharing
        out, _, _ = run_cmd('net share')
        shares = [line for line in out.splitlines()
                  if line.strip() and not line.startswith("---")
                  and "command completed" not in line.lower()
                  and "Share name" not in line]
        print(f"  Network shares: {len(shares)}")
        for s in shares:
            print(f"    📁 {s.strip()}")

        if len(shares) > 3:
            results.append(check("Network Shares", False,
                                 f"{len(shares} shares (high)", 40))
        else:
            results.append(check("Network Shares", True,
                                 f"{len(shares)} shares", 0))

        # Check RDP
        out2, _, _ = run_cmd(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections'
        )
        if "0x0" in out2:
            print(f"  {C.YELLOW}⚠️  Remote Desktop is ENABLED{C.RESET}")
            results.append(check("Remote Desktop", True, "RDP enabled (verify if needed)", 20))
        else:
            print(f"  {C.GREEN}✅ Remote Desktop is DISABLED{C.RESET}")
            results.append(check("Remote Desktop", True, "RDP disabled", 0))

    elif system == "Linux":
        # Check SSH
        out, _, rc = run_cmd("systemctl is-active sshd 2>/dev/null || service ssh status 2>/dev/null")
        if "active" in out.lower():
            print(f"  {C.YELLOW}⚠️  SSH server is running{C.RESET}")
            results.append(check("SSH Server", True, "SSH active (verify config)", 10))

            # Check for password auth
            out2, _, _ = run_cmd("grep -i 'PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null")
            if "yes" in out2.lower():
                print(f"  {C.RED}❌ SSH password authentication is ENABLED{C.RESET}")
                results.append(check("SSH Password Auth", False,
                                     "Password auth enabled (use keys)", 50))
            else:
                print(f"  {C.GREEN}✅ SSH password auth appears disabled{C.RESET}")
                results.append(check("SSH Password Auth", True,
                                     "Password auth disabled", 0))
        else:
            print(f"  {C.GREEN}✅ SSH server is not running{C.RESET}")
            results.append(check("SSH Server", True, "SSH not running", 0))

    return results


def audit_system_integrity():
    """Check system file integrity and security features."""
    print(f"\n{C.BOLD}{C.BLUE}[14/14] System Integrity & Security Features{C.RESET}")
    results = []
    system = platform.system()

    if system == "Windows":
        # Check Windows Defender SmartScreen
        out, _, _ = run_cmd(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" /v SmartScreenEnabled'
        )
        if "On" in out or "RequireAdmin" in out:
            print(f"  {C.GREEN}✅ SmartScreen is ENABLED{C.RESET}")
            results.append(check("SmartScreen", True, "Enabled", 0))
        else:
            print(f"  {C.YELLOW}⚠️  SmartScreen status unknown or disabled{C.RESET}")
            results.append(check("SmartScreen", False, "Disabled or unknown", 40))

        # Check DEP
        out2, _, _ = run_cmd(
            'bcdedit /enum {current} | findstr nx'
        )
        if "OptIn" in out2 or "AlwaysOn" in out2:
            print(f"  {C.GREEN}✅ DEP (Data Execution Prevention) is ON{C.RESET}")
            results.append(check("DEP", True, "Enabled", 0))
        else:
            print(f"  {C.YELLOW}⚠️  DEP status unclear{C.RESET}")
            results.append(check("DEP", False, "Status unclear", 30))

        # Check UAC
        out3, _, _ = run_cmd(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA'
        )
        if "0x1" in out3:
            print(f"  {C.GREEN}✅ UAC is ENABLED{C.RESET}")
            results.append(check("UAC", True, "Enabled", 0))
        else:
            print(f"  {C.RED}❌ UAC is DISABLED{C.RESET}")
            results.append(check("UAC", False, "Disabled", 70))

    elif system == "Linux":
        # Check SELinux / AppArmor
        out, _, _ = run_cmd("getenforce 2>/dev/null")
        if out.strip().lower() == "enforcing":
            print(f"  {C.GREEN}✅ SELinux is ENFORCING{C.RESET}")
            results.append(check("SELinux", True, "Enforcing", 0))
        else:
            out2, _, _ = run_cmd("aa-status 2>/dev/null | head -1")
            if "apparmor" in out2.lower():
                print(f"  {C.GREEN}✅ AppArmor is active{C.RESET}")
                results.append(check("AppArmor", True, "Active", 0))
            else:
                print(f"  {C.YELLOW}⚠️  No MAC (SELinux/AppArmor) detected{C.RESET}")
                results.append(check("MAC Security", False, "No SELinux/AppArmor", 50))

        # Check kernel ASLR
        out3, _, _ = run_cmd("cat /proc/sys/kernel/randomize_va_space")
        if out3.strip() == "2":
            print(f"  {C.GREEN}✅ ASLR is fully enabled{C.RESET}")
            results.append(check("ASLR", True, "Full randomization", 0))
        else:
            print(f"  {C.YELLOW}⚠️  ASLR may not be fully enabled{C.RESET}")
            results.append(check("ASLR", False, f"Value: {out3.strip()}", 30))

    return results


# ─── Report Generation ─────────────────────────────────────────────────────────

def generate_report(all_results):
    """Generate a summary report."""
    print(f"\n{C.BOLD}{'='*64}")
    print(f"  📊  SECURITY AUDIT SUMMARY")
    print(f"{'='*64}{C.RESET}\n")

    total = len(all_results)
    passed = sum(1 for r in all_results if r["status"] == "PASS")
    failed = total - passed

    # Severity breakdown
    sev_counts = {}
    for r in all_results:
        s = r["severity"]
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # Calculate overall score
    max_score = sum(r["score"] for r in all_results)
    # Invert: lower score = better security
    overall_score = max(0, 100 - max_score) if max_score < 100 else 0

    print(f"  Total Checks:    {total}")
    print(f"  {C.GREEN}Passed:           {passed}{C.RESET}")
    print(f"  {C.RED}Failed:           {failed}{C.RESET}")
    print(f"\n  Severity Breakdown:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sev_counts.get(sev, 0)
        if count > 0:
            color = color_for_severity(sev)
            print(f"    {color}{sev:>10}: {count}{C.RESET}")

    # Overall grade
    if overall_score >= 90:
        grade = "A+"
        grade_color = C.GREEN
    elif overall_score >= 80:
        grade = "A"
        grade_color = C.GREEN
    elif overall_score >= 70:
        grade = "B"
        grade_color = C.CYAN
    elif overall_score >= 60:
        grade = "C"
        grade_color = C.YELLOW
    elif overall_score >= 50:
        grade = "D"
        grade_color = C.YELLOW
    else:
        grade = "F"
        grade_color = C.RED

    print(f"\n  {C.BOLD}Overall Security Score: {grade_color}{overall_score}/100 (Grade: {grade}){C.RESET}")

    # Failed checks detail
    if failed > 0:
        print(f"\n  {C.RED}{C.BOLD}Failed Checks:{C.RESET}")
        for r in all_results:
            if r["status"] == "FAIL":
                color = color_for_severity(r["severity"])
                print(f"    {color}[{r['severity']}] {r['name']}: {r['detail']}{C.RESET}")

    # Recommendations
    print(f"\n  {C.CYAN}{C.BOLD}Recommendations:{C.RESET}")
    recs = set()
    for r in all_results:
        if r["status"] == "FAIL":
            name_lower = r["name"].lower()
            if "firewall" in name_lower:
                recs.add("🔧 Enable and configure the system firewall")
            if "defender" in name_lower or "antivirus" in name_lower or "av " in name_lower:
                recs.add("🛡️  Enable real-time antivirus protection")
            if "bitlocker" in name_lower or "encrypt" in name_lower:
                recs.add("🔐 Enable full-disk encryption (BitLocker/LUKS)")
            if "password" in name_lower:
                recs.add("🔑 Enforce strong password policies (min 8 chars, expiry)")
            if "admin" in name_lower:
                recs.add("👤 Reduce the number of administrator accounts")
            if "guest" in name_lower:
                recs.add("🚫 Disable the Guest account")
            if "port" in name_lower:
                recs.add("🔒 Close unnecessary open ports")
            if "update" in name_lower:
                recs.add("🔄 Install all pending OS and software updates")
            if "rdp" in name_lower or "remote" in name_lower:
                recs.add("🖥️  Disable Remote Desktop if not needed")
            if "uac" in name_lower:
                recs.add("🔐 Enable User Account Control (UAC)")
            if "smart" in name_lower:
                recs.add("🛡️  Enable Windows SmartScreen")
            if "dep" in name_lower:
                recs.add("🔒 Enable Data Execution Prevention (DEP)")
            if "selinux" in name_lower or "apparmor" in name_lower:
                recs.add("🛡️  Enable SELinux or AppArmor mandatory access controls")
            if "aslr" in name_lower:
                recs.add("🔒 Ensure kernel ASLR is fully enabled")
            if "ssh" in name_lower:
                recs.add("🔑 Disable SSH password authentication; use key-based auth")
            if "startup" in name_lower:
                recs.add("🚀 Review and minimize startup items")
            if "share" in name_lower:
                recs.add("📁 Review and disable unnecessary network shares")

    for i, rec in enumerate(sorted(recs), 1):
        print(f"    {i}. {rec}")

    if not recs:
        print(f"    {C.GREEN}✅ No critical recommendations — system looks secure!{C.RESET}")

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "severity_breakdown": sev_counts,
        "overall_score": overall_score,
        "grade": grade,
        "results": all_results,
    }


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🔒 Device Security Audit Script — Comprehensive local security scanner"
    )
    parser.add_argument("--output", "-o", default=None,
                        help="Save JSON report to file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    args = parser.parse_args()

    banner()

    all_results = []

    # Run all audit modules
    all_results.extend(audit_os_info())
    all_results.extend(audit_firewall())
    all_results.extend(audit_open_ports())
    all_results.extend(audit_antivirus())
    all_results.extend(audit_user_accounts())
    all_results.extend(audit_password_policy())
    all_results.extend(audit_disk_encryption())
    all_results.extend(audit_running_services())
    all_results.extend(audit_network_connections())
    all_results.extend(audit_startup_items())
    all_results.extend(audit_updates())
    all_results.extend(audit_browser_security())
    all_results.extend(audit_sharing_settings())
    all_results.extend(audit_system_integrity())

    # Generate report
    report = generate_report(all_results)

    # Save JSON report
    if args.output:
        out_path = args.output
    else:
        out_path = f"security_audit_{socket.gethostname()}_{datetime.datetime.now():%Y%m%d_%H%M%S}.json"

    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n  📄 JSON report saved to: {out_path}")
    print(f"\n{C.BOLD}{C.GREEN}✅ Audit complete!{C.RESET}\n")


if __name__ == "__main__":
    main()
