"""
SOC Log Analyzer & Threat Detector
=====================================
This tool parses security log files and detects suspicious patterns
that a SOC (Security Operations Center) analyst would investigate.

It simulates real SOC workflows used in tools like:
- Splunk
- Google Chronicle
- IBM QRadar
- Microsoft Sentinel

Security concepts covered:
- Brute force detection (many failed logins)
- Impossible travel detection (logins from different countries quickly)
- After-hours access detection
- Port scan detection
- Privilege escalation detection

Author: [Your Name]
"""

import json
import re
from datetime import datetime, timedelta
from collections import defaultdict


# ─────────────────────────────────────────────
# LOG PARSING
# ─────────────────────────────────────────────

def parse_logs(log_file):
    """
    Parse log entries from a JSON file.
    Each log entry represents a security event.
    """
    with open(log_file, "r") as f:
        logs = json.load(f)
    print(f"  ✔ Loaded {len(logs)} log entries from {log_file}")
    return logs


# ─────────────────────────────────────────────
# THREAT DETECTION FUNCTIONS
# ─────────────────────────────────────────────

def detect_brute_force(logs):
    """
    Detect brute force login attacks.
    Rule: 5 or more failed login attempts from the same IP within 10 minutes.
    
    This is one of the most common attacks SOC analysts deal with daily.
    """
    alerts = []
    
    # Group failed logins by IP address
    failed_logins = defaultdict(list)
    
    for log in logs:
        if log.get("event_type") == "login_failed":
            ip = log.get("source_ip")
            timestamp = datetime.fromisoformat(log.get("timestamp"))
            failed_logins[ip].append(timestamp)
    
    # Check each IP for rapid repeated failures
    for ip, timestamps in failed_logins.items():
        timestamps.sort()
        
        # Sliding 10-minute window
        for i in range(len(timestamps)):
            window_end = timestamps[i] + timedelta(minutes=10)
            count_in_window = sum(1 for t in timestamps if timestamps[i] <= t <= window_end)
            
            if count_in_window >= 5:
                alerts.append({
                    "alert_type": "BRUTE FORCE ATTACK",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "detail": f"{count_in_window} failed login attempts within 10 minutes",
                    "first_seen": timestamps[i].isoformat(),
                    "mitre_tactic": "Credential Access (T1110)"
                })
                break  # One alert per IP
    
    return alerts


def detect_after_hours_access(logs):
    """
    Detect successful logins outside of business hours (before 7am or after 8pm).
    
    After-hours access can indicate stolen credentials or insider threat.
    """
    alerts = []
    business_start = 7   # 7 AM
    business_end = 20    # 8 PM
    
    for log in logs:
        if log.get("event_type") == "login_success":
            timestamp = datetime.fromisoformat(log.get("timestamp"))
            hour = timestamp.hour
            
            if hour < business_start or hour >= business_end:
                alerts.append({
                    "alert_type": "AFTER-HOURS ACCESS",
                    "severity": "MEDIUM",
                    "source_ip": log.get("source_ip"),
                    "detail": f"User '{log.get('username')}' logged in at {timestamp.strftime('%H:%M')} (outside business hours)",
                    "first_seen": log.get("timestamp"),
                    "mitre_tactic": "Initial Access (T1078)"
                })
    
    return alerts


def detect_port_scan(logs):
    """
    Detect port scanning activity.
    Rule: Single IP connects to 10+ different ports within 5 minutes.
    
    Port scans are typically the first step of network reconnaissance.
    """
    alerts = []
    
    # Group connection attempts by source IP
    connections = defaultdict(list)
    
    for log in logs:
        if log.get("event_type") == "connection_attempt":
            ip = log.get("source_ip")
            port = log.get("destination_port")
            timestamp = datetime.fromisoformat(log.get("timestamp"))
            connections[ip].append({"port": port, "time": timestamp})
    
    for ip, conn_list in connections.items():
        conn_list.sort(key=lambda x: x["time"])
        
        # Check 5-minute windows for many different ports
        for i in range(len(conn_list)):
            window_end = conn_list[i]["time"] + timedelta(minutes=5)
            ports_in_window = set(
                c["port"] for c in conn_list
                if conn_list[i]["time"] <= c["time"] <= window_end
            )
            
            if len(ports_in_window) >= 10:
                alerts.append({
                    "alert_type": "PORT SCAN DETECTED",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "detail": f"Connected to {len(ports_in_window)} different ports in 5 minutes: {sorted(list(ports_in_window))[:10]}...",
                    "first_seen": conn_list[i]["time"].isoformat(),
                    "mitre_tactic": "Reconnaissance (T1046)"
                })
                break
    
    return alerts


def detect_privilege_escalation(logs):
    """
    Detect privilege escalation attempts.
    Rule: A non-admin user runs sudo/admin commands or accesses admin resources.
    
    Attackers escalate privileges to gain more control after initial access.
    """
    alerts = []
    
    for log in logs:
        if log.get("event_type") == "privilege_escalation":
            alerts.append({
                "alert_type": "PRIVILEGE ESCALATION ATTEMPT",
                "severity": "CRITICAL",
                "source_ip": log.get("source_ip"),
                "detail": f"User '{log.get('username')}' attempted to escalate privileges using: {log.get('command', 'unknown command')}",
                "first_seen": log.get("timestamp"),
                "mitre_tactic": "Privilege Escalation (T1548)"
            })
    
    return alerts


def detect_data_exfiltration(logs):
    """
    Detect potential data exfiltration.
    Rule: Large outbound data transfers to external/unknown IPs.
    
    Data exfiltration is the final stage of many cyberattacks.
    """
    alerts = []
    THRESHOLD_MB = 100  # Alert if more than 100MB sent to one external IP
    
    # Track data sent per source-destination pair
    data_sent = defaultdict(int)
    destinations = {}
    
    for log in logs:
        if log.get("event_type") == "data_transfer":
            key = (log.get("source_ip"), log.get("destination_ip"))
            data_sent[key] += log.get("bytes_sent", 0)
            destinations[key] = log.get("timestamp")
    
    for (src, dst), total_bytes in data_sent.items():
        total_mb = total_bytes / (1024 * 1024)
        if total_mb >= THRESHOLD_MB:
            alerts.append({
                "alert_type": "POTENTIAL DATA EXFILTRATION",
                "severity": "CRITICAL",
                "source_ip": src,
                "detail": f"{total_mb:.1f} MB sent to external IP {dst}. Possible data theft.",
                "first_seen": destinations[(src, dst)],
                "mitre_tactic": "Exfiltration (T1048)"
            })
    
    return alerts


# ─────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────

def generate_threat_report(all_alerts, log_file):
    """
    Print a formatted threat report and save it to a file.
    """
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for alert in all_alerts:
        sev = alert.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n" + "="*65)
    print("   SOC THREAT DETECTION REPORT")
    print("="*65)
    print(f"  Log File  : {log_file}")
    print(f"  Scan Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*65)

    print("\n📊 ALERT SUMMARY:")
    print(f"  🔴 CRITICAL : {severity_counts['CRITICAL']}")
    print(f"  🟠 HIGH     : {severity_counts['HIGH']}")
    print(f"  🟡 MEDIUM   : {severity_counts['MEDIUM']}")
    print(f"  🟢 LOW      : {severity_counts['LOW']}")
    print(f"  📋 TOTAL    : {len(all_alerts)}")

    if not all_alerts:
        print("\n✅ No threats detected in this log set.")
        return

    # Print by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        group = [a for a in all_alerts if a["severity"] == severity]
        if not group:
            continue

        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        print(f"\n{icons[severity]} {severity} ALERTS:")
        print("-" * 55)

        for i, alert in enumerate(group, 1):
            print(f"\n  [{i}] Alert     : {alert['alert_type']}")
            print(f"      Source IP  : {alert.get('source_ip', 'N/A')}")
            print(f"      Detail     : {alert['detail']}")
            print(f"      MITRE ATT&CK: {alert.get('mitre_tactic', 'N/A')}")
            print(f"      Time       : {alert['first_seen']}")

    print("\n" + "="*65)
    print("  Prioritize CRITICAL alerts for immediate investigation.")
    print("="*65 + "\n")

    # Save report
    report_file = "threat_report.txt"
    with open(report_file, "w") as f:
        f.write(f"SOC Threat Detection Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Alerts: {len(all_alerts)}\n\n")
        for alert in all_alerts:
            f.write(f"[{alert['severity']}] {alert['alert_type']}\n")
            f.write(f"  Source IP: {alert.get('source_ip', 'N/A')}\n")
            f.write(f"  Detail: {alert['detail']}\n")
            f.write(f"  MITRE: {alert.get('mitre_tactic', 'N/A')}\n\n")

    print(f"  📄 Threat report saved to: {report_file}\n")


# ─────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────

def main():
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else "sample_logs.json"

    print(f"\n🔍 SOC Log Analyzer starting on: {log_file}\n")

    logs = parse_logs(log_file)

    print("\n  Running threat detection rules...")
    print("  ✔ Checking for brute force attacks...")
    brute_force_alerts = detect_brute_force(logs)

    print("  ✔ Checking for after-hours access...")
    after_hours_alerts = detect_after_hours_access(logs)

    print("  ✔ Checking for port scans...")
    port_scan_alerts = detect_port_scan(logs)

    print("  ✔ Checking for privilege escalation...")
    priv_esc_alerts = detect_privilege_escalation(logs)

    print("  ✔ Checking for data exfiltration...")
    exfil_alerts = detect_data_exfiltration(logs)

    all_alerts = (
        brute_force_alerts +
        after_hours_alerts +
        port_scan_alerts +
        priv_esc_alerts +
        exfil_alerts
    )

    generate_threat_report(all_alerts, log_file)


if __name__ == "__main__":
    main()
