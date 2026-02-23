# 🛡️ SOC Log Analyzer & Threat Detector

A Python-based Security Operations Center (SOC) tool that analyzes security logs and automatically detects suspicious patterns using real-world threat detection rules.

## 🔍 What It Does

This tool parses JSON security logs and applies detection rules to surface threats that a SOC analyst would investigate:

| Detection Rule | What It Catches | MITRE ATT&CK |
|---|---|---|
| **Brute Force Detection** | 5+ failed logins from same IP in 10 min | T1110 |
| **After-Hours Access** | Logins outside 7am–8pm business hours | T1078 |
| **Port Scan Detection** | 10+ ports scanned from one IP in 5 min | T1046 |
| **Privilege Escalation** | Non-admin users running sudo/admin commands | T1548 |
| **Data Exfiltration** | Large outbound transfers (>100MB) to external IPs | T1048 |

Each alert is tagged with severity level and **MITRE ATT&CK framework** tactic — the industry-standard framework used by SOC analysts worldwide.

## 🚀 How to Run

> **Requirements:** Python 3.7+ (no extra libraries needed)

### Run on sample logs (pre-loaded with attack scenarios):
```bash
python soc_log_analyzer.py sample_logs.json
```

### Run on your own logs:
```bash
python soc_log_analyzer.py your_logs.json
```

A threat report is saved to `threat_report.txt` after each run.

## 📋 Sample Output

```
🔍 SOC Log Analyzer starting on: sample_logs.json

  ✔ Loaded 32 log entries
  ✔ Checking for brute force attacks...
  ✔ Checking for after-hours access...
  ✔ Checking for port scans...
  ✔ Checking for privilege escalation...
  ✔ Checking for data exfiltration...

═══════════════════════════════════════════════════
   SOC THREAT DETECTION REPORT
═══════════════════════════════════════════════════

  🔴 CRITICAL : 3
  🟠 HIGH     : 2
  🟡 MEDIUM   : 3
  📋 TOTAL    : 8

🔴 CRITICAL ALERTS:
  [1] Alert    : POTENTIAL DATA EXFILTRATION
      Source IP: 10.0.0.50
      Detail   : 110.0 MB sent to external IP 203.0.113.200
      MITRE    : Exfiltration (T1048)
```

## 📁 Project Structure

```
soc-log-analyzer/
│
├── soc_log_analyzer.py     # Main detection engine
├── sample_logs.json        # Example logs with embedded attack patterns
├── threat_report.txt       # Generated after each run
└── README.md               # This file
```

## 📖 Log Format

Logs should be a JSON array. Each event has:

```json
[
  { "event_type": "login_failed", "timestamp": "2024-03-15T02:01:00", "source_ip": "1.2.3.4", "username": "admin", "destination": "server" },
  { "event_type": "connection_attempt", "timestamp": "2024-03-15T14:00:01", "source_ip": "1.2.3.4", "destination_ip": "10.0.0.1", "destination_port": 22 },
  { "event_type": "data_transfer", "timestamp": "2024-03-15T17:30:00", "source_ip": "10.0.0.50", "destination_ip": "1.2.3.4", "bytes_sent": 52428800 }
]
```

Supported `event_type` values: `login_failed`, `login_success`, `connection_attempt`, `privilege_escalation`, `data_transfer`

## 💡 Security Concepts Demonstrated

- **MITRE ATT&CK Framework** — Industry standard for categorizing attacker behavior
- **SIEM Logic** — Correlation rules used in Splunk, Chronicle, and QRadar
- **Threat Hunting** — Proactively searching logs for indicators of compromise (IoCs)
- **Sliding Window Detection** — Time-based alerting used in real SOC environments
- **Incident Triage** — Severity-based prioritization for analyst workflows

## 🛠️ Future Improvements

- [ ] Add GeoIP lookup to detect impossible travel
- [ ] Add real-time log streaming support
- [ ] Export alerts to STIX/TAXII format (threat intelligence sharing)
- [ ] Add whitelist/allowlist for known-good IPs
- [ ] Integrate with Google Chronicle API

## 👤 Author

[Shiva Sai Pashikanti] | [https://www.linkedin.com/in/shiva-sai-pashikanti-480956126/] | [shivasai.pashikanti@gmail.com]
