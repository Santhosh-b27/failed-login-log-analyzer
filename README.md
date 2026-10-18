# 🛡️ AuthSentinel: Enterprise Authentication Log Forensics & Threat Detection Engine

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110%20%7C%20T1078-red.svg)](https://attack.mitre.org/)
[![Tests: 19 Passed](https://img.shields.io/badge/Tests-19%20Passed%20(100%25)-brightgreen.svg)]()
[![SIEM Ready](https://img.shields.io/badge/SIEM-Splunk%20%7C%20Elastic-orange.svg)]()

**AuthSentinel** is a production-grade Cybersecurity & SOC Detection Engineering platform that ingests multi-source authentication logs, performs stateful behavioral correlation to identify complex cyberattacks (Brute Force, Password Spraying, Impossible Travel, and Breach After Attack), calculates dynamic IP Risk Scores with GeoIP enrichment, maps incidents to the **MITRE ATT&CK Enterprise Matrix**, and provides both an interactive **SOC Web Dashboard** and SIEM-ready export capabilities.

---

## 🚀 Why This Project Stands Out on a Cybersecurity Resume

Most beginner log analysis projects only search for the word `"failed"` using basic regular expressions. **AuthSentinel** elevates log forensics to an enterprise SOC standard:

| Feature Dimension | Basic Log Script | 🛡️ **AuthSentinel Enterprise** |
| :--- | :--- | :--- |
| **Supported Formats** | Single format (SSH) | **Linux (SSH/PAM), Windows (Security 4625/4624), Web (Nginx/Apache), FTP, Cloud JSON** |
| **Detection Logic** | Simple counter per IP | **Stateful sliding windows, horizontal password spraying, geo-velocity impossible travel** |
| **Threat Intelligence** | None | **Dynamic 0–100 IP Risk Scoring, GeoIP resolution, Tor/VPN/ASN threat attribution** |
| **Framework Standards** | None | **Explicit MITRE ATT&CK technique mapping & automated SOC containment playbooks** |
| **Post-Attack Detection** | Blind to breach | **Detects Critical Compromise (multiple failures followed by successful authentication)** |
| **User Interfaces** | Plain terminal printout | **Color-coded CLI, Live File Tailing (`watch`), and Interactive Streamlit SOC Dashboard** |
| **SIEM Compatibility** | None | **One-click export to SIEM JSON (Splunk/Elastic), Forensic CSV, and Executive HTML reports** |
| **Test Coverage** | None | **19 automated unit tests across all parsers, algorithms, and exporters (100% passing)** |

---

## 🏛️ System Architecture

```
                                      [ INGESTION LAYER ]
                    +------------------------------------------------------+
                    |  Linux auth.log | Windows 4625/4624 | Nginx / Apache |
                    |  FTP (vsftpd)   | RDP Terminal Svc  | Cloud SaaS JSON|
                    +------------------------------------------------------+
                                               |
                                               v
                                [ DISPATCHER & NORMALIZATION ]
                    +------------------------------------------------------+
                    | Normalized AuthEvent: timestamp, IP, user, service,  |
                    | status (SUCCESS/FAILED), reason, invalid_user_flag   |
                    +------------------------------------------------------+
                                               |
                                               v
                                 [ ENRICHMENT & THREAT INTEL ]
                    +------------------------------------------------------+
                    | • GeoIP Resolution (City, Country, Lat/Lon, ISP/ASN) |
                    | • RFC 1918 Private Subnet vs Public IP Classification|
                    | • Dynamic IP Risk Scorer (0-100) & Tor/VPN Flagging  |
                    +------------------------------------------------------+
                                               |
                                               v
                            [ STATEFUL THREAT CORRELATION ENGINE ]
                    +------------------------------------------------------+
                    | 1. Brute Force Detector (Vertical Password Guessing) |
                    | 2. Password Spray Detector (Horizontal multi-account)|
                    | 3. Account Enumeration Detector (Invalid usernames)  |
                    | 4. Impossible Travel Detector (Haversine velocity)   |
                    | 5. Confirmed Breach Detector (Failure burst -> Win!) |
                    +------------------------------------------------------+
                                               |
                                               v
                               [ MITRE ATT&CK & SOC RUNBOOKS ]
                    +------------------------------------------------------+
                    | Maps alerts to T1110.001, T1110.003, T1078 + Actions  |
                    +------------------------------------------------------+
                                               |
                                               v
                                  [ INTERFACES & EXPORTERS ]
          +-----------------------+--------------------------+-----------------------+
          |                       |                          |                       |
          v                       v                          v                       v
    [ Rich CLI ]        [ SOC Web Dashboard ]       [ Executive HTML ]     [ SIEM JSON & CSV ]
```

---

## 🎯 Threat Detection Capabilities & MITRE ATT&CK Mapping

1. **Vertical Brute Force (`MITRE T1110.001: Password Guessing`)**
   - Correlates high-frequency failed authentication attempts from a single IP against a specific username within a configurable sliding window (default: 5 failures in 120s).
   - Elevates severity to **CRITICAL** when targeting privileged accounts (`root`, `administrator`, `sa`, `postgres`).

2. **Horizontal Password Spraying (`MITRE T1110.003: Password Spraying`)**
   - Detects adversaries testing common passwords against multiple distinct user accounts from a single IP to bypass account lockout policies.

3. **Systematic Account Enumeration (`MITRE T1087.002: Account Discovery`)**
   - Identifies malicious probing that exploits differences in daemon response codes for invalid/non-existent usernames.

4. **Impossible Travel Anomaly (`MITRE T1078: Valid Accounts`)**
   - Calculates great-circle distance (Haversine formula) between successive logins for the same account. Flags logins across distant geographic locations occurring at speeds exceeding commercial flight capabilities (>800 km/h).

5. **Confirmed Breach Detection (`MITRE T1078.003: Compromise After Attack`)**
   - **Highest SOC Priority (P1)**: Detects when an IP executes a series of failed login attempts and subsequently achieves a successful login, indicating compromised credentials.

---

## ⚡ Quickstart

### 1. Prerequisites
- Python 3.9+ (Fully compatible with Python 3.10, 3.11, 3.12, 3.13, 3.14)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/your-username/auth-sentinel.git
cd auth-sentinel

# Install requirements
pip install -r requirements.txt
```

*(Note: The core CLI engine runs with standard Python libraries. `requirements.txt` installs optional UI packages: Streamlit, Plotly, Pandas, Colorama).*

### 3. Run Forensic Analysis on Sample Logs
```bash
# Analyze mixed enterprise attack scenario
python cli.py analyze samples/mixed_enterprise.log

# Generate full Executive HTML Report, SIEM JSON, and Forensic CSV
python cli.py analyze samples/mixed_enterprise.log --html incident_report.html --json siem_output.json --csv alerts.csv
```

### 4. Launch Interactive Modern SOC Dashboard
```bash
# Launch the web-based SOC triage dashboard
python cli.py dashboard
# Or directly:
streamlit run dashboard.py
```

---

## 🖥️ CLI Usage & Commands

```bash
# General Syntax
python cli.py [subcommand] [arguments]

# 1. Analyze logs with custom detection thresholds
python cli.py analyze path/to/auth.log --threshold-bf 3 --threshold-spray 3

# 2. Live File Tailing Mode (continuous real-time monitoring)
python cli.py watch /var/log/auth.log

# 3. Generate synthetic attack datasets for testing and demos
python cli.py generate --scenario mixed --output attack_scenario.log
python cli.py generate --scenario bruteforce --output ssh_attack.log
python cli.py generate --scenario spray --output spray_attack.log

# 4. Backward Compatibility Mode (works like the original script)
python analyzer.py samples/sample.log
```

---

## 📊 Sample CLI Output

```text
    ___          __  __    _____            __  _            __
   /   | __  __ / /_/ /_  / ___/___  ____  / /_(_)___  ___  / /
  / /| |/ / / // __/ __ \ \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ / 
 / ___ / /_/ // /_/ / / /___/ /  __/ / / / /_/ / / / /  __/ /  
/_/  |_\__,_/ \__/_/ /_//____/\___/_/ /_/\__/_/_/ /_/\___/_/   
Enterprise Authentication Forensics & Threat Detection Engine v1.0.0

[*] Ingesting and parsing log file: samples/mixed_enterprise.log
[*] Running multi-vector correlation and threat intelligence engine...

============================== [ SOC FORENSIC OVERVIEW ] ==============================
Total Logs Ingested:    27
Failed Authentications: 21
Successful Logins:      6
Unique Source IPs:      9
Unique Target Accounts: 13
High-Risk / Malicious:  2
Correlated Incidents:   5

[ Service Protocol Breakdown ]
  * SSH         : 18
  * RDP         : 5
  * WEB         : 3
  * FTP         : 1

============================== [ CRITICAL THREAT ALERTS (5) ] ==============================

[!] CRITICAL: Brute Force (Single User)
    Alert ID:        ALT-BF-0001
    Source IP:       203.0.113.10
    Target Account:  root
    Attempts Count:  5 in 24.0s
    MITRE ATT&CK:    T1110.001 (Brute Force: Password Guessing)
    Details:         Observed 5 failed authentication attempts against user 'root' from IP 203.0.113.10 within 24.0s. [Targeting Privileged Account]
    SOC Action:      1. Containment: Temporarily null-route or block attacker IP on border firewall/WAF.

[!] HIGH: Password Spraying
    Alert ID:        ALT-PS-0001
    Source IP:       198.51.100.45
    Target Account:  alice, bob, charlie, david
    Attempts Count:  4 in 45.0s
    MITRE ATT&CK:    T1110.003 (Brute Force: Password Spraying)
    Details:         Password spraying detected from IP 198.51.100.45: attempted 4 logins across 4 distinct accounts (alice, bob, charlie, david) within 45.0s.
    SOC Action:      1. Priority Triage: Inspect whether common passwords (e.g. Summer2026!, Welcome123) are in use.

[!] CRITICAL: Compromise After Attack (Critical)
    Alert ID:        ALT-BR-0001
    Source IP:       192.0.2.77
    Target Account:  administrator
    Attempts Count:  5 in 95.0s
    MITRE ATT&CK:    T1078.003 (Valid Accounts: Compromise After Attack)
    Details:         POTENTIAL BREACH CONFIRMED: IP 192.0.2.77 executed 4 failed attempts and then gained SUCCESSFUL authentication as 'administrator' within 95.0s!
    SOC Action:      1. P1 EMERGENCY: Immediately isolate the affected host and revoke the compromised account credentials.

============================== [ IOC & SOURCE IP RISK PROFILES ] ==============================
Source IP        Risk     Fail/Total   Location                 Target Users        
------------------------------------------------------------------------------------
192.0.2.77       100/100  4/5          Pyongyang, KP            administrator       
203.0.113.10     75/100   8/8          Moscow, RU               root                
198.51.100.45    45/100   8/8          Beijing, CN              alice, bob (+6)     
185.220.101.5    35/100   1/1          Frankfurt, DE            victor              
```

---

## 🧪 Testing & Verification

AuthSentinel includes a comprehensive unit test suite covering every parser, detector, enrichment engine, and exporter:

```bash
# Run unit test suite
python -m unittest discover tests -v
```

```text
test_breach_confirmation_detection (test_detection.TestDetectionEngine) ... ok
test_brute_force_detection (test_detection.TestDetectionEngine) ... ok
test_full_detection_engine (test_detection.TestDetectionEngine) ... ok
test_impossible_travel_detection (test_detection.TestDetectionEngine) ... ok
test_password_spray_detection (test_detection.TestDetectionEngine) ... ok
test_distance_calculation (test_enrichment.TestEnrichment) ... ok
test_public_geoip_resolution (test_enrichment.TestEnrichment) ... ok
test_rfc1918_private_ip (test_enrichment.TestEnrichment) ... ok
test_threat_score_calculation (test_enrichment.TestEnrichment) ... ok
test_dispatcher_auto_detection (test_parsers.TestLogParsers) ... ok
test_ftp_parser (test_parsers.TestLogParsers) ... ok
test_json_audit_parser (test_parsers.TestLogParsers) ... ok
test_linux_ssh_accepted (test_parsers.TestLogParsers) ... ok
test_linux_ssh_parser (test_parsers.TestLogParsers) ... ok
test_web_nginx_parser (test_parsers.TestLogParsers) ... ok
test_windows_parser (test_parsers.TestLogParsers) ... ok
test_alerts_csv_export (test_reporting.TestReporting) ... ok
test_html_report_generation (test_reporting.TestReporting) ... ok
test_siem_json_export (test_reporting.TestReporting) ... ok

----------------------------------------------------------------------
Ran 19 tests in 0.045s

OK (100% Passing)
```

---

## 💼 How to Present This on Your Resume

See **[RESUME_GUIDE.md](RESUME_GUIDE.md)** for:
- Pre-written, high-impact bullet points formatted with Google's **STAR** and **X-Y-Z** framework.
- Role-specific variations (SOC Analyst, Detection Engineer, DevSecOps, Python Security Engineer).
- 10 Technical interview questions with suggested answers explaining sliding window time complexity, correlation architecture, and false-positive reduction strategies.
- A 5-minute live interview demo script.

---

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
