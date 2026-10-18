# 📄 AuthSentinel: Resume & Technical Interview Guide

This guide is designed to help you showcase **AuthSentinel** on your resume, LinkedIn profile, GitHub portfolio, and during technical cybersecurity interviews.

---

## 📌 1. Resume Section: Project Entries

Choose the bullet set that best matches the role you are targeting.

### Option A: For SOC Analyst / Security Operations Center (Tier 1 - 3)
> **AuthSentinel – Enterprise Authentication Forensics & SOC Triage Platform**  
> *Python, MITRE ATT&CK, SIEM Ingestion (Splunk/Elastic), Threat Intelligence, Streamlit, Linux/Windows Auditing*
> - Engineered an automated multi-source log forensics platform parsing Linux Syslog, Windows Security Events (4625/4624), Nginx, and Cloud SaaS audit logs with 100% test coverage.
> - Formulated stateful correlation heuristics detecting 5 core attack vectors, including horizontal password spraying (T1110.003), vertical brute force (T1110.001), and critical post-attack credential compromises.
> - Integrated dynamic GeoIP resolution and a 0–100 IP Risk Scoring engine factoring in velocity, targeting of privileged accounts, and Tor/VPN exit node threat intelligence.
> - Built an interactive SOC Web Dashboard (Streamlit) and automated report generators producing executive HTML forensics briefings and SIEM-compliant JSON/CSV artifacts.

### Option B: For Detection Engineer / Threat Hunting
> **AuthSentinel – Behavioral Authentication Detection & Threat Correlation Engine**  
> *Python 3, Detection Engineering, Sigma Rules, MITRE ATT&CK Framework, Geo-Velocity Correlation*
> - Designed and deployed a detection engine utilizing sliding window correlation algorithms to identify distributed password spraying across multi-account environments.
> - Implemented an impossible travel anomaly detector using the Haversine spherical distance formula to flag concurrent authentication sessions exceeding 800 km/h velocity.
> - Mapped detection alerts directly to the MITRE ATT&CK Enterprise Matrix, packaging each alert with automated containment playbooks and Sigma rule signatures for border firewall blocks.
> - Developed a synthetic cyberattack scenario generator to stress-test correlation rules against simulated APT credential stuffing campaigns and mixed enterprise baselines.

### Option C: For Python Security Engineer / DevSecOps
> **AuthSentinel – Modular Authentication Forensics & Security Observability Tool**  
> *Python, Dataclasses, Pytest/Unittest, CLI Architecture, Plotly, Pandas, CI/CD Ready*
> - Architected a modular Python security package featuring pluggable log parser dispatchers, normalized data models, and zero-dependency standard library fallbacks.
> - Optimized timestamp normalization across heterogeneous syslog RFC formats and ISO-8601 UTC standards, preventing timezone collation race conditions.
> - Developed dual operational interfaces: a rich CLI supporting live log stream tailing (`watch` mode) and an interactive analytical web dashboard.
> - Authored an end-to-end automated test suite (19 unit tests) achieving 100% pass rates across parser, detection, and SIEM exporter pipelines.

---

## 🛠️ 2. Skills to Add to Your Resume

Add these keywords to your **Technical Skills** section:
- **Security & Forensics:** Detection Engineering, Log Forensics, SOC Triage, Threat Intelligence (TI), MITRE ATT&CK Mapping, Incident Response Runbooks, Indicators of Compromise (IOCs).
- **Log Ecosystems:** Linux Syslog (`/var/log/auth.log`, `sshd`, PAM), Windows Security Auditing (Event IDs 4625 & 4624), Nginx/Apache Web Auth, CloudTrail JSON.
- **Languages & Frameworks:** Python 3, Streamlit, Plotly Express, Pandas, Colorama, Regex, Unit Testing (`unittest`).
- **Data & Standards:** SIEM Ingestion (Elastic ECS / Splunk CIM JSON), CSV Forensics, Haversine Distance Calculations, IP Subnetting (RFC 1918 / Bogon).

---

## 🎙️ 3. Technical Interview Preparation & Talking Points

Interviewers love asking deep technical questions about portfolio projects. Here are the top questions and exact answers:

### Q1: "Why did you build AuthSentinel instead of just using grep or simple regex?"
> **Answer:**  
> *"Traditional grep or one-liner regex scripts can identify isolated error keywords like 'Failed password', but they are completely blind to multi-event attack patterns. Real-world adversaries conduct horizontal password spraying across dozens of different usernames to stay under per-user lockout thresholds, or they execute credential stuffing followed by a subtle successful login. AuthSentinel introduces a stateful correlation engine that groups events across time windows, tracks IP profiles, detects impossible travel velocities, and flags critical breaches that static grep searches miss."*

### Q2: "How does the sliding window algorithm work for brute force and password spraying?"
> **Answer:**  
> *"Each incoming log is parsed into a normalized `AuthEvent` with an offset-naive UTC timestamp. For brute force, events are grouped by `(source_ip, username)`. Using a two-pointer sliding window with time complexity \(O(N)\), the right pointer expands while the left pointer advances whenever the time delta exceeds the threshold window (e.g. 120 seconds). If the event count within the window reaches the threshold, an alert is triggered. For password spraying, we group by `source_ip` and evaluate the cardinality of distinct usernames targeted within the window."*

### Q3: "How does the Impossible Travel detector calculate geographic velocity?"
> **Answer:**  
> *"When a user logs in from two distinct IP addresses, AuthSentinel resolves the latitude and longitude coordinates and verifies neither IP is an RFC 1918 private subnet. It then applies the Haversine great-circle formula to calculate the distance in kilometers over the Earth's curvature. By dividing the distance by the elapsed time in hours between the two logins, it computes velocity. If the calculated velocity exceeds realistic commercial aviation speeds (800 km/h) and a minimum distance threshold, it triggers an impossible travel security alert."*

### Q4: "How did you prevent false positives?"
> **Answer:**  
> *"We implemented several tuning mechanisms:
> 1. Private IP filtering (RFC 1918 subnets like 10.0.0.0/8 and 192.168.0.0/16 are recognized so internal jump boxes and corporate NATs don't trigger false geo-velocity alerts).
> 2. Configurable time windows and failure thresholds instead of static counters.
> 3. Separate rules for vertical brute force (targeting one user repeatedly) versus password spraying (targeting multiple users), preventing normal user typos from triggering mass attack alerts.
> 4. Risk scoring that combines failure frequency, targeted privilege level (e.g. root/admin vs standard users), and multi-service targeting."*

### Q5: "How does AuthSentinel integrate with enterprise SIEM solutions?"
> **Answer:**  
> *"AuthSentinel exports parsed events and correlated alerts into SIEM-compatible JSON structures mapped with MITRE ATT&CK technique IDs, severity ratings, and evidence payloads. This schema can be directly ingested into Elasticsearch (ECS) indices or Splunk CIM authentication data models. It also exports self-contained HTML executive reports for incident commanders."*

---

## 🎬 4. Five-Minute Live Interview Demo Script

If an interviewer asks you to screen share or walk through your project, follow this 4-step sequence:

1. **Step 1: The Problem (30 seconds)**
   - Explain: *"Most log parsers just count failed lines. I wanted to build an end-to-end detection engineering platform that correlates multi-protocol logs into actionable incidents with MITRE ATT&CK mapping."*

2. **Step 2: Generate & Analyze via CLI (1 minute)**
   - Open terminal and run:
     ```bash
     python cli.py analyze samples/mixed_enterprise.log --html incident_report.html
     ```
   - Highlight the colorful CLI output: point to the **SOC Forensic Overview**, the **Protocol Breakdown**, and the **Critical Breach Alert** where `192.0.2.77` had 4 failed attempts followed by an accepted login.

3. **Step 3: Show the Executive HTML Report (1.5 minutes)**
   - Open `incident_report.html` in Chrome or Edge.
   - Point out:
     - The dark SOC design theme.
     - The interactive Chart.js doughnut chart breaking down attacks by MITRE category.
     - The IOC table with dynamic 0–100 risk scores and geolocation attribution.
     - The SOC containment runbooks attached to each incident.

4. **Step 4: Launch the Streamlit SOC Dashboard (2 minutes)**
   - Run:
     ```bash
     streamlit run dashboard.py
     ```
   - Switch between scenarios (`mixed_enterprise.log` vs `ssh_bruteforce.log`).
   - Demonstrate the sliders in the sidebar: adjust the Brute Force Threshold from 5 to 3 and show how the dashboard dynamically re-evaluates the incidents in real-time.
   - Conclude: *"This demonstrates clean Python architecture, detection engineering heuristics, and full-stack cybersecurity tooling."*
