"""
Standalone HTML Executive Forensic Report Generator with modern SOC aesthetics and charts.
"""

import json
from typing import List
from ..core.models import AuthEvent, IncidentSummary


class HtmlReportGenerator:
    """Generates a self-contained, publication-ready SOC Incident Report."""

    @staticmethod
    def generate(summary: IncidentSummary, events: List[AuthEvent], output_path: str) -> None:
        # Prepare data for charts
        attack_counts = {}
        for alt in summary.alerts:
            val = alt.attack_type.value
            attack_counts[val] = attack_counts.get(val, 0) + 1

        service_labels = list(summary.service_breakdown.keys())
        service_values = list(summary.service_breakdown.values())

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthSentinel - Forensic Incident Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-dark: #0f172a;
            --card-dark: #1e293b;
            --border-dark: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --danger-red: #ef4444;
            --warn-amber: #f59e0b;
            --success-green: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            padding: 30px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-dark);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .brand-title {{ font-size: 26px; font-weight: 800; color: var(--accent-blue); display: flex; align-items: center; gap: 10px; }}
        .badge-confidential {{
            background: rgba(239, 68, 68, 0.2);
            color: var(--danger-red);
            border: 1px solid var(--danger-red);
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .grid-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background-color: var(--card-dark);
            border: 1px solid var(--border-dark);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        }}
        .stat-title {{ font-size: 13px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}
        .stat-value {{ font-size: 32px; font-weight: 800; margin-top: 5px; }}
        .color-danger {{ color: var(--danger-red); }}
        .color-warn {{ color: var(--warn-amber); }}
        .color-accent {{ color: var(--accent-blue); }}
        .color-success {{ color: var(--success-green); }}

        .charts-row {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .chart-box {{
            background: var(--card-dark);
            border: 1px solid var(--border-dark);
            border-radius: 12px;
            padding: 20px;
            height: 350px;
        }}
        h2 {{ font-size: 20px; margin-bottom: 15px; font-weight: 700; border-left: 4px solid var(--accent-blue); padding-left: 10px; }}

        .alert-card {{
            background: var(--card-dark);
            border: 1px solid var(--border-dark);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 5px solid var(--border-dark);
        }}
        .alert-card.CRITICAL {{ border-left-color: var(--danger-red); }}
        .alert-card.HIGH {{ border-left-color: #f97316; }}
        .alert-card.MEDIUM {{ border-left-color: var(--warn-amber); }}
        .alert-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .alert-title {{ font-weight: 700; font-size: 17px; }}
        .mitre-badge {{
            background: #334155;
            color: #38bdf8;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-family: monospace;
            font-weight: 600;
        }}
        .playbook-box {{
            background: rgba(15, 23, 42, 0.6);
            border: 1px dashed #475569;
            padding: 10px 15px;
            border-radius: 6px;
            margin-top: 10px;
            font-size: 13px;
            color: #cbd5e1;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: var(--card-dark);
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid var(--border-dark);
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-dark);
            font-size: 14px;
        }}
        th {{ background: #1a2234; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 12px; }}
        tr:hover {{ background: rgba(56, 189, 248, 0.05); }}
        .risk-pill {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 12px;
        }}
        .risk-high {{ background: rgba(239, 68, 68, 0.2); color: var(--danger-red); }}
        .risk-med {{ background: rgba(245, 158, 11, 0.2); color: var(--warn-amber); }}
        .risk-low {{ background: rgba(16, 185, 129, 0.2); color: var(--success-green); }}

        footer {{
            margin-top: 40px;
            text-align: center;
            font-size: 13px;
            color: var(--text-muted);
            border-top: 1px solid var(--border-dark);
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <div class="brand-title">🛡️ AuthSentinel Enterprise SOC Report</div>
                <div style="font-size: 13px; color: var(--text-muted); margin-top: 5px;">
                    Incident Analysis & Threat Forensics | Timeframe: {summary.timeframe_start or 'N/A'} - {summary.timeframe_end or 'N/A'}
                </div>
            </div>
            <div class="badge-confidential">SOC Triage: {len(summary.alerts)} Incidents Active</div>
        </header>

        <!-- KPI Metrics Grid -->
        <div class="grid-stats">
            <div class="stat-card">
                <div class="stat-title">Total Logs Ingested</div>
                <div class="stat-value color-accent">{summary.total_events}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Failed Authentications</div>
                <div class="stat-value color-danger">{summary.total_failed}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Unique Attack Sources</div>
                <div class="stat-value">{summary.unique_ips}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">High-Risk Malicious IPs</div>
                <div class="stat-value color-danger">{summary.high_risk_ips}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Correlation Incidents</div>
                <div class="stat-value color-warn">{len(summary.alerts)}</div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="charts-row">
            <div class="chart-box">
                <h3 style="font-size: 15px; margin-bottom: 10px; color: var(--text-muted);">Incidents by Attack Classification</h3>
                <canvas id="attackChart"></canvas>
            </div>
            <div class="chart-box">
                <h3 style="font-size: 15px; margin-bottom: 10px; color: var(--text-muted);">Authentication Volume by Service</h3>
                <canvas id="serviceChart"></canvas>
            </div>
        </div>

        <!-- Detected Incidents Section -->
        <h2>Correlated Security Incidents & MITRE ATT&CK Mapping</h2>
        <div style="margin-bottom: 30px;">
"""
        for alt in summary.alerts:
            severity_class = alt.severity.value
            html_template += f"""
            <div class="alert-card {severity_class}">
                <div class="alert-header">
                    <div>
                        <span class="risk-pill {'risk-high' if severity_class in ('CRITICAL', 'HIGH') else 'risk-med'}">{alt.severity.value}</span>
                        <span class="alert-title" style="margin-left: 10px;">{alt.attack_type.value}</span>
                    </div>
                    <div>
                        <span class="mitre-badge">MITRE {alt.mitre_technique_id}</span>
                        <span style="font-size: 12px; color: var(--text-muted); margin-left: 10px;">ID: {alt.alert_id}</span>
                    </div>
                </div>
                <p style="font-size: 14px; margin-top: 5px;">{alt.description}</p>
                <div class="playbook-box">
                    <strong>SOC Response Action:</strong> {alt.recommended_action}
                </div>
            </div>
            """

        # IOC Profiles Table
        html_template += """
        </div>

        <h2>Indicators of Compromise (IOC Profile Summary)</h2>
        <table>
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>Risk Score</th>
                    <th>Geolocation</th>
                    <th>ISP / ASN</th>
                    <th>Failed / Total</th>
                    <th>Targeted Accounts</th>
                    <th>Risk Factors</th>
                </tr>
            </thead>
            <tbody>
        """

        for ip, prof in sorted(summary.ip_profiles.items(), key=lambda x: x[1].risk_score, reverse=True):
            risk_class = "risk-high" if prof.risk_score >= 70 else ("risk-med" if prof.risk_score >= 40 else "risk-low")
            geo_info = f"{prof.geo.city}, {prof.geo.country}" if prof.geo else "Unknown"
            isp_info = prof.geo.isp if prof.geo else "Unknown"
            users_str = ", ".join(prof.targeted_users[:3]) + (f" (+{len(prof.targeted_users)-3})" if len(prof.targeted_users) > 3 else "")
            factors_str = "<br>".join(prof.risk_factors[:2])

            html_template += f"""
            <tr>
                <td><code>{ip}</code></td>
                <td><span class="risk-pill {risk_class}">{prof.risk_score}/100</span></td>
                <td>{geo_info}</td>
                <td><small>{isp_info}</small></td>
                <td>{prof.failed_attempts} / {prof.total_attempts}</td>
                <td><strong>{users_str}</strong></td>
                <td><small style="color: var(--text-muted);">{factors_str}</small></td>
            </tr>
            """

        html_template += f"""
            </tbody>
        </table>

        <footer>
            Generated by <strong>AuthSentinel v1.0.0</strong> - Automated Detection & Forensics Engineering Platform
        </footer>
    </div>

    <script>
        const attackCtx = document.getElementById('attackChart').getContext('2d');
        new Chart(attackCtx, {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(list(attack_counts.keys()))},
                datasets: [{{
                    data: {json.dumps(list(attack_counts.values()))},
                    backgroundColor: ['#ef4444', '#f59e0b', '#38bdf8', '#8b5cf6', '#ec4899'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'right', labels: {{ color: '#94a3b8' }} }} }}
            }}
        }});

        const serviceCtx = document.getElementById('serviceChart').getContext('2d');
        new Chart(serviceCtx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps(service_labels)},
                datasets: [{{
                    label: 'Events Count',
                    data: {json.dumps(service_values)},
                    backgroundColor: '#38bdf8',
                    borderRadius: 6
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ display: false }} }},
                    y: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: '#334155' }} }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_template)
