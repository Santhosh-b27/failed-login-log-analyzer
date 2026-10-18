"""
SIEM Export Utilities (JSON, CSV, and Markdown Summary).
"""

import csv
import json
from typing import List
from ..core.models import AuthEvent, IncidentSummary


class SiemExporter:
    """Exports forensic events and detected incidents into SIEM-ready formats."""

    @staticmethod
    def export_json(summary: IncidentSummary, output_path: str) -> None:
        """Export full incident summary to standard SIEM JSON format."""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary.to_dict(), f, indent=2)

    @staticmethod
    def export_events_csv(events: List[AuthEvent], output_path: str) -> None:
        """Export parsed authentication events to a forensic CSV."""
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Event ID",
                    "Timestamp",
                    "Service",
                    "Status",
                    "Source IP",
                    "Username",
                    "Country",
                    "City",
                    "ISP",
                    "Port",
                    "Failure Reason",
                    "Invalid User Flag",
                ]
            )
            for ev in events:
                writer.writerow(
                    [
                        ev.event_id,
                        ev.timestamp.isoformat(),
                        ev.service,
                        ev.status,
                        ev.ip,
                        ev.username,
                        ev.geo.country if ev.geo else "Unknown",
                        ev.geo.city if ev.geo else "Unknown",
                        ev.geo.isp if ev.geo else "Unknown",
                        ev.port or "",
                        ev.failure_reason,
                        "Yes" if ev.is_invalid_user else "No",
                    ]
                )

    @staticmethod
    def export_alerts_csv(summary: IncidentSummary, output_path: str) -> None:
        """Export detected alerts to CSV."""
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Alert ID",
                    "Timestamp",
                    "Attack Type",
                    "Severity",
                    "Source IP",
                    "Targeted Users",
                    "Attempts",
                    "Window (s)",
                    "MITRE Technique",
                    "Description",
                    "Action",
                ]
            )
            for alt in summary.alerts:
                writer.writerow(
                    [
                        alt.alert_id,
                        alt.timestamp.isoformat(),
                        alt.attack_type.value,
                        alt.severity.value,
                        alt.source_ip,
                        ";".join(alt.targeted_users),
                        alt.attempt_count,
                        alt.time_window_seconds,
                        f"{alt.mitre_technique_id} ({alt.mitre_technique_name})",
                        alt.description,
                        alt.recommended_action,
                    ]
                )

    @staticmethod
    def export_markdown_summary(summary: IncidentSummary, output_path: str) -> None:
        """Generate a clean executive summary in Markdown format."""
        md = []
        md.append("# AuthSentinel Security Incident Summary Report\n")
        md.append(f"- **Generated:** {summary.timeframe_end or 'N/A'}")
        md.append(f"- **Total Events Inspected:** {summary.total_events}")
        md.append(f"- **Failed Authentication Attempts:** {summary.total_failed}")
        md.append(f"- **Successful Authentications:** {summary.total_success}")
        md.append(f"- **Unique Source IPs:** {summary.unique_ips}")
        md.append(f"- **High-Risk Malicious IPs:** {summary.high_risk_ips}")
        md.append(f"- **Total Incidents Detected:** {len(summary.alerts)}\n")

        md.append("## Detected Security Incidents\n")
        if not summary.alerts:
            md.append("No critical security incidents or attack patterns detected.\n")
        else:
            md.append("| Alert ID | Severity | Attack Type | Source IP | MITRE | Description |")
            md.append("|---|---|---|---|---|---|")
            for alt in summary.alerts:
                md.append(
                    f"| {alt.alert_id} | **{alt.severity.value}** | {alt.attack_type.value} | `{alt.source_ip}` | {alt.mitre_technique_id} | {alt.description} |"
                )
            md.append("\n")

        md.append("## High Risk Indicators of Compromise (IOCs)\n")
        md.append("| IP Address | Risk Score | Geo Location | Targeted Accounts | Risk Factors |")
        md.append("|---|---|---|---|---|")
        for ip, prof in sorted(summary.ip_profiles.items(), key=lambda x: x[1].risk_score, reverse=True):
            if prof.risk_score >= 40:
                geo_str = f"{prof.geo.country} ({prof.geo.city})" if prof.geo else "Unknown"
                users_str = ", ".join(prof.targeted_users[:3])
                factors_str = "; ".join(prof.risk_factors[:2])
                md.append(f"| `{ip}` | **{prof.risk_score}/100** | {geo_str} | {users_str} | {factors_str} |")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md))
