"""
AuthSentinel: Interactive Modern SOC Web Dashboard.
Run via: streamlit run dashboard.py
"""

import os
import io
import json
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

from auth_sentinel.core.config import SentinelConfig
from auth_sentinel.core.models import IncidentSummary, AuthEvent, SeverityLevel
from auth_sentinel.parsers.auto_detector import LogParserDispatcher
from auth_sentinel.detection.engine import DetectionEngine
from auth_sentinel.reporting.html_report import HtmlReportGenerator
from auth_sentinel.reporting.siem_export import SiemExporter

# Configure page layout and dark SOC theme
st.set_page_config(
    page_title="AuthSentinel - SOC Threat & Forensics Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for dark-mode SOC aesthetic
st.markdown(
    """
    <style>
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 10px;
    }
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.2);
        color: #ef4444;
        border: 1px solid #ef4444;
        padding: 2px 8px;
        border-radius: 6px;
        font-weight: bold;
    }
    .badge-high {
        background-color: rgba(249, 115, 22, 0.2);
        color: #f97316;
        border: 1px solid #f97316;
        padding: 2px 8px;
        border-radius: 6px;
        font-weight: bold;
    }
    .badge-med {
        background-color: rgba(245, 158, 11, 0.2);
        color: #f59e0b;
        border: 1px solid #f59e0b;
        padding: 2px 8px;
        border-radius: 6px;
        font-weight: bold;
    }
    .stAlert {
        border-radius: 10px;
    }
    </style>
""",
    unsafe_allow_html=True,
)


def load_and_analyze(log_content: str, config: SentinelConfig):
    dispatcher = LogParserDispatcher()
    events = []
    lines = log_content.splitlines()
    for line in lines:
        ev = dispatcher.parse_line(line)
        if ev:
            events.append(ev)

    engine = DetectionEngine(config)
    summary = engine.process_events(events)
    return events, summary


def main():
    st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.sidebar.title("AuthSentinel SOC")
    st.sidebar.caption("Enterprise Authentication Threat Detection")

    st.sidebar.markdown("---")
    st.sidebar.subheader("Log Ingestion Source")
    data_source = st.sidebar.radio(
        "Select Log Ingestion Mode:",
        ["Preset Attack Scenario", "Upload Custom Log File", "Paste Raw Logs"],
    )

    log_text = ""
    samples_dir = os.path.join(os.path.dirname(__file__), "samples")

    if data_source == "Preset Attack Scenario":
        preset_file = st.sidebar.selectbox(
            "Select Scenario:",
            [
                "mixed_enterprise.log (All Attack Scenarios)",
                "ssh_bruteforce.log (Vertical Brute Force)",
                "password_spray.log (Horizontal Password Spray)",
                "sample.log (Multi-Service Baseline)",
            ],
        )
        fname = preset_file.split(" ")[0]
        fpath = os.path.join(samples_dir, fname)
        if os.path.exists(fpath):
            with open(fpath, "r", encoding="utf-8") as f:
                log_text = f.read()
        else:
            st.error(f"Sample file not found at {fpath}")

    elif data_source == "Upload Custom Log File":
        uploaded = st.sidebar.file_uploader("Upload Auth Log (.log, .txt, .json)", type=["log", "txt", "json"])
        if uploaded is not None:
            log_text = uploaded.getvalue().decode("utf-8", errors="replace")

    else:
        log_text = st.sidebar.text_area("Paste log lines here:", height=200)

    # Detection Threshold Controls
    st.sidebar.markdown("---")
    st.sidebar.subheader("Detection Rules Tuning")
    bf_thresh = st.sidebar.slider("Brute Force Threshold (Failures):", 2, 20, 5)
    spray_thresh = st.sidebar.slider("Password Spray Threshold (Unique Users):", 2, 15, 4)
    travel_speed = st.sidebar.slider("Max Flight Speed (km/h):", 500, 1500, 800)

    config = SentinelConfig(
        brute_force_threshold=bf_thresh,
        password_spray_threshold=spray_thresh,
        impossible_travel_speed_kmh=float(travel_speed),
    )

    # Main view header
    st.title("🛡️ AuthSentinel: SOC Threat Forensics & Correlation Dashboard")
    st.markdown(
        "Real-time multi-source authentication monitoring, behavioral heuristic correlation, and MITRE ATT&CK mapping."
    )

    if not log_text.strip():
        st.info("👈 Please select a scenario or upload a log file from the sidebar to begin analysis.")
        return

    events, summary = load_and_analyze(log_text, config)

    if not events:
        st.warning("No authentication events could be recognized from the provided log content.")
        return

    # Top KPI Metrics Row
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("Total Logs Ingested", f"{summary.total_events:,}")
    with m2:
        fail_pct = (summary.total_failed / max(1, summary.total_events)) * 100
        st.metric("Failed Attempts", f"{summary.total_failed:,}", f"{fail_pct:.1f}% fail rate", delta_color="inverse")
    with m3:
        st.metric("Targeted Accounts", f"{summary.unique_users:,}")
    with m4:
        st.metric("High-Risk / Malicious IPs", f"{summary.high_risk_ips:,}", delta_color="inverse")
    with m5:
        st.metric("Active Threat Incidents", f"{len(summary.alerts):,}", delta_color="inverse")

    st.markdown("---")

    # Tabs for organized SOC investigation
    tab_incidents, tab_visuals, tab_iocs, tab_events, tab_export = st.tabs(
        [
            "🚨 Threat Incidents & Triage",
            "📊 Visual Analytics & Geo Map",
            "🎯 IOC Risk Profiles",
            "📜 Normalized Events Log",
            "💾 SIEM Export & Reports",
        ]
    )

    # TAB 1: THREAT INCIDENTS
    with tab_incidents:
        st.subheader("Correlated Threat Incidents & MITRE ATT&CK Triage")
        if not summary.alerts:
            st.success("✅ Clean log stream: No malicious brute force, spray, or compromise incidents detected!")
        else:
            for alt in summary.alerts:
                sev = alt.severity.value
                badge_class = "badge-critical" if sev in ("CRITICAL", "HIGH") else "badge-med"
                with st.expander(f"[{sev}] {alt.attack_type.value} | Source: {alt.source_ip} (Alert ID: {alt.alert_id})", expanded=(sev == "CRITICAL")):
                    st.markdown(
                        f"""
                        **Severity:** <span class="{badge_class}">{sev}</span> &nbsp;&nbsp;|&nbsp;&nbsp;
                        **MITRE ATT&CK:** `{alt.mitre_technique_id} - {alt.mitre_technique_name}` &nbsp;&nbsp;|&nbsp;&nbsp;
                        **Timestamp:** `{alt.timestamp.strftime('%Y-%m-%d %H:%M:%S')}`
                        """,
                        unsafe_allow_html=True,
                    )
                    st.write(f"**Details:** {alt.description}")
                    st.write(f"**Targeted Account(s):** `{', '.join(alt.targeted_users)}`")
                    st.write(f"**Attempt Volume:** {alt.attempt_count} events in {alt.time_window_seconds}s")
                    st.info(f"📋 **SOC Remediation Playbook:**\n{alt.recommended_action}")

                    if alt.evidence_events:
                        st.caption("Forensic Evidence Sample:")
                        ev_df = pd.DataFrame(
                            [
                                {
                                    "Timestamp": e.get("timestamp"),
                                    "Service": e.get("service"),
                                    "IP": e.get("ip"),
                                    "User": e.get("username"),
                                    "Status": e.get("status"),
                                    "Failure Reason": e.get("failure_reason"),
                                }
                                for e in alt.evidence_events[:5]
                            ]
                        )
                        st.dataframe(ev_df, use_container_width=True)

    # TAB 2: VISUAL ANALYTICS & GEO MAP
    with tab_visuals:
        col_g1, col_g2 = st.columns(2)
        with col_g1:
            st.subheader("Attacks by MITRE Technique")
            if summary.alerts:
                alert_types = [a.attack_type.value for a in summary.alerts]
                df_alert_types = pd.DataFrame({"Attack Type": alert_types})
                fig_pie = px.pie(
                    df_alert_types,
                    names="Attack Type",
                    title="Incident Category Breakdown",
                    hole=0.45,
                    color_discrete_sequence=px.colors.sequential.RdBu,
                )
                fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.info("No active incidents to chart.")

        with col_g2:
            st.subheader("Traffic Volume by Service")
            df_srv = pd.DataFrame(list(summary.service_breakdown.items()), columns=["Service", "Count"])
            fig_bar = px.bar(
                df_srv,
                x="Service",
                y="Count",
                color="Service",
                title="Protocol & Daemon Distribution",
                text="Count",
            )
            fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
            st.plotly_chart(fig_bar, use_container_width=True)

        st.subheader("Geographical Distribution of Attack Sources")
        geo_data = []
        for ip, prof in summary.ip_profiles.items():
            if prof.geo and not prof.geo.is_private and (prof.geo.latitude != 0 or prof.geo.longitude != 0):
                geo_data.append(
                    {
                        "IP": ip,
                        "Country": prof.geo.country,
                        "City": prof.geo.city,
                        "Lat": prof.geo.latitude,
                        "Lon": prof.geo.longitude,
                        "Failed Attempts": prof.failed_attempts,
                        "Risk Score": prof.risk_score,
                    }
                )
        if geo_data:
            df_geo = pd.DataFrame(geo_data)
            fig_map = px.scatter_geo(
                df_geo,
                lat="Lat",
                lon="Lon",
                color="Risk Score",
                size="Failed Attempts",
                hover_name="IP",
                hover_data=["Country", "City", "Risk Score", "Failed Attempts"],
                projection="natural earth",
                title="Global Attack Source Origin",
                color_continuous_scale="Reds",
            )
            fig_map.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
            st.plotly_chart(fig_map, use_container_width=True)
        else:
            st.info("No external public IPs with coordinates in current log.")

    # TAB 3: IOC RISK PROFILES
    with tab_iocs:
        st.subheader("Indicators of Compromise (Threat Scores & Host Attribution)")
        ioc_rows = []
        for ip, prof in sorted(summary.ip_profiles.items(), key=lambda x: x[1].risk_score, reverse=True):
            geo_str = f"{prof.geo.city}, {prof.geo.country}" if prof.geo else "Unknown"
            isp_str = prof.geo.isp if prof.geo else "Unknown"
            ioc_rows.append(
                {
                    "Source IP": ip,
                    "Risk Score": f"{prof.risk_score}/100",
                    "Severity": "CRITICAL" if prof.risk_score >= 90 else ("HIGH" if prof.risk_score >= 70 else ("MEDIUM" if prof.risk_score >= 40 else "LOW")),
                    "Fail / Total": f"{prof.failed_attempts} / {prof.total_attempts}",
                    "Location": geo_str,
                    "ISP / Organization": isp_str,
                    "Targeted Accounts": ", ".join(prof.targeted_users[:3]),
                    "Risk Factors": " | ".join(prof.risk_factors[:2]),
                }
            )
        st.dataframe(pd.DataFrame(ioc_rows), use_container_width=True)

    # TAB 4: NORMALIZED EVENTS
    with tab_events:
        st.subheader("Normalized Authentication Events Stream")
        raw_rows = [
            {
                "Event ID": ev.event_id,
                "Timestamp": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Service": ev.service,
                "Status": ev.status,
                "Source IP": ev.ip,
                "User": ev.username,
                "Reason": ev.failure_reason or "N/A",
                "Invalid User": "Yes" if ev.is_invalid_user else "No",
            }
            for ev in events
        ]
        st.dataframe(pd.DataFrame(raw_rows), use_container_width=True)

    # TAB 5: EXPORTS
    with tab_export:
        st.subheader("Export Forensic Evidence & SIEM Artifacts")
        col_e1, col_e2, col_e3 = st.columns(3)

        with col_e1:
            st.markdown("#### Executive HTML Forensic Report")
            html_buffer = io.StringIO()
            # Generate to temp and read
            temp_html = "temp_dashboard_report.html"
            HtmlReportGenerator.generate(summary, events, temp_html)
            if os.path.exists(temp_html):
                with open(temp_html, "r", encoding="utf-8") as f:
                    html_data = f.read()
                st.download_button(
                    label="📥 Download HTML Report",
                    data=html_data,
                    file_name="AuthSentinel_Executive_Report.html",
                    mime="text/html",
                )

        with col_e2:
            st.markdown("#### SIEM JSON Ingestion Schema")
            json_data = json.dumps(summary.to_dict(), indent=2)
            st.download_button(
                label="📥 Download SIEM JSON",
                data=json_data,
                file_name="auth_sentinel_siem.json",
                mime="application/json",
            )

        with col_e3:
            st.markdown("#### Forensic Alerts CSV")
            temp_csv = "temp_dashboard_alerts.csv"
            SiemExporter.export_alerts_csv(summary, temp_csv)
            if os.path.exists(temp_csv):
                with open(temp_csv, "r", encoding="utf-8") as f:
                    csv_data = f.read()
                st.download_button(
                    label="📥 Download Alerts CSV",
                    data=csv_data,
                    file_name="auth_sentinel_alerts.csv",
                    mime="text/csv",
                )


if __name__ == "__main__":
    main()
