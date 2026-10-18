"""
Unit tests for HTML report and SIEM exporters.
"""

import os
import unittest
from datetime import datetime
from auth_sentinel.core.models import IncidentSummary, AuthEvent, DetectionAlert, AttackType, SeverityLevel
from auth_sentinel.reporting.html_report import HtmlReportGenerator
from auth_sentinel.reporting.siem_export import SiemExporter


class TestReporting(unittest.TestCase):
    def setUp(self):
        self.summary = IncidentSummary(
            total_events=10,
            total_failed=8,
            total_success=2,
            unique_ips=2,
            unique_users=3,
            high_risk_ips=1,
            timeframe_start=datetime(2026, 10, 18, 10, 0, 0),
            timeframe_end=datetime(2026, 10, 18, 10, 10, 0),
            alerts=[
                DetectionAlert(
                    alert_id="ALT-001",
                    timestamp=datetime(2026, 10, 18, 10, 5, 0),
                    attack_type=AttackType.BRUTE_FORCE,
                    severity=SeverityLevel.HIGH,
                    source_ip="203.0.113.10",
                    targeted_users=["root"],
                    attempt_count=5,
                    time_window_seconds=30.0,
                    mitre_technique_id="T1110.001",
                    mitre_technique_name="Password Guessing",
                    description="Brute force against root",
                    recommended_action="Block IP",
                )
            ],
            service_breakdown={"SSH": 8, "WEB": 2},
        )
        self.events = [
            AuthEvent(
                event_id="EVT-1",
                timestamp=datetime(2026, 10, 18, 10, 0, 0),
                service="SSH",
                ip="203.0.113.10",
                username="root",
                status="FAILED",
                raw_line="sample line",
            )
        ]

    def test_html_report_generation(self):
        out_file = "test_output_report.html"
        try:
            HtmlReportGenerator.generate(self.summary, self.events, out_file)
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("AuthSentinel Enterprise SOC Report", content)
            self.assertIn("ALT-001", content)
            self.assertIn("T1110.001", content)
        finally:
            if os.path.exists(out_file):
                os.remove(out_file)

    def test_siem_json_export(self):
        out_file = "test_output_siem.json"
        try:
            SiemExporter.export_json(self.summary, out_file)
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn('"total_events": 10', content)
            self.assertIn('"ALT-001"', content)
        finally:
            if os.path.exists(out_file):
                os.remove(out_file)

    def test_alerts_csv_export(self):
        out_file = "test_output_alerts.csv"
        try:
            SiemExporter.export_alerts_csv(self.summary, out_file)
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Alert ID", content)
            self.assertIn("ALT-001", content)
            self.assertIn("Password Guessing", content)
        finally:
            if os.path.exists(out_file):
                os.remove(out_file)


if __name__ == "__main__":
    unittest.main()
