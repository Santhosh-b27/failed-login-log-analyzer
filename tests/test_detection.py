"""
Unit tests for AuthSentinel detection engine and correlation algorithms.
"""

import unittest
from datetime import datetime, timedelta
from auth_sentinel.core.config import SentinelConfig
from auth_sentinel.core.models import AuthEvent, AttackType, GeoLocation
from auth_sentinel.detection.brute_force import BruteForceDetector
from auth_sentinel.detection.password_spray import PasswordSprayDetector
from auth_sentinel.detection.impossible_travel import ImpossibleTravelDetector
from auth_sentinel.detection.breach_detect import BreachConfirmationDetector
from auth_sentinel.detection.engine import DetectionEngine


class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
        self.config = SentinelConfig(
            brute_force_threshold=3,
            brute_force_window_seconds=60,
            password_spray_threshold=3,
            password_spray_window_seconds=120,
            compromise_min_failed_before_success=2,
            compromise_window_seconds=300,
            impossible_travel_speed_kmh=800.0,
        )

    def test_brute_force_detection(self):
        detector = BruteForceDetector(self.config)
        base = datetime(2026, 10, 18, 12, 0, 0)
        events = [
            AuthEvent(
                event_id=f"EVT-{i}",
                timestamp=base + timedelta(seconds=i * 5),
                service="SSH",
                ip="198.51.100.1",
                username="admin",
                status="FAILED",
                raw_line="",
            )
            for i in range(4)
        ]
        alerts = detector.detect(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, AttackType.BRUTE_FORCE)
        self.assertEqual(alerts[0].source_ip, "198.51.100.1")
        self.assertEqual(alerts[0].targeted_users, ["admin"])

    def test_password_spray_detection(self):
        detector = PasswordSprayDetector(self.config)
        base = datetime(2026, 10, 18, 12, 0, 0)
        users = ["user1", "user2", "user3", "user4"]
        events = [
            AuthEvent(
                event_id=f"EVT-{i}",
                timestamp=base + timedelta(seconds=i * 10),
                service="SSH",
                ip="198.51.100.2",
                username=users[i],
                status="FAILED",
                raw_line="",
            )
            for i in range(4)
        ]
        alerts = detector.detect(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, AttackType.PASSWORD_SPRAY)
        self.assertEqual(alerts[0].source_ip, "198.51.100.2")
        self.assertGreaterEqual(len(alerts[0].targeted_users), 3)

    def test_impossible_travel_detection(self):
        detector = ImpossibleTravelDetector(self.config)
        base = datetime(2026, 10, 18, 12, 0, 0)
        # Location 1: New York (US)
        geo1 = GeoLocation(ip="45.33.32.1", country="United States", city="Fremont", latitude=37.5485, longitude=-121.9886)
        ev1 = AuthEvent(
            event_id="EVT-1",
            timestamp=base,
            service="WEB",
            ip="45.33.32.1",
            username="john",
            status="SUCCESS",
            raw_line="",
            geo=geo1,
        )

        # Location 2: Frankfurt (Germany), 10 minutes later (distance ~ 9,000 km)
        geo2 = GeoLocation(ip="185.220.101.1", country="Germany", city="Frankfurt", latitude=50.1109, longitude=8.6821)
        ev2 = AuthEvent(
            event_id="EVT-2",
            timestamp=base + timedelta(minutes=10),
            service="WEB",
            ip="185.220.101.1",
            username="john",
            status="FAILED",
            raw_line="",
            geo=geo2,
        )

        alerts = detector.detect([ev1, ev2])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, AttackType.IMPOSSIBLE_TRAVEL)
        self.assertEqual(alerts[0].targeted_users, ["john"])

    def test_breach_confirmation_detection(self):
        detector = BreachConfirmationDetector(self.config)
        base = datetime(2026, 10, 18, 12, 0, 0)
        events = [
            AuthEvent(
                event_id="EVT-1",
                timestamp=base,
                service="RDP",
                ip="192.0.2.5",
                username="administrator",
                status="FAILED",
                raw_line="",
            ),
            AuthEvent(
                event_id="EVT-2",
                timestamp=base + timedelta(seconds=10),
                service="RDP",
                ip="192.0.2.5",
                username="administrator",
                status="FAILED",
                raw_line="",
            ),
            AuthEvent(
                event_id="EVT-3",
                timestamp=base + timedelta(seconds=20),
                service="RDP",
                ip="192.0.2.5",
                username="administrator",
                status="SUCCESS",
                raw_line="",
            ),
        ]
        alerts = detector.detect(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, AttackType.BREACH_CONFIRMED)
        self.assertEqual(alerts[0].severity.value, "CRITICAL")
        self.assertEqual(alerts[0].source_ip, "192.0.2.5")

    def test_full_detection_engine(self):
        engine = DetectionEngine(self.config)
        base = datetime(2026, 10, 18, 12, 0, 0)
        events = [
            AuthEvent(
                event_id=f"EVT-{i}",
                timestamp=base + timedelta(seconds=i * 2),
                service="SSH",
                ip="203.0.113.10",
                username="root",
                status="FAILED",
                raw_line="",
            )
            for i in range(5)
        ]
        summary = engine.process_events(events)
        self.assertEqual(summary.total_events, 5)
        self.assertEqual(summary.total_failed, 5)
        self.assertGreaterEqual(len(summary.alerts), 1)
        self.assertIn("203.0.113.10", summary.ip_profiles)
        self.assertGreater(summary.ip_profiles["203.0.113.10"].risk_score, 50)


if __name__ == "__main__":
    unittest.main()
