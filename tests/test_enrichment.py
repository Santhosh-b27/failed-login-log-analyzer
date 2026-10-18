"""
Unit tests for GeoIP resolver and Threat Intelligence engine.
"""

import unittest
from auth_sentinel.core.models import IPProfile
from auth_sentinel.enrichment.geoip import GeoIPResolver
from auth_sentinel.enrichment.threat_intel import ThreatIntelligenceEngine


class TestEnrichment(unittest.TestCase):
    def setUp(self):
        self.geoip = GeoIPResolver()
        self.intel = ThreatIntelligenceEngine()

    def test_rfc1918_private_ip(self):
        geo = self.geoip.resolve("192.168.1.1")
        self.assertTrue(geo.is_private)
        self.assertEqual(geo.country_code, "LOCAL")

    def test_public_geoip_resolution(self):
        geo = self.geoip.resolve("203.0.113.10")
        self.assertFalse(geo.is_private)
        self.assertEqual(geo.country_code, "RU")
        self.assertEqual(geo.country, "Russian Federation")

    def test_distance_calculation(self):
        # Distance between NY (40.7128, -74.0060) and London (51.5074, -0.1278) ~ 5570 km
        d = GeoIPResolver.calculate_distance_km(40.7128, -74.0060, 51.5074, -0.1278)
        self.assertGreater(d, 5000)
        self.assertLess(d, 6000)

    def test_threat_score_calculation(self):
        profile = IPProfile(
            ip="203.0.113.5",
            total_attempts=25,
            failed_attempts=25,
            targeted_users=["root", "admin", "service"],
            targeted_services=["SSH", "RDP"],
        )
        score, factors, severity = self.intel.calculate_ip_risk_score(profile)
        self.assertGreaterEqual(score, 70)
        self.assertIn("CRITICAL", [severity.value, "HIGH"])
        self.assertGreaterEqual(len(factors), 2)


if __name__ == "__main__":
    unittest.main()
