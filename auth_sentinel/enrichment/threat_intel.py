"""
Threat intelligence enrichment, reputation analysis, and dynamic risk scoring.
"""

from typing import List, Set, Tuple
from ..core.config import SentinelConfig, DEFAULT_CONFIG
from ..core.models import IPProfile, SeverityLevel


class ThreatIntelligenceEngine:
    """Calculates risk scores, attributes threat tags, and evaluates IP profiles."""

    # Curated known threat tags / indicators
    KNOWN_TOR_IPS = {"185.220.101.5", "185.220.101.6", "185.220.101.7"}
    SUSPICIOUS_ASNS = {"AS131279", "AS12389"}

    def __init__(self, config: SentinelConfig = DEFAULT_CONFIG):
        self.config = config

    def calculate_ip_risk_score(self, profile: IPProfile) -> Tuple[int, List[str], SeverityLevel]:
        """
        Calculate an overall Risk Score (0-100) and risk factors for an IPProfile.
        """
        score = 0
        factors: List[str] = []

        # 1. Volume of failed attempts
        failed = profile.failed_attempts
        if failed >= 20:
            score += 40
            factors.append(f"High failure volume ({failed} failed attempts)")
        elif failed >= 10:
            score += 25
            factors.append(f"Moderate failure volume ({failed} failed attempts)")
        elif failed >= 5:
            score += 15
            factors.append(f"Repeated failures ({failed} attempts)")
        elif failed >= 1:
            score += 5

        # 2. Targeted Accounts Analysis
        targeted_users_lower = {u.lower() for u in profile.targeted_users}
        targeted_privileged = targeted_users_lower.intersection(self.config.privileged_accounts)
        if targeted_privileged:
            score += 25
            factors.append(f"Targeted privileged accounts: {', '.join(sorted(targeted_privileged))}")

        # 3. Horizontal Password Spraying (multiple users)
        unique_users_count = len(profile.targeted_users)
        if unique_users_count >= self.config.password_spray_threshold:
            score += 30
            factors.append(f"Password spraying pattern across {unique_users_count} distinct usernames")
        elif unique_users_count > 1:
            score += 10
            factors.append(f"Targeted multiple users ({unique_users_count} accounts)")

        # 4. Multi-Service Targeting (pivoting / wide scan)
        if len(profile.targeted_services) > 1:
            score += 15
            factors.append(f"Targeted multiple services: {', '.join(profile.targeted_services)}")

        # 5. Geolocation / Infrastructure threat factors
        if profile.geo:
            if profile.ip in self.KNOWN_TOR_IPS or "Tor" in profile.geo.isp:
                score += 30
                factors.append("Known Tor Exit Node / Anonymization Proxy")
            for asn in self.SUSPICIOUS_ASNS:
                if asn in profile.geo.isp:
                    score += 20
                    factors.append(f"High-risk Autonomous System ({asn})")

        # 6. Critical Alert Presence (e.g. Compromise detected)
        for alert_str in profile.alerts_triggered:
            if "Compromise" in alert_str:
                score = 100
                factors.append("CRITICAL: Confirmed successful authentication following attack")
                break
            elif "Brute Force" in alert_str:
                score += 15
                factors.append("Triggered automated Brute Force alert")

        # Clamp score to [0, 100]
        score = min(100, max(0, score))

        # Severity Classification
        if score >= self.config.high_risk_score_threshold:
            severity = SeverityLevel.CRITICAL if score >= 90 else SeverityLevel.HIGH
        elif score >= self.config.medium_risk_score_threshold:
            severity = SeverityLevel.MEDIUM
        elif score > 10:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.INFO

        return score, factors, severity
