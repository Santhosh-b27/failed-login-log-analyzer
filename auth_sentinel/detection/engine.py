"""
Correlation & Threat Detection Engine orchestrator for AuthSentinel.
"""

from collections import defaultdict
from typing import Dict, List, Optional
from ..core.config import SentinelConfig, DEFAULT_CONFIG
from ..core.models import AuthEvent, DetectionAlert, IncidentSummary, IPProfile
from ..enrichment.geoip import GeoIPResolver
from ..enrichment.threat_intel import ThreatIntelligenceEngine
from .brute_force import BruteForceDetector
from .password_spray import PasswordSprayDetector
from .account_enum import AccountEnumerationDetector
from .impossible_travel import ImpossibleTravelDetector
from .breach_detect import BreachConfirmationDetector


class DetectionEngine:
    """Orchestrates log enrichment, stateful correlation, and threat detection."""

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or DEFAULT_CONFIG
        self.geoip = GeoIPResolver()
        self.threat_intel = ThreatIntelligenceEngine(self.config)

        self.detectors = [
            BruteForceDetector(self.config),
            PasswordSprayDetector(self.config),
            AccountEnumerationDetector(self.config),
            ImpossibleTravelDetector(self.config),
            BreachConfirmationDetector(self.config),
        ]

    def process_events(self, events: List[AuthEvent]) -> IncidentSummary:
        """Run full correlation pipeline across provided authentication events."""
        if not events:
            return IncidentSummary()

        # Sort chronologically
        events.sort(key=lambda x: x.timestamp)

        # 1. Enrich events with GeoIP
        for ev in events:
            if not ev.geo and ev.ip != "0.0.0.0":
                ev.geo = self.geoip.resolve(ev.ip)

        # 2. Build preliminary IP Profiles and Service Breakdown
        ip_profiles: Dict[str, IPProfile] = {}
        service_breakdown: Dict[str, int] = defaultdict(int)
        unique_users = set()
        failed_count = 0
        success_count = 0

        for ev in events:
            service_breakdown[ev.service] += 1
            if ev.username and ev.username != "unknown":
                unique_users.add(ev.username)

            if ev.status == "FAILED":
                failed_count += 1
            elif ev.status == "SUCCESS":
                success_count += 1

            if ev.ip not in ip_profiles and ev.ip != "0.0.0.0":
                ip_profiles[ev.ip] = IPProfile(ip=ev.ip, geo=ev.geo)

            if ev.ip in ip_profiles:
                prof = ip_profiles[ev.ip]
                prof.total_attempts += 1
                if ev.status == "FAILED":
                    prof.failed_attempts += 1
                elif ev.status == "SUCCESS":
                    prof.success_attempts += 1

                if ev.username and ev.username != "unknown" and ev.username not in prof.targeted_users:
                    prof.targeted_users.append(ev.username)
                if ev.service and ev.service not in prof.targeted_services:
                    prof.targeted_services.append(ev.service)

        # 3. Run all detection heuristics
        all_alerts: List[DetectionAlert] = []
        for detector in self.detectors:
            alerts = detector.detect(events)
            all_alerts.extend(alerts)

        # Sort alerts chronologically
        all_alerts.sort(key=lambda a: a.timestamp)

        # 4. Map alerts back to IP Profiles and run Threat Scoring
        for alert in all_alerts:
            if alert.source_ip in ip_profiles:
                ip_profiles[alert.source_ip].alerts_triggered.append(alert.attack_type.value)

        high_risk_count = 0
        for ip, prof in ip_profiles.items():
            score, factors, severity = self.threat_intel.calculate_ip_risk_score(prof)
            prof.risk_score = score
            prof.risk_factors = factors
            prof.is_malicious = score >= self.config.high_risk_score_threshold
            if prof.is_malicious:
                high_risk_count += 1

        summary = IncidentSummary(
            total_events=len(events),
            total_failed=failed_count,
            total_success=success_count,
            unique_ips=len(ip_profiles),
            unique_users=len(unique_users),
            high_risk_ips=high_risk_count,
            timeframe_start=events[0].timestamp if events else None,
            timeframe_end=events[-1].timestamp if events else None,
            alerts=all_alerts,
            ip_profiles=ip_profiles,
            service_breakdown=dict(service_breakdown),
        )

        return summary
