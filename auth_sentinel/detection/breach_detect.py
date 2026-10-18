"""
Detector for Confirmed Compromise (Failed authentication burst followed immediately by a successful login).
"""

from collections import defaultdict
from typing import List
from ..core.config import SentinelConfig
from ..core.models import AuthEvent, DetectionAlert, AttackType, SeverityLevel
from ..mitre.mapping import get_mitre_info


class BreachConfirmationDetector:
    """Detects when an attacker successfully logs in after multiple failed password attempts."""

    def __init__(self, config: SentinelConfig):
        self.config = config

    def detect(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        events_by_ip = defaultdict(list)

        for ev in sorted(events, key=lambda x: x.timestamp):
            if ev.ip != "0.0.0.0":
                events_by_ip[ev.ip].append(ev)

        alert_idx = 0
        for ip, ip_events in events_by_ip.items():
            failed_streak: List[AuthEvent] = []

            for ev in ip_events:
                if ev.status == "FAILED":
                    failed_streak.append(ev)
                elif ev.status == "SUCCESS":
                    if len(failed_streak) >= self.config.compromise_min_failed_before_success:
                        time_since_first_fail = (ev.timestamp - failed_streak[0].timestamp).total_seconds()

                        if time_since_first_fail <= self.config.compromise_window_seconds:
                            alert_idx += 1
                            mitre = get_mitre_info(AttackType.BREACH_CONFIRMED)
                            affected_user = ev.username

                            alerts.append(
                                DetectionAlert(
                                    alert_id=f"ALT-BR-{alert_idx:04d}",
                                    timestamp=ev.timestamp,
                                    attack_type=AttackType.BREACH_CONFIRMED,
                                    severity=SeverityLevel.CRITICAL,
                                    source_ip=ip,
                                    targeted_users=[affected_user],
                                    attempt_count=len(failed_streak) + 1,
                                    time_window_seconds=round(time_since_first_fail, 2),
                                    mitre_technique_id=mitre.technique_id,
                                    mitre_technique_name=mitre.technique_name,
                                    description=(
                                        f"POTENTIAL BREACH CONFIRMED: IP {ip} executed {len(failed_streak)} failed attempts "
                                        f"and then gained SUCCESSFUL authentication as '{affected_user}' within {time_since_first_fail:.1f}s!"
                                    ),
                                    recommended_action=mitre.soc_playbook[0],
                                    evidence_events=[f.to_dict() for f in failed_streak] + [ev.to_dict()],
                                )
                            )

                    # Reset streak after success evaluation
                    failed_streak = []

        return alerts
