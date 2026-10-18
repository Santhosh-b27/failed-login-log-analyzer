"""
Detector for Horizontal Password Spraying (Single IP targeting multiple distinct usernames).
"""

from collections import defaultdict
from typing import List
from ..core.config import SentinelConfig
from ..core.models import AuthEvent, DetectionAlert, AttackType, SeverityLevel
from ..mitre.mapping import get_mitre_info


class PasswordSprayDetector:
    """Detects when an IP sprays passwords across multiple accounts to bypass lockout policies."""

    def __init__(self, config: SentinelConfig):
        self.config = config

    def detect(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        # Group failed events by IP
        grouped_by_ip = defaultdict(list)
        for ev in sorted(events, key=lambda x: x.timestamp):
            if ev.status == "FAILED" and ev.ip != "0.0.0.0" and ev.username != "unknown":
                grouped_by_ip[ev.ip].append(ev)

        alert_idx = 0
        for ip, ip_events in grouped_by_ip.items():
            n = len(ip_events)
            if n < self.config.password_spray_threshold:
                continue

            left = 0
            for right in range(n):
                window_duration = (ip_events[right].timestamp - ip_events[left].timestamp).total_seconds()
                while window_duration > self.config.password_spray_window_seconds and left < right:
                    left += 1
                    window_duration = (ip_events[right].timestamp - ip_events[left].timestamp).total_seconds()

                window_events = ip_events[left : right + 1]
                unique_users = sorted({e.username for e in window_events})

                if len(unique_users) >= self.config.password_spray_threshold:
                    alert_idx += 1
                    mitre = get_mitre_info(AttackType.PASSWORD_SPRAY)

                    alerts.append(
                        DetectionAlert(
                            alert_id=f"ALT-PS-{alert_idx:04d}",
                            timestamp=ip_events[right].timestamp,
                            attack_type=AttackType.PASSWORD_SPRAY,
                            severity=SeverityLevel.HIGH,
                            source_ip=ip,
                            targeted_users=unique_users,
                            attempt_count=len(window_events),
                            time_window_seconds=round(window_duration, 2),
                            mitre_technique_id=mitre.technique_id,
                            mitre_technique_name=mitre.technique_name,
                            description=(
                                f"Password spraying detected from IP {ip}: attempted {len(window_events)} logins "
                                f"across {len(unique_users)} distinct accounts ({', '.join(unique_users[:5])}"
                                + (f" and {len(unique_users)-5} more" if len(unique_users) > 5 else "")
                                + f") within {window_duration:.1f}s."
                            ),
                            recommended_action=mitre.soc_playbook[0],
                            evidence_events=[e.to_dict() for e in window_events],
                        )
                    )
                    # Advance to skip overlapping alerts
                    left = right + 1

        return alerts
