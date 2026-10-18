"""
Detector for Vertical Brute Force (High frequency password guessing against a single user).
"""

from collections import defaultdict
from typing import List
from ..core.config import SentinelConfig
from ..core.models import AuthEvent, DetectionAlert, AttackType, SeverityLevel
from ..mitre.mapping import get_mitre_info


class BruteForceDetector:
    """Detects repeated authentication failures from a single IP targeting a specific user."""

    def __init__(self, config: SentinelConfig):
        self.config = config

    def detect(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        # Group by (ip, username)
        grouped = defaultdict(list)
        for ev in sorted(events, key=lambda x: x.timestamp):
            if ev.status == "FAILED" and ev.ip != "0.0.0.0" and ev.username != "unknown":
                grouped[(ev.ip, ev.username)].append(ev)

        alert_idx = 0
        for (ip, username), user_events in grouped.items():
            n = len(user_events)
            if n < self.config.brute_force_threshold:
                continue

            # Sliding window check
            left = 0
            for right in range(n):
                window_duration = (user_events[right].timestamp - user_events[left].timestamp).total_seconds()
                while window_duration > self.config.brute_force_window_seconds and left < right:
                    left += 1
                    window_duration = (user_events[right].timestamp - user_events[left].timestamp).total_seconds()

                count_in_window = right - left + 1
                if count_in_window >= self.config.brute_force_threshold:
                    alert_idx += 1
                    mitre = get_mitre_info(AttackType.BRUTE_FORCE)
                    is_privileged = username.lower() in self.config.privileged_accounts
                    severity = SeverityLevel.CRITICAL if is_privileged else SeverityLevel.HIGH

                    alerts.append(
                        DetectionAlert(
                            alert_id=f"ALT-BF-{alert_idx:04d}",
                            timestamp=user_events[right].timestamp,
                            attack_type=AttackType.BRUTE_FORCE,
                            severity=severity,
                            source_ip=ip,
                            targeted_users=[username],
                            attempt_count=count_in_window,
                            time_window_seconds=round(window_duration, 2),
                            mitre_technique_id=mitre.technique_id,
                            mitre_technique_name=mitre.technique_name,
                            description=(
                                f"Observed {count_in_window} failed authentication attempts against user '{username}' "
                                f"from IP {ip} within {window_duration:.1f}s."
                                + (" [Targeting Privileged Account]" if is_privileged else "")
                            ),
                            recommended_action=mitre.soc_playbook[0],
                            evidence_events=[e.to_dict() for e in user_events[left : right + 1]],
                        )
                    )
                    # Advance left past this burst to avoid duplicate overlapping alerts
                    left = right + 1

        return alerts
