"""
Detector for Account Enumeration (Systematic attempts against non-existent accounts).
"""

from collections import defaultdict
from typing import List
from ..core.config import SentinelConfig
from ..core.models import AuthEvent, DetectionAlert, AttackType, SeverityLevel
from ..mitre.mapping import get_mitre_info


class AccountEnumerationDetector:
    """Detects systematic probing for invalid or non-existent usernames."""

    def __init__(self, config: SentinelConfig):
        self.config = config

    def detect(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        invalid_events_by_ip = defaultdict(list)

        for ev in sorted(events, key=lambda x: x.timestamp):
            if ev.is_invalid_user and ev.ip != "0.0.0.0":
                invalid_events_by_ip[ev.ip].append(ev)

        alert_idx = 0
        for ip, ev_list in invalid_events_by_ip.items():
            n = len(ev_list)
            if n < self.config.account_enum_threshold:
                continue

            left = 0
            for right in range(n):
                window_duration = (ev_list[right].timestamp - ev_list[left].timestamp).total_seconds()
                while window_duration > self.config.account_enum_window_seconds and left < right:
                    left += 1
                    window_duration = (ev_list[right].timestamp - ev_list[left].timestamp).total_seconds()

                count_in_window = right - left + 1
                if count_in_window >= self.config.account_enum_threshold:
                    alert_idx += 1
                    mitre = get_mitre_info(AttackType.ACCOUNT_ENUMERATION)
                    unique_invalid_users = sorted({e.username for e in ev_list[left : right + 1]})

                    alerts.append(
                        DetectionAlert(
                            alert_id=f"ALT-AE-{alert_idx:04d}",
                            timestamp=ev_list[right].timestamp,
                            attack_type=AttackType.ACCOUNT_ENUMERATION,
                            severity=SeverityLevel.MEDIUM,
                            source_ip=ip,
                            targeted_users=unique_invalid_users,
                            attempt_count=count_in_window,
                            time_window_seconds=round(window_duration, 2),
                            mitre_technique_id=mitre.technique_id,
                            mitre_technique_name=mitre.technique_name,
                            description=(
                                f"Account enumeration activity from IP {ip}: tested {count_in_window} invalid users "
                                f"({', '.join(unique_invalid_users[:4])}) within {window_duration:.1f}s."
                            ),
                            recommended_action=mitre.soc_playbook[0],
                            evidence_events=[e.to_dict() for e in ev_list[left : right + 1]],
                        )
                    )
                    left = right + 1

        return alerts
