"""
Detector for Impossible Travel Anomalies (Geo-velocity correlation for single user accounts).
"""

from collections import defaultdict
from typing import List
from ..core.config import SentinelConfig
from ..core.models import AuthEvent, DetectionAlert, AttackType, SeverityLevel
from ..enrichment.geoip import GeoIPResolver
from ..mitre.mapping import get_mitre_info


class ImpossibleTravelDetector:
    """Detects geographically impossible login velocity for the same user account."""

    def __init__(self, config: SentinelConfig):
        self.config = config

    def detect(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        user_events = defaultdict(list)

        # Sort events by timestamp
        for ev in sorted(events, key=lambda x: x.timestamp):
            if ev.username and ev.username != "unknown" and ev.geo and not ev.geo.is_private:
                user_events[ev.username].append(ev)

        alert_idx = 0
        for username, ev_list in user_events.items():
            if len(ev_list) < 2:
                continue

            for i in range(len(ev_list) - 1):
                ev1 = ev_list[i]
                ev2 = ev_list[i + 1]

                # Check if from different IP addresses
                if ev1.ip == ev2.ip:
                    continue

                # Ensure valid coordinates
                if (ev1.geo.latitude == 0.0 and ev1.geo.longitude == 0.0) or (
                    ev2.geo.latitude == 0.0 and ev2.geo.longitude == 0.0
                ):
                    continue

                distance_km = GeoIPResolver.calculate_distance_km(
                    ev1.geo.latitude, ev1.geo.longitude, ev2.geo.latitude, ev2.geo.longitude
                )

                if distance_km < self.config.impossible_travel_min_km:
                    continue

                time_diff_seconds = abs((ev2.timestamp - ev1.timestamp).total_seconds())
                time_diff_hours = max(time_diff_seconds / 3600.0, 0.0001)

                speed_kmh = distance_km / time_diff_hours

                if speed_kmh > self.config.impossible_travel_speed_kmh:
                    alert_idx += 1
                    mitre = get_mitre_info(AttackType.IMPOSSIBLE_TRAVEL)

                    alerts.append(
                        DetectionAlert(
                            alert_id=f"ALT-IT-{alert_idx:04d}",
                            timestamp=ev2.timestamp,
                            attack_type=AttackType.IMPOSSIBLE_TRAVEL,
                            severity=SeverityLevel.HIGH,
                            source_ip=ev2.ip,
                            targeted_users=[username],
                            attempt_count=2,
                            time_window_seconds=round(time_diff_seconds, 2),
                            mitre_technique_id=mitre.technique_id,
                            mitre_technique_name=mitre.technique_name,
                            description=(
                                f"Impossible travel detected for user '{username}': logged in from "
                                f"{ev1.geo.city}, {ev1.geo.country} ({ev1.ip}) and then from "
                                f"{ev2.geo.city}, {ev2.geo.country} ({ev2.ip}). "
                                f"Distance: {distance_km:.0f} km within {time_diff_seconds/60:.1f} mins "
                                f"(calculated velocity: {speed_kmh:.0f} km/h, exceeds max {self.config.impossible_travel_speed_kmh} km/h)."
                            ),
                            recommended_action=mitre.soc_playbook[0],
                            evidence_events=[ev1.to_dict(), ev2.to_dict()],
                        )
                    )

        return alerts
