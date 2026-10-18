"""
Detection thresholds, scoring weights, and system configurations.
"""

from dataclasses import dataclass, field
from typing import List, Set


@dataclass
class SentinelConfig:
    # Brute Force Detection (Single IP -> Single User)
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 120

    # Password Spraying Detection (Single IP -> Multiple Unique Users)
    password_spray_threshold: int = 4
    password_spray_window_seconds: int = 300

    # Account Enumeration Detection (Testing Invalid Usernames)
    account_enum_threshold: int = 3
    account_enum_window_seconds: int = 180

    # Impossible Travel Detection
    impossible_travel_speed_kmh: float = 800.0  # Max realistic commercial flight speed
    impossible_travel_min_km: float = 200.0

    # Compromise Detection (Failed Attempts followed by Success)
    compromise_window_seconds: int = 600
    compromise_min_failed_before_success: int = 3

    # Threat Scoring Thresholds
    high_risk_score_threshold: int = 70
    medium_risk_score_threshold: int = 40

    # High-Privilege / Sensitive Accounts
    privileged_accounts: Set[str] = field(
        default_factory=lambda: {
            "root",
            "admin",
            "administrator",
            "sa",
            "oracle",
            "postgres",
            "sysadmin",
            "support",
            "guest",
            "backup",
            "deploy",
            "master",
        }
    )

    # Features toggle
    enable_threat_intel: bool = True
    enable_geoip: bool = True


DEFAULT_CONFIG = SentinelConfig()
