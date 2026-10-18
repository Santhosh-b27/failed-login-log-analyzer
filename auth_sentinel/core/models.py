"""
Core domain models and dataclasses for AuthSentinel.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(str, Enum):
    BRUTE_FORCE = "Brute Force (Single User)"
    PASSWORD_SPRAY = "Password Spraying"
    ACCOUNT_ENUMERATION = "Account Enumeration"
    IMPOSSIBLE_TRAVEL = "Impossible Travel Anomaly"
    BREACH_CONFIRMED = "Compromise After Attack (Critical)"
    CREDENTIAL_STUFFING = "Credential Stuffing"
    ANOMALOUS_GEO = "Anomalous Geolocation Activity"


@dataclass
class GeoLocation:
    ip: str
    country: str = "Unknown"
    country_code: str = "XX"
    city: str = "Unknown"
    latitude: float = 0.0
    longitude: float = 0.0
    isp: str = "Unknown"
    is_private: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthEvent:
    event_id: str
    timestamp: datetime
    service: str  # SSH, RDP, FTP, WEB, PAM, WINLOGON, CLOUD
    ip: str
    username: str
    status: str  # SUCCESS, FAILED, UNKNOWN
    raw_line: str
    failure_reason: str = ""
    port: Optional[int] = None
    hostname: str = ""
    is_invalid_user: bool = False
    geo: Optional[GeoLocation] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


@dataclass
class DetectionAlert:
    alert_id: str
    timestamp: datetime
    attack_type: AttackType
    severity: SeverityLevel
    source_ip: str
    targeted_users: List[str]
    attempt_count: int
    time_window_seconds: float
    mitre_technique_id: str
    mitre_technique_name: str
    description: str
    recommended_action: str
    evidence_events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "attack_type": self.attack_type.value,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "targeted_users": self.targeted_users,
            "attempt_count": self.attempt_count,
            "time_window_seconds": self.time_window_seconds,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "description": self.description,
            "recommended_action": self.recommended_action,
            "evidence_count": len(self.evidence_events),
        }


@dataclass
class IPProfile:
    ip: str
    total_attempts: int = 0
    failed_attempts: int = 0
    success_attempts: int = 0
    targeted_users: List[str] = field(default_factory=list)
    targeted_services: List[str] = field(default_factory=list)
    risk_score: int = 0  # 0 to 100
    risk_factors: List[str] = field(default_factory=list)
    geo: Optional[GeoLocation] = None
    alerts_triggered: List[str] = field(default_factory=list)
    is_malicious: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.geo:
            d["geo"] = self.geo.to_dict()
        return d


@dataclass
class IncidentSummary:
    total_events: int = 0
    total_failed: int = 0
    total_success: int = 0
    unique_ips: int = 0
    unique_users: int = 0
    high_risk_ips: int = 0
    timeframe_start: Optional[datetime] = None
    timeframe_end: Optional[datetime] = None
    alerts: List[DetectionAlert] = field(default_factory=list)
    ip_profiles: Dict[str, IPProfile] = field(default_factory=dict)
    service_breakdown: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_events": self.total_events,
            "total_failed": self.total_failed,
            "total_success": self.total_success,
            "unique_ips": self.unique_ips,
            "unique_users": self.unique_users,
            "high_risk_ips": self.high_risk_ips,
            "timeframe_start": self.timeframe_start.isoformat() if self.timeframe_start else None,
            "timeframe_end": self.timeframe_end.isoformat() if self.timeframe_end else None,
            "alerts": [alert.to_dict() for alert in self.alerts],
            "ip_profiles": {ip: prof.to_dict() for ip, prof in self.ip_profiles.items()},
            "service_breakdown": self.service_breakdown,
        }
