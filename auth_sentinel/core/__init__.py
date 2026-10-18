"""Core data structures and configurations."""
from .models import AuthEvent, DetectionAlert, IncidentSummary, IPProfile, GeoLocation, SeverityLevel, AttackType
from .config import SentinelConfig, DEFAULT_CONFIG

__all__ = [
    "AuthEvent",
    "DetectionAlert",
    "IncidentSummary",
    "IPProfile",
    "GeoLocation",
    "SeverityLevel",
    "AttackType",
    "SentinelConfig",
    "DEFAULT_CONFIG",
]
