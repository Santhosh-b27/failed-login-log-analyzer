"""
Detection module for AuthSentinel.
"""

from .engine import DetectionEngine
from .brute_force import BruteForceDetector
from .password_spray import PasswordSprayDetector
from .account_enum import AccountEnumerationDetector
from .impossible_travel import ImpossibleTravelDetector
from .breach_detect import BreachConfirmationDetector

__all__ = [
    "DetectionEngine",
    "BruteForceDetector",
    "PasswordSprayDetector",
    "AccountEnumerationDetector",
    "ImpossibleTravelDetector",
    "BreachConfirmationDetector",
]
