"""
Abstract Base Parser and common parsing helpers for AuthSentinel.
"""

from __future__ import annotations
import abc
import re
from datetime import datetime, timezone
from typing import Optional
from ..core.models import AuthEvent


class BaseLogParser(abc.ABC):
    """Abstract base class for all log format parsers."""

    name: str = "BaseParser"
    service_name = "UNKNOWN"

    # Common IPv4 Regex
    IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    # Common Timestamps: ISO8601, RFC3164 (Syslog), standard datetime
    ISO_TIMESTAMP_REGEX = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
    SYSLOG_TIMESTAMP_REGEX = re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

    @staticmethod
    def to_naive_utc(dt: datetime) -> datetime:
        """Convert any timezone-aware datetime to offset-naive UTC."""
        if dt.tzinfo is not None:
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt

    @abc.abstractmethod
    def can_parse(self, line: str) -> bool:
        """Return True if this parser can handle the given log line."""
        pass

    @abc.abstractmethod
    def parse(self, line: str, event_id: str) -> Optional[AuthEvent]:
        """Parse a single log line into an AuthEvent."""
        pass

    def extract_ip(self, line: str) -> str:
        """Extract the first valid IPv4 address from the line."""
        match = self.IP_REGEX.search(line)
        if match:
            return match.group(0)
        return "0.0.0.0"

    def extract_timestamp(self, line: str) -> datetime:
        """Extract or parse timestamp from line, fallback to current time."""
        # Try ISO8601 first
        iso_match = self.ISO_TIMESTAMP_REGEX.search(line)
        if iso_match:
            raw_ts = iso_match.group(1).replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(raw_ts)
                return self.to_naive_utc(dt)
            except ValueError:
                pass

        # Try Syslog (e.g., Oct 18 14:02:11)
        syslog_match = self.SYSLOG_TIMESTAMP_REGEX.search(line)
        if syslog_match:
            raw_ts = syslog_match.group(1)
            # Reconstruct with current year
            current_year = datetime.now().year
            try:
                # Normalize double space in dates like "Oct  5 14:02:11"
                normalized_ts = re.sub(r"\s+", " ", raw_ts)
                parsed = datetime.strptime(f"{current_year} {normalized_ts}", "%Y %b %d %H:%M:%S")
                return self.to_naive_utc(parsed)
            except ValueError:
                pass

        return self.to_naive_utc(datetime.now())
