"""
Auto-detection and parsing dispatcher for multi-format log lines.
"""

from typing import List, Optional
from .base import BaseLogParser
from .linux_ssh import LinuxSSHParser
from .windows import WindowsEventParser
from .web_nginx import WebAuthParser
from .ftp_rdp import FTPLogParser
from .json_audit import JSONAuditParser
from ..core.models import AuthEvent


class FallbackGenericParser(BaseLogParser):
    """Fallback parser for generic logs that contain authentication keywords."""

    name = "FallbackGenericParser"
    service_name = "GENERIC"

    FAILURE_KEYWORDS = [
        "failed password",
        "authentication failure",
        "login failed",
        "failed login",
        "fail login",
        "invalid password",
        "invalid credentials",
        "auth failed",
        "access denied",
        "bad password",
    ]
    SUCCESS_KEYWORDS = [
        "accepted password",
        "login successful",
        "authentication succeeded",
        "session opened",
        "access granted",
    ]

    def can_parse(self, line: str) -> bool:
        lowered = line.lower()
        return any(k in lowered for k in self.FAILURE_KEYWORDS) or any(k in lowered for k in self.SUCCESS_KEYWORDS)

    def parse(self, line: str, event_id: str) -> Optional[AuthEvent]:
        timestamp = self.extract_timestamp(line)
        ip = self.extract_ip(line)
        lowered = line.lower()

        status = "UNKNOWN"
        failure_reason = ""
        if any(k in lowered for k in self.FAILURE_KEYWORDS):
            status = "FAILED"
            failure_reason = "Generic authentication failure"
        elif any(k in lowered for k in self.SUCCESS_KEYWORDS):
            status = "SUCCESS"

        # Guess service
        service = "UNKNOWN"
        if "ssh" in lowered:
            service = "SSH"
        elif "ftp" in lowered:
            service = "FTP"
        elif "rdp" in lowered:
            service = "RDP"
        elif "web" in lowered or "http" in lowered:
            service = "WEB"

        # Guess username
        username = "unknown"
        import re

        user_match = (
            re.search(r"\buser(?:name)?=([a-zA-Z0-9._@-]+)", line, re.IGNORECASE)
            or re.search(r"\bfor invalid user\s+([a-zA-Z0-9._@-]+)", line, re.IGNORECASE)
            or re.search(r"\bfor\s+([a-zA-Z0-9._@-]+)\s+from\b", line, re.IGNORECASE)
            or re.search(r'\buser\s+"([a-zA-Z0-9._@-]+)"', line, re.IGNORECASE)
            or re.search(r"\buser:?\s*([a-zA-Z0-9._@-]+)", line, re.IGNORECASE)
        )
        if user_match:
            username = user_match.group(1)

        return AuthEvent(
            event_id=event_id,
            timestamp=timestamp,
            service=service,
            ip=ip,
            username=username,
            status=status,
            raw_line=line,
            failure_reason=failure_reason,
            is_invalid_user="invalid user" in lowered,
        )


class LogParserDispatcher:
    """Manages active parsers and routes lines to the appropriate parser."""

    def __init__(self, custom_parsers: Optional[List[BaseLogParser]] = None):
        self.parsers: List[BaseLogParser] = custom_parsers or [
            JSONAuditParser(),
            LinuxSSHParser(),
            WindowsEventParser(),
            WebAuthParser(),
            FTPLogParser(),
            FallbackGenericParser(),
        ]
        self._counter = 0

    def parse_line(self, raw_line: str) -> Optional[AuthEvent]:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            return None

        self._counter += 1
        event_id = f"EVT-{self._counter:06d}"

        for parser in self.parsers:
            if parser.can_parse(line):
                event = parser.parse(line, event_id)
                if event and event.status in ("FAILED", "SUCCESS"):
                    return event

        return None

    def parse_file(self, file_path: str) -> List[AuthEvent]:
        events: List[AuthEvent] = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                event = self.parse_line(line)
                if event:
                    events.append(event)
        return events
