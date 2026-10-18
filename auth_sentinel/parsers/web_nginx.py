"""
Parser for Web Application, Nginx, and Apache authentication logs.
"""

import re
from typing import Optional
from .base import BaseLogParser
from ..core.models import AuthEvent


class WebAuthParser(BaseLogParser):
    """Parses Web Server (Nginx, Apache, API) authentication logs."""

    name = "WebAuthParser"
    service_name = "WEB"

    STATUS_CODE_REGEX = re.compile(r"\b(?:status=|HTTP/\d\.\d\"\s+)(\d{3})\b", re.IGNORECASE)

    def can_parse(self, line: str) -> bool:
        lowered = line.lower()
        return (
            "nginx" in lowered
            or "apache" in lowered
            or "webapp" in lowered
            or "/login" in lowered
            or "http" in lowered
            or "/api/auth" in lowered
        )

    def parse(self, line: str, event_id: str) -> Optional[AuthEvent]:
        timestamp = self.extract_timestamp(line)
        ip = self.extract_ip(line)
        status = "UNKNOWN"
        failure_reason = ""
        is_invalid_user = False

        # Extract HTTP Status Code if present
        status_match = self.STATUS_CODE_REGEX.search(line)
        status_code = int(status_match.group(1)) if status_match else None

        lowered = line.lower()
        if status_code in (401, 403) or "invalid" in lowered or "fail" in lowered or "denied" in lowered:
            status = "FAILED"
            failure_reason = f"HTTP {status_code}: Unauthorized" if status_code else "Web Auth Failure"
        elif status_code in (200, 204, 302) or "login successful" in lowered or "accepted" in lowered:
            status = "SUCCESS"

        # Extract Username
        username = "unknown"
        user_match = (
            re.search(r'\busername="?([^"\s,]+)"?', line, re.IGNORECASE)
            or re.search(r'\buser="?([^"\s,]+)"?', line, re.IGNORECASE)
            or re.search(r'\buser=([^"\s,]+)', line, re.IGNORECASE)
            or re.search(r'\b"user"\s*:\s*"([^"]+)"', line, re.IGNORECASE)
        )
        if user_match:
            username = user_match.group(1)

        # Check for invalid account flag
        if "unknown user" in lowered or "user not found" in lowered:
            is_invalid_user = True
            failure_reason = "User account not found"

        return AuthEvent(
            event_id=event_id,
            timestamp=timestamp,
            service=self.service_name,
            ip=ip,
            username=username,
            status=status,
            raw_line=line,
            failure_reason=failure_reason,
            port=443 if "https" in lowered else 80,
            is_invalid_user=is_invalid_user,
        )
