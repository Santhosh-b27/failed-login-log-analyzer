"""
Parser for Windows Security Event Logs (Event IDs 4625, 4624) and RDP Auth.
"""

import re
from typing import Optional
from .base import BaseLogParser
from ..core.models import AuthEvent


class WindowsEventParser(BaseLogParser):
    """Parses Windows Security Auditing (4625, 4624) and RDP login events."""

    name = "WindowsEventParser"
    service_name = "WINDOWS_RDP"

    def can_parse(self, line: str) -> bool:
        lowered = line.lower()
        return (
            "4625" in lowered
            or "4624" in lowered
            or "security-auditing" in lowered
            or "rdpauth" in lowered
            or "terminalservices" in lowered
            or "mstsc" in lowered
        )

    def parse(self, line: str, event_id: str) -> Optional[AuthEvent]:
        timestamp = self.extract_timestamp(line)
        lowered = line.lower()
        ip = self.extract_ip(line)
        status = "UNKNOWN"
        failure_reason = ""
        service = "RDP" if ("rdp" in lowered or "terminal" in lowered or "logon type: 10" in lowered) else "WINLOGON"
        is_invalid_user = False

        if "4625" in lowered or "failed" in lowered or "failure" in lowered:
            status = "FAILED"
            failure_reason = "Logon Failure (Bad password or unknown account)"
        elif "4624" in lowered or "success" in lowered or "successful" in lowered:
            status = "SUCCESS"

        # Extract Username
        username = "unknown"
        user_match = (
            re.search(r"\bAccount Name:\s*([^\s,]+)", line, re.IGNORECASE)
            or re.search(r"\bAccount:\s*([^\s,]+)", line, re.IGNORECASE)
            or re.search(r"\buser=([^\s,]+)", line, re.IGNORECASE)
            or re.search(r"\buser:\s*([^\s,]+)", line, re.IGNORECASE)
            or re.search(r"\bTargetUserName:\s*([^\s,]+)", line, re.IGNORECASE)
        )
        if user_match:
            username = user_match.group(1).strip('"\'')

        # Check for invalid user hints
        if "unknown user" in lowered or "user name does not exist" in lowered:
            is_invalid_user = True
            failure_reason = "Unknown user name"

        # Extract specific failure reason if present
        reason_match = re.search(r"\breason=([^\s,]+)", line, re.IGNORECASE)
        if reason_match:
            failure_reason = reason_match.group(1).replace("_", " ")

        # Extract workstation / host
        hostname = ""
        host_match = re.search(r"\bWorkstation(?:\s*Name)?:\s*([^\s,]+)", line, re.IGNORECASE)
        if host_match:
            hostname = host_match.group(1)

        return AuthEvent(
            event_id=event_id,
            timestamp=timestamp,
            service=service,
            ip=ip,
            username=username,
            status=status,
            raw_line=line,
            failure_reason=failure_reason,
            hostname=hostname,
            is_invalid_user=is_invalid_user,
        )
