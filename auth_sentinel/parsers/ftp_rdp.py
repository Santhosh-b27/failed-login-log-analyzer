"""
Parser for FTP daemons (vsftpd, proftpd, pure-ftpd).
"""

import re
from typing import Optional
from .base import BaseLogParser
from ..core.models import AuthEvent


class FTPLogParser(BaseLogParser):
    """Parses FTP daemon logs (vsftpd, proftpd)."""

    name = "FTPLogParser"
    service_name = "FTP"

    def can_parse(self, line: str) -> bool:
        lowered = line.lower()
        return "vsftpd" in lowered or "proftpd" in lowered or "pure-ftpd" in lowered or "ftp" in lowered

    def parse(self, line: str, event_id: str) -> Optional[AuthEvent]:
        timestamp = self.extract_timestamp(line)
        ip = self.extract_ip(line)
        lowered = line.lower()
        status = "UNKNOWN"
        failure_reason = ""

        if "fail login" in lowered or "login failed" in lowered or "failed" in lowered:
            status = "FAILED"
            failure_reason = "FTP authentication failure"
        elif "ok login" in lowered or "login successful" in lowered or "logged in" in lowered:
            status = "SUCCESS"

        # Extract Username
        username = "unknown"
        user_match = (
            re.search(r'user\s+"([^"]+)"', line, re.IGNORECASE)
            or re.search(r'user=([^\s,]+)', line, re.IGNORECASE)
            or re.search(r'\[([^\]]+)\]\s+FAIL LOGIN', line, re.IGNORECASE)
        )
        if user_match:
            username = user_match.group(1)

        return AuthEvent(
            event_id=event_id,
            timestamp=timestamp,
            service=self.service_name,
            ip=ip,
            username=username,
            status=status,
            raw_line=line,
            failure_reason=failure_reason,
            port=21,
            is_invalid_user=False,
        )
