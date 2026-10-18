"""
Parser for Linux authentication logs (OpenSSH, PAM, and Syslog auth.log).
"""

import re
from typing import Optional
from .base import BaseLogParser
from ..core.models import AuthEvent


class LinuxSSHParser(BaseLogParser):
    """Parses OpenSSH and PAM authentication lines."""

    name = "LinuxSSHParser"
    service_name = "SSH"

    # Match patterns
    SSH_FAILED_INVALID = re.compile(
        r"sshd\[\d+\]:\s+Failed\s+password\s+for\s+invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE,
    )
    SSH_FAILED = re.compile(
        r"sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE,
    )
    SSH_ACCEPTED = re.compile(
        r"sshd\[\d+\]:\s+Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE,
    )
    PAM_AUTH_FAIL = re.compile(
        r"pam_unix\([^)]+\):\s+authentication\s+failure;.*?\s+user=(?P<user>\S+).*?(?:rhost=(?P<ip>\S+))?",
        re.IGNORECASE,
    )
    PAM_AUTH_SUCCESS = re.compile(
        r"pam_unix\([^)]+\):\s+(?:session\s+opened|authentication\s+succeeded).*?\s+user=(?P<user>\S+).*?(?:rhost=(?P<ip>\S+))?",
        re.IGNORECASE,
    )

    def can_parse(self, line: str) -> bool:
        lowered = line.lower()
        return "sshd" in lowered or "pam_unix" in lowered or ("ssh" in lowered and ("failed" in lowered or "accepted" in lowered))

    def parse(self, line: str, event_id: str) -> Optional[AuthEvent]:
        timestamp = self.extract_timestamp(line)
        status = "UNKNOWN"
        username = "unknown"
        ip = self.extract_ip(line)
        port = None
        is_invalid_user = False
        reason = ""

        # Check SSH Failed Invalid User
        match = self.SSH_FAILED_INVALID.search(line)
        if match:
            status = "FAILED"
            username = match.group("user")
            ip = match.group("ip") or ip
            port = int(match.group("port")) if match.group("port") else None
            is_invalid_user = True
            reason = "Invalid username or bad password"
            return AuthEvent(
                event_id=event_id,
                timestamp=timestamp,
                service=self.service_name,
                ip=ip,
                username=username,
                status=status,
                raw_line=line,
                failure_reason=reason,
                port=port,
                is_invalid_user=is_invalid_user,
            )

        # Check SSH Failed Valid User
        match = self.SSH_FAILED.search(line)
        if match:
            status = "FAILED"
            username = match.group("user")
            ip = match.group("ip") or ip
            port = int(match.group("port")) if match.group("port") else None
            reason = "Failed password"
            return AuthEvent(
                event_id=event_id,
                timestamp=timestamp,
                service=self.service_name,
                ip=ip,
                username=username,
                status=status,
                raw_line=line,
                failure_reason=reason,
                port=port,
                is_invalid_user=False,
            )

        # Check SSH Accepted
        match = self.SSH_ACCEPTED.search(line)
        if match:
            status = "SUCCESS"
            username = match.group("user")
            ip = match.group("ip") or ip
            port = int(match.group("port")) if match.group("port") else None
            return AuthEvent(
                event_id=event_id,
                timestamp=timestamp,
                service=self.service_name,
                ip=ip,
                username=username,
                status=status,
                raw_line=line,
                failure_reason="",
                port=port,
                is_invalid_user=False,
            )

        # Check PAM failure
        match = self.PAM_AUTH_FAIL.search(line)
        if match:
            status = "FAILED"
            username = match.group("user")
            extracted_rhost = match.group("ip")
            if extracted_rhost and extracted_rhost != "0.0.0.0":
                ip = extracted_rhost
            reason = "PAM authentication failure"
            return AuthEvent(
                event_id=event_id,
                timestamp=timestamp,
                service="PAM",
                ip=ip,
                username=username,
                status=status,
                raw_line=line,
                failure_reason=reason,
                port=port,
                is_invalid_user=False,
            )

        # Check PAM success
        match = self.PAM_AUTH_SUCCESS.search(line)
        if match:
            status = "SUCCESS"
            username = match.group("user")
            extracted_rhost = match.group("ip")
            if extracted_rhost and extracted_rhost != "0.0.0.0":
                ip = extracted_rhost
            return AuthEvent(
                event_id=event_id,
                timestamp=timestamp,
                service="PAM",
                ip=ip,
                username=username,
                status=status,
                raw_line=line,
                failure_reason="",
                port=port,
                is_invalid_user=False,
            )

        # Generic SSH line
        lowered = line.lower()
        if "failed" in lowered or "invalid" in lowered:
            status = "FAILED"
            reason = "Generic SSH authentication failure"
        elif "accepted" in lowered or "succeeded" in lowered:
            status = "SUCCESS"

        # Try to extract user
        user_match = re.search(r"\buser[ =]([a-zA-Z0-9._-]+)", line, re.IGNORECASE)
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
            failure_reason=reason,
            port=port,
            is_invalid_user=is_invalid_user,
        )
