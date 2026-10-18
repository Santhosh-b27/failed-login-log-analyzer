"""
Parser for Structured Cloud Audit & Modern JSON Authentication Logs.
"""

import json
from datetime import datetime
from typing import Optional
from .base import BaseLogParser
from ..core.models import AuthEvent


class JSONAuditParser(BaseLogParser):
    """Parses JSON-structured authentication events (e.g. AWS CloudTrail, Okta, Auth0)."""

    name = "JSONAuditParser"
    service_name = "CLOUD_AUDIT"

    def can_parse(self, line: str) -> bool:
        trimmed = line.strip()
        return trimmed.startswith("{") and trimmed.endswith("}")

    def parse(self, line: str, event_id: str) -> Optional[AuthEvent]:
        try:
            data = json.loads(line)
        except Exception:
            return None

        # Extract timestamp
        raw_ts = data.get("timestamp") or data.get("eventTime") or data.get("time") or data.get("@timestamp")
        timestamp = self.to_naive_utc(datetime.now())
        if raw_ts:
            try:
                dt = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
                timestamp = self.to_naive_utc(dt)
            except ValueError:
                pass

        # Extract IP
        ip = (
            data.get("sourceIPAddress")
            or data.get("ip")
            or data.get("client_ip")
            or (data.get("client", {}).get("ipAddress") if isinstance(data.get("client"), dict) else None)
            or self.extract_ip(line)
        )

        # Extract Username
        user_identity = data.get("userIdentity")
        if isinstance(user_identity, dict):
            username = user_identity.get("userName") or user_identity.get("principalId") or "unknown"
        else:
            actor = data.get("actor")
            if isinstance(actor, dict):
                username = actor.get("alternateId") or actor.get("displayName") or "unknown"
            else:
                username = data.get("username") or data.get("user") or data.get("user_id") or "unknown"

        # Determine Status
        status = "UNKNOWN"
        failure_reason = ""
        response = data.get("responseElements")
        outcome = data.get("outcome")

        if isinstance(response, dict) and response.get("ConsoleLogin") == "Failure":
            status = "FAILED"
            failure_reason = data.get("errorMessage", "Cloud ConsoleLogin Failed")
        elif isinstance(outcome, dict) and outcome.get("result") in ("FAILURE", "DENIED"):
            status = "FAILED"
            failure_reason = outcome.get("reason", "Auth outcome failed")
        elif data.get("status") in ("FAILED", "FAILURE", "failed", 401, 403):
            status = "FAILED"
            failure_reason = data.get("reason", "Failed status code")
        elif (
            (isinstance(response, dict) and response.get("ConsoleLogin") == "Success")
            or (isinstance(outcome, dict) and outcome.get("result") == "SUCCESS")
            or data.get("status") in ("SUCCESS", "success", 200)
        ):
            status = "SUCCESS"

        service = data.get("eventName") or data.get("service") or self.service_name

        return AuthEvent(
            event_id=event_id,
            timestamp=timestamp,
            service=str(service),
            ip=str(ip),
            username=str(username),
            status=status,
            raw_line=line,
            failure_reason=failure_reason,
            port=data.get("port"),
            is_invalid_user=bool(data.get("invalid_user", False)),
        )
