"""
MITRE ATT&CK mapping, SOC triage playbooks, and Sigma detection rules.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from ..core.models import AttackType, SeverityLevel


@dataclass
class MitreTechniqueInfo:
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    soc_playbook: List[str]
    sigma_rule_summary: str


MITRE_TACTIC_DATABASE: Dict[AttackType, MitreTechniqueInfo] = {
    AttackType.BRUTE_FORCE: MitreTechniqueInfo(
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        tactic="Credential Access",
        description=(
            "Adversaries systematically guess passwords for a specific account "
            "to acquire valid credentials without prior account knowledge."
        ),
        soc_playbook=[
            "1. Containment: Temporarily null-route or block attacker IP on border firewall/WAF.",
            "2. Account Verification: Check whether any attempt was followed by an 'Accepted' or '200 OK' log.",
            "3. Hardening: Verify fail2ban or SSH rate-limiting policies are enforced.",
            "4. Identity: If targeted account is privileged, ensure MFA is strictly required.",
        ],
        sigma_rule_summary="title: Potential SSH/RDP Password Guessing\nstatus: production\ncondition: count(event_id) > 5 by source_ip, username within 2m",
    ),
    AttackType.PASSWORD_SPRAY: MitreTechniqueInfo(
        technique_id="T1110.003",
        technique_name="Brute Force: Password Spraying",
        tactic="Credential Access",
        description=(
            "Adversaries use a small list of commonly used passwords against many different accounts "
            "to circumvent account lockout policies."
        ),
        soc_playbook=[
            "1. Priority Triage: Inspect whether common passwords (e.g. Summer2026!, Welcome123) are in use.",
            "2. Perimeter Defense: Block source IP or ASN at the perimeter and CASB/IdP level.",
            "3. Investigation: Review Okta/Azure AD sign-in logs to identify if spray affected other cloud endpoints.",
            "4. Remediation: Prompt global password change for targeted accounts if any successful login was noted.",
        ],
        sigma_rule_summary="title: Password Spraying Across Multiple Accounts\nstatus: production\ncondition: count(distinct username) >= 4 by source_ip within 5m",
    ),
    AttackType.ACCOUNT_ENUMERATION: MitreTechniqueInfo(
        technique_id="T1087.002",
        technique_name="Account Discovery: Domain/Local Account",
        tactic="Discovery",
        description=(
            "Adversaries attempt to discover legitimate account names on a system by observing "
            "different error responses (e.g. 'Invalid user' vs 'Invalid password')."
        ),
        soc_playbook=[
            "1. Triage: Check if attacker is iterating through dictionary or employee names.",
            "2. Defense: Ensure generic authentication failure messages are enabled (prevent user enumeration).",
            "3. Monitor: Flag source IP for heightened monitoring across API gateways.",
        ],
        sigma_rule_summary="title: Systematic Account Enumeration Probing\nstatus: production\ncondition: count(invalid_user) >= 3 by source_ip within 3m",
    ),
    AttackType.IMPOSSIBLE_TRAVEL: MitreTechniqueInfo(
        technique_id="T1078",
        technique_name="Valid Accounts: Cloud / Remote Infrastructure",
        tactic="Defense Evasion / Initial Access",
        description=(
            "A single user account was accessed or attempted from two distant geographic locations "
            "within a time window that physically precludes commercial flight travel."
        ),
        soc_playbook=[
            "1. Critical Triage: Contact user directly through an out-of-band communication channel (Slack/phone).",
            "2. Session Invalidation: Immediately revoke all active refresh tokens and OAuth sessions for the account.",
            "3. Investigation: Verify if user was utilizing a corporate VPN with split-tunneling.",
            "4. Reset: Force immediate password reset and MFA re-registration if travel was not legitimate.",
        ],
        sigma_rule_summary="title: Impossible Travel Anomaly Across Geographies\nstatus: experimental\ncondition: distance(geo1, geo2) / time_delta > 800km/h",
    ),
    AttackType.BREACH_CONFIRMED: MitreTechniqueInfo(
        technique_id="T1078.003",
        technique_name="Valid Accounts: Compromise After Attack",
        tactic="Initial Access & Persistence",
        description=(
            "CRITICAL INCIDENT: An attacker IP executed multiple failed authentication attempts "
            "and subsequently achieved a SUCCESSFUL login. High probability of credential compromise!"
        ),
        soc_playbook=[
            "1. P1 EMERGENCY: Immediately isolate the affected host and revoke the compromised account credentials.",
            "2. Threat Hunting: Inspect bash history, Process Creation (Sysmon Event ID 1), and lateral movement.",
            "3. Evidence Collection: Dump memory and preserve volatile logs for digital forensics analysis.",
            "4. Escalation: Notify Lead Incident Commander and trigger SOC P1 Incident Response SLA.",
        ],
        sigma_rule_summary="title: Successful Authentication Followed By High Volume Failures\nstatus: critical\ncondition: (failed_count >= 3) FOLLOWED BY (status == SUCCESS) by source_ip within 10m",
    ),
}


def get_mitre_info(attack_type: AttackType) -> MitreTechniqueInfo:
    """Retrieve MITRE ATT&CK technique details and SOC playbook."""
    return MITRE_TACTIC_DATABASE.get(
        attack_type,
        MitreTechniqueInfo(
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            description="Adversaries employ brute force techniques to guess passwords.",
            soc_playbook=["1. Monitor attacker IP", "2. Check account status"],
            sigma_rule_summary="title: Generic Auth Attack",
        ),
    )
