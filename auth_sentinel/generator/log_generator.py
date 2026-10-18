"""
Synthetic Attack Scenario & Enterprise Log Generator for AuthSentinel.
"""

import random
from datetime import datetime, timedelta
from typing import List


class LogGenerator:
    """Generates realistic cybersecurity attack logs and benchmark datasets."""

    LEGIT_USERS = ["john", "alice", "bob", "carol", "david", "emma", "dev_team", "ops_eng"]
    PRIVILEGED_USERS = ["root", "admin", "administrator", "sa", "postgres"]

    @classmethod
    def generate_ssh_bruteforce(cls, base_time: datetime, attacker_ip: str = "203.0.113.10", count: int = 12) -> List[str]:
        """Simulate vertical SSH brute force against root/admin."""
        logs = []
        target_user = "root"
        for i in range(count):
            t = base_time + timedelta(seconds=i * 6)
            ts_str = t.strftime("%Y-%m-%dT%H:%M:%SZ")
            port = random.randint(49152, 65535)
            line = f"{ts_str} host-core sshd[4190]: Failed password for {target_user} from {attacker_ip} port {port} ssh2"
            logs.append(line)
        return logs

    @classmethod
    def generate_password_spray(cls, base_time: datetime, attacker_ip: str = "198.51.100.45") -> List[str]:
        """Simulate horizontal password spraying across multiple user accounts."""
        logs = []
        spray_targets = ["alice", "bob", "charlie", "david", "finance", "hr_manager", "helpdesk", "sarah"]
        for i, user in enumerate(spray_targets):
            t = base_time + timedelta(seconds=i * 15)
            ts_str = t.strftime("%Y-%m-%dT%H:%M:%SZ")
            port = random.randint(50000, 60000)
            line = f"{ts_str} bastion-01 sshd[5521]: Failed password for {user} from {attacker_ip} port {port} ssh2"
            logs.append(line)
        return logs

    @classmethod
    def generate_impossible_travel(cls, base_time: datetime, username: str = "victor") -> List[str]:
        """Simulate impossible travel anomaly (New York -> Frankfurt in 10 minutes)."""
        logs = []
        # Event 1: New York (US)
        t1 = base_time
        line1 = f'{t1.strftime("%Y-%m-%dT%H:%M:%SZ")} webapp nginx: POST /login status=200 ip=45.33.32.156 username={username} message="Login successful"'
        logs.append(line1)

        # Event 2: Frankfurt (Germany - Tor / Host) 10 minutes later (speed > 30,000 km/h)
        t2 = base_time + timedelta(minutes=10)
        line2 = f'{t2.strftime("%Y-%m-%dT%H:%M:%SZ")} webapp nginx: POST /login status=401 ip=185.220.101.5 username={username} message="Invalid credentials"'
        logs.append(line2)

        return logs

    @classmethod
    def generate_compromise_scenario(cls, base_time: datetime, attacker_ip: str = "192.0.2.77") -> List[str]:
        """Simulate multiple failures followed by a successful authentication."""
        logs = []
        target = "administrator"
        # 4 failed attempts
        for i in range(4):
            t = base_time + timedelta(seconds=i * 20)
            logs.append(
                f"{t.strftime('%Y-%m-%d %H:%M:%S')} Microsoft-Windows-Security-Auditing 4625 Logon Failure: Account: {target}, Workstation: DC01, Source IP: {attacker_ip}, Logon Type: 10, Failure Reason: %%2313"
            )

        # Successful breach
        t_success = base_time + timedelta(seconds=95)
        logs.append(
            f"{t_success.strftime('%Y-%m-%d %H:%M:%S')} Microsoft-Windows-Security-Auditing 4624 Successful Logon: Account: {target}, Workstation: DC01, Source IP: {attacker_ip}, Logon Type: 10"
        )
        return logs

    @classmethod
    def generate_scenario(cls, scenario: str, base_time: datetime = None) -> List[str]:
        """Generate a complete log dataset by scenario name."""
        base = base_time or datetime(2026, 10, 18, 10, 0, 0)
        scenario = scenario.lower()

        if scenario == "bruteforce":
            return cls.generate_ssh_bruteforce(base)
        elif scenario == "spray":
            return cls.generate_password_spray(base)
        elif scenario == "travel":
            return cls.generate_impossible_travel(base)
        elif scenario == "compromise":
            return cls.generate_compromise_scenario(base)
        elif scenario == "mixed":
            all_logs = []
            # Legitimate traffic
            all_logs.append(f'{base.strftime("%Y-%m-%dT%H:%M:%SZ")} auth-gw sshd[100]: Accepted password for alice from 192.168.1.100 port 52341 ssh2')
            all_logs.append(f'{(base + timedelta(seconds=12)).strftime("%Y-%m-%dT%H:%M:%SZ")} ftp-server vsftpd[200]: OK LOGIN: Client "192.168.1.105", user "backup"')
            all_logs.append(f'{(base + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")} webapp nginx: POST /login status=200 ip=192.168.1.110 username=bob message="Login successful"')

            # Attack 1: SSH Brute Force
            all_logs.extend(cls.generate_ssh_bruteforce(base + timedelta(minutes=5), attacker_ip="203.0.113.10", count=8))

            # Attack 2: Password Spraying
            all_logs.extend(cls.generate_password_spray(base + timedelta(minutes=15), attacker_ip="198.51.100.45"))

            # Attack 3: Impossible Travel
            all_logs.extend(cls.generate_impossible_travel(base + timedelta(minutes=30), username="victor"))

            # Attack 4: Confirmed Compromise on RDP
            all_logs.extend(cls.generate_compromise_scenario(base + timedelta(minutes=45), attacker_ip="192.0.2.77"))

            # Interleaved Legitimate logs
            all_logs.append(f'{(base + timedelta(minutes=50)).strftime("%Y-%m-%dT%H:%M:%SZ")} auth-gw sshd[100]: Accepted publickey for dev_team from 10.0.0.50 port 51111 ssh2')

            # Sort all logs chronologically
            return all_logs
        else:
            return cls.generate_ssh_bruteforce(base)
