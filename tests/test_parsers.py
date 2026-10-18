"""
Unit tests for AuthSentinel log parsers.
"""

import unittest
from auth_sentinel.parsers.linux_ssh import LinuxSSHParser
from auth_sentinel.parsers.windows import WindowsEventParser
from auth_sentinel.parsers.web_nginx import WebAuthParser
from auth_sentinel.parsers.ftp_rdp import FTPLogParser
from auth_sentinel.parsers.json_audit import JSONAuditParser
from auth_sentinel.parsers.auto_detector import LogParserDispatcher


class TestLogParsers(unittest.TestCase):
    def test_linux_ssh_parser(self):
        parser = LinuxSSHParser()
        line = "2026-03-17T08:12:33Z host1 sshd[2145]: Failed password for invalid user admin from 203.0.113.10 port 51234 ssh2"
        self.assertTrue(parser.can_parse(line))
        event = parser.parse(line, "EVT-001")
        self.assertIsNotNone(event)
        self.assertEqual(event.status, "FAILED")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.ip, "203.0.113.10")
        self.assertEqual(event.port, 51234)
        self.assertTrue(event.is_invalid_user)

    def test_linux_ssh_accepted(self):
        parser = LinuxSSHParser()
        line = "2026-03-17T08:13:15Z host1 sshd[2145]: Accepted password for analyst from 203.0.113.55 port 52222 ssh2"
        event = parser.parse(line, "EVT-002")
        self.assertIsNotNone(event)
        self.assertEqual(event.status, "SUCCESS")
        self.assertEqual(event.username, "analyst")
        self.assertEqual(event.ip, "203.0.113.55")

    def test_windows_parser(self):
        parser = WindowsEventParser()
        line = "2026-03-17 08:31:07 Microsoft-Windows-Security-Auditing 4625 Logon Failure: Account: administrator, Workstation: DC01, Source IP: 192.0.2.44, Logon Type: 10, Failure Reason: %%2313"
        self.assertTrue(parser.can_parse(line))
        event = parser.parse(line, "EVT-003")
        self.assertIsNotNone(event)
        self.assertEqual(event.status, "FAILED")
        self.assertEqual(event.username, "administrator")
        self.assertEqual(event.ip, "192.0.2.44")

    def test_web_nginx_parser(self):
        parser = WebAuthParser()
        line = '2026-03-17T08:45:02Z webapp nginx: POST /login status=401 ip=203.0.113.77 username=alice message="Invalid credentials"'
        self.assertTrue(parser.can_parse(line))
        event = parser.parse(line, "EVT-004")
        self.assertIsNotNone(event)
        self.assertEqual(event.status, "FAILED")
        self.assertEqual(event.username, "alice")
        self.assertEqual(event.ip, "203.0.113.77")

    def test_ftp_parser(self):
        parser = FTPLogParser()
        line = '2026-03-17T08:20:01Z ftp-server vsftpd[998]: FAIL LOGIN: Client "198.51.100.23", user "ftpadmin"'
        self.assertTrue(parser.can_parse(line))
        event = parser.parse(line, "EVT-005")
        self.assertIsNotNone(event)
        self.assertEqual(event.status, "FAILED")
        self.assertEqual(event.username, "ftpadmin")
        self.assertEqual(event.ip, "198.51.100.23")

    def test_json_audit_parser(self):
        parser = JSONAuditParser()
        line = '{"timestamp": "2026-03-17T09:10:00Z", "eventName": "ConsoleLogin", "sourceIPAddress": "198.51.100.5", "userIdentity": {"userName": "cloud-admin"}, "responseElements": {"ConsoleLogin": "Failure"}}'
        self.assertTrue(parser.can_parse(line))
        event = parser.parse(line, "EVT-006")
        self.assertIsNotNone(event)
        self.assertEqual(event.status, "FAILED")
        self.assertEqual(event.username, "cloud-admin")
        self.assertEqual(event.ip, "198.51.100.5")

    def test_dispatcher_auto_detection(self):
        dispatcher = LogParserDispatcher()
        line = "2026-03-17T08:12:33Z host1 sshd[2145]: Failed password for root from 203.0.113.10 port 51235 ssh2"
        event = dispatcher.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.username, "root")
        self.assertEqual(event.ip, "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
