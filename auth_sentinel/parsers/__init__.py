"""
Log parsers module for AuthSentinel.
"""

from .base import BaseLogParser
from .linux_ssh import LinuxSSHParser
from .windows import WindowsEventParser
from .web_nginx import WebAuthParser
from .ftp_rdp import FTPLogParser
from .json_audit import JSONAuditParser
from .auto_detector import LogParserDispatcher, FallbackGenericParser

__all__ = [
    "BaseLogParser",
    "LinuxSSHParser",
    "WindowsEventParser",
    "WebAuthParser",
    "FTPLogParser",
    "JSONAuditParser",
    "LogParserDispatcher",
    "FallbackGenericParser",
]
