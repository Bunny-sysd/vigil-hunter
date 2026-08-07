"""
Parser for Linux authentication logs (auth.log / secure).
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from pathlib import Path

from dateutil import parser as date_parser

from vigil.ingestors.base import BaseIngestor
from vigil.models import LogEntry, LogType


class AuthLogIngestor(BaseIngestor):
    """
    Ingestor for auth.log / secure.

    Handles failed/successful SSH logins, sudo commands, user additions,
    and privilege escalation attempt signs.
    """

    # Matches syslog timestamps at start of line
    # e.g. "Jul 18 03:42:17" or "2026-07-18T03:42:17.123456-04:00"
    TS_PATTERN = re.compile(
        r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|"  # Jul 18 03:42:17
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)"  # ISO-8601
    )

    # Patterns for key security events
    SSH_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (\d+) ssh2")
    SSH_SUCCESS = re.compile(r"Accepted password for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (\d+) ssh2")
    SSH_KEY_SUCCESS = re.compile(r"Accepted publickey for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (\d+) ssh2")
    SSH_INVALID = re.compile(r"Invalid user (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (\d+)")
    
    SUDO_CMD = re.compile(r"sudo:\s+(\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)")
    SU_CMD = re.compile(r"su:\s+session opened for user (\S+) by (\S+)")
    USER_ADD = re.compile(r"useradd\[\d+\]:\s+new user:\s+name=(\S+)")

    def can_ingest(self, filepath: Path) -> bool:
        if not filepath.is_file():
            return False
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                head = [f.readline() for _ in range(15)]
            return self.detect_format(head)
        except Exception:
            return False

    def detect_format(self, sample_lines: list[str]) -> bool:
        auth_triggers = ["sshd", "sudo", "PAM", "su:", "useradd", "groupadd"]
        matches = 0
        for line in sample_lines:
            if any(trigger in line for trigger in auth_triggers):
                matches += 1
        return matches >= 2

    def ingest(self, filepath: Path) -> list[LogEntry]:
        entries: list[LogEntry] = []
        source_name = filepath.name

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                entry = self._parse_line(line, idx, source_name)
                if entry:
                    entries.append(entry)

        return entries

    def _parse_line(self, line: str, line_num: int, source_file: str) -> LogEntry | None:
        # 1. Parse timestamp
        ts_match = self.TS_PATTERN.match(line)
        if not ts_match:
            return None

        ts_str = ts_match.group(1)
        timestamp = self._parse_timestamp(ts_str)

        # 2. Basic components
        log_entry = LogEntry(
            timestamp=timestamp,
            raw_line=line,
            line_number=line_num,
            source_file=source_file,
            log_type=LogType.AUTH_LOG,
        )

        # 3. Categorize and extract indicators
        # SSH Failures
        ssh_fail = self.SSH_FAILED.search(line)
        if ssh_fail:
            username, ip, port = ssh_fail.groups()
            log_entry.username = username
            log_entry.source_ip = ip
            log_entry.action = "ssh_login_failed"
            log_entry.metadata = {"service": "sshd", "port": int(port), "method": "password"}
            return log_entry

        ssh_invalid = self.SSH_INVALID.search(line)
        if ssh_invalid:
            username, ip, port = ssh_invalid.groups()
            log_entry.username = username
            log_entry.source_ip = ip
            log_entry.action = "ssh_login_failed"
            log_entry.metadata = {"service": "sshd", "port": int(port), "method": "invalid_user"}
            return log_entry

        # SSH Success (Password)
        ssh_success = self.SSH_SUCCESS.search(line)
        if ssh_success:
            username, ip, port = ssh_success.groups()
            log_entry.username = username
            log_entry.source_ip = ip
            log_entry.action = "ssh_login_success"
            log_entry.metadata = {"service": "sshd", "port": int(port), "method": "password"}
            return log_entry

        # SSH Success (Public Key)
        ssh_key_success = self.SSH_KEY_SUCCESS.search(line)
        if ssh_key_success:
            username, ip, port = ssh_key_success.groups()
            log_entry.username = username
            log_entry.source_ip = ip
            log_entry.action = "ssh_login_success"
            log_entry.metadata = {"service": "sshd", "port": int(port), "method": "publickey"}
            return log_entry

        # Sudo Commands
        sudo_match = self.SUDO_CMD.search(line)
        if sudo_match:
            invoker, target_user, command = sudo_match.groups()
            log_entry.username = invoker
            log_entry.action = "sudo_command"
            log_entry.metadata = {"target_user": target_user, "command": command.strip()}
            return log_entry

        # SU session shifts
        su_match = self.SU_CMD.search(line)
        if su_match:
            target_user, invoker = su_match.groups()
            log_entry.username = invoker
            log_entry.action = "su_session"
            log_entry.metadata = {"target_user": target_user}
            return log_entry

        # User additions
        user_add = self.USER_ADD.search(line)
        if user_add:
            new_user = user_add.group(1)
            log_entry.username = new_user
            log_entry.action = "user_created"
            return log_entry

        # Return general entry if it contains syslog identifiers but wasn't classified
        return log_entry

    def _parse_timestamp(self, ts_str: str) -> float | None:
        try:
            # Check if it has no year (e.g. Jul 18 03:42:17)
            # Default to current year
            dt = date_parser.parse(ts_str)
            if dt.year == datetime.now().year and ts_str.strip().startswith(tuple(datetime.now().strftime("%b"))):
                # Ensure correct parsing
                pass
            return dt.timestamp()
        except Exception:
            return time.time()  # Fallback
