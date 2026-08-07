"""
Ingestor for crontab files and scheduled tasks.
"""

from __future__ import annotations

import re
from pathlib import Path

from vigil.ingestors.base import BaseIngestor
from vigil.models import LogEntry, LogType


class CrontabParser(BaseIngestor):
    """
    Ingestor for Linux crontab configurations.

    Parses active schedules, executing commands, and running users.
    Generates LogEntry objects representing the configuration state.
    """

    # Matches standard cron configuration lines:
    # * * * * * username command
    # Or system crontab lines:
    # * * * * * command (without username, defaults to running environment user)
    # Also handles special values like @reboot, @daily, etc.
    CRON_LINE_PATTERN = re.compile(
        r"^(?:"
        r"(@reboot|@yearly|@annually|@monthly|@weekly|@daily|@midnight|@hourly)|"  # Special keywords
        r"((?:[0-9*,/\-]+)\s+(?:[0-9*,/\-]+)\s+(?:[0-9*,/\-]+)\s+(?:[0-9*,/\-]+)\s+(?:[0-9*,/\-]+))"  # Standard 5-field schedule
        r")\s+(.*)$"
    )

    def can_ingest(self, filepath: Path) -> bool:
        # Check by common name/extensions
        name = filepath.name.lower()
        if "cron" in name or name == "crontab":
            return True
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                head = [f.readline() for _ in range(15)]
            return self.detect_format(head)
        except Exception:
            return False

    def detect_format(self, sample_lines: list[str]) -> bool:
        # Check for environment assignments (SHELL, PATH, MAILTO) or cron lines
        env_count = 0
        cron_count = 0
        for line in sample_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line and any(var in line for var in ("SHELL", "PATH", "MAILTO", "HOME")):
                env_count += 1
            elif self.CRON_LINE_PATTERN.match(line):
                cron_count += 1

        return env_count >= 1 or cron_count >= 1

    def ingest(self, filepath: Path) -> list[LogEntry]:
        entries: list[LogEntry] = []
        source_name = filepath.name

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Skip environment variable definitions for analysis
                if "=" in line and any(var in line.split("=")[0].strip() for var in ("SHELL", "PATH", "MAILTO", "HOME")):
                    continue

                entry = self._parse_line(line, idx, source_name)
                if entry:
                    entries.append(entry)

        return entries

    def _parse_line(self, line: str, line_num: int, source_file: str) -> LogEntry | None:
        match = self.CRON_LINE_PATTERN.match(line)
        if not match:
            return None

        special, schedule, command_block = match.groups()
        final_schedule = special or schedule
        command_block = command_block.strip()

        # Handle system-wide cron vs user-specific cron
        # System crontabs contain a username field before the command
        # Let's extract the username if it looks like one
        tokens = command_block.split(None, 1)
        if len(tokens) == 2 and self._is_username(tokens[0]):
            username = tokens[0]
            command = tokens[1]
        else:
            username = "root"  # Default fallback if unspecified (user crons run as the owner, which is usually root/admin)
            command = command_block

        metadata = {
            "schedule": final_schedule,
            "command": command,
            "user": username,
        }

        raw_summary = f"Cron | Schedule: {final_schedule} | User: {username} | Command: {command}"

        return LogEntry(
            timestamp=None, # Cron configuration events don't have a dynamic execution timestamp
            username=username,
            action="cron_scheduled",
            raw_line=raw_summary,
            line_number=line_num,
            source_file=source_file,
            log_type=LogType.CRONTAB,
            metadata=metadata,
        )

    def _is_username(self, token: str) -> bool:
        # A simple check: username token must start with a letter/underscore and contain letters, digits, dashes, underscores
        # Also avoid matching standard command binaries or paths (e.g. /usr/bin/python)
        if "/" in token or "\\" in token or token.startswith("-"):
            return False
        return bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_\-]*$", token))
