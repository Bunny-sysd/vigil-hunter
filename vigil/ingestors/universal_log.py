"""
Universal Log Ingestor ("Feed Me Anything").

Parses unstructured, unrecognized, or mixed log formats using pattern density scoring
and fallback regex extractions. Ensures Vigil can process ANY raw log file.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from vigil.ingestors.base import BaseIngestor
from vigil.models import LogEntry, LogType

# Extraction regexes for universal log elements
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
USER_PATTERN = re.compile(r"\b(?:user|username|account|for|user=)\s*[:=]?\s*['\"]?([a-zA-Z0-9_\-\.]+)", re.IGNORECASE)
ACTION_PATTERN = re.compile(r"\b(failed|accepted|denied|authenticated|connected|disconnected|executed|created|deleted)\b", re.IGNORECASE)
LOG_LEVEL_PATTERN = re.compile(r"\b(error|warning|critical|info|debug)\b", re.IGNORECASE)
TIMESTAMP_PATTERN = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?|\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")


class UniversalLogIngestor(BaseIngestor):
    """
    Fallback ingestor that parses any plain text file into structured LogEntry objects.
    """

    def can_ingest(self, filepath: Path) -> bool:
        """Universal ingestor can ingest any text file as a last resort."""
        if not filepath.is_file():
            return False
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                sample = f.read(1024)
                return "\0" not in sample
        except Exception:
            return False

    def detect_format(self, filepath: Path) -> LogType:
        return LogType.UNKNOWN

    def ingest(self, filepath: Path) -> list[LogEntry]:
        """Parse raw text line by line using fallback pattern matching."""
        entries: list[LogEntry] = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        for idx, line in enumerate(lines, 1):
            line_str = line.strip()
            if not line_str:
                continue

            # Extract IP addresses
            ip_matches = IP_PATTERN.findall(line_str)
            src_ip = ip_matches[0] if ip_matches else None
            dst_ip = ip_matches[1] if len(ip_matches) > 1 else None

            # Extract Username
            user_match = USER_PATTERN.search(line_str)
            username = user_match.group(1) if user_match else None

            # Extract Action (prefer security actions, then log levels)
            action_match = ACTION_PATTERN.search(line_str)
            if action_match:
                action = action_match.group(1).lower()
            else:
                lvl_match = LOG_LEVEL_PATTERN.search(line_str)
                action = lvl_match.group(1).lower() if lvl_match else "event"

            # Extract Metadata indicators
            metadata: dict[str, Any] = {}
            if "error" in line_str.lower():
                metadata["level"] = "ERROR"
            elif "warning" in line_str.lower():
                metadata["level"] = "WARN"

            entry = LogEntry(
                timestamp=time.time(),
                source_ip=src_ip,
                dest_ip=dst_ip,
                username=username,
                action=action,
                raw_line=line_str,
                line_number=idx,
                source_file=filepath.name,
                log_type=LogType.UNKNOWN,
                metadata=metadata,
            )
            entries.append(entry)

        return entries
