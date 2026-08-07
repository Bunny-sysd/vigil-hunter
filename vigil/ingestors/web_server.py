"""
Ingestor for Web Server access and error logs (Apache / nginx).
"""

from __future__ import annotations

import re
import urllib.parse
from datetime import datetime
from pathlib import Path

from dateutil import parser as date_parser

from vigil.ingestors.base import BaseIngestor
from vigil.models import LogEntry, LogType


class WebServerLogIngestor(BaseIngestor):
    """
    Ingestor for web server logs.

    Supports Common/Combined Log Format for access logs,
    and standard error log format for error logs.
    """

    # Combined Log Format: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/referer.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
    ACCESS_PATTERN = re.compile(
        r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+([^\s?]+)(?:\?(\S+))?\s+([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?'
    )

    # Basic Apache Error format: [Mon Oct 10 13:55:36.123456 2000] [module:level] [pid 1234] [client 127.0.0.1:42156] Message...
    ERROR_PATTERN = re.compile(
        r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+(?:\[pid\s+(\d+)\]\s+)?(?:\[client\s+([^\s:]+)(?::\d+)?\]\s+)?(.*)"
    )

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
        access_matches = sum(1 for line in sample_lines if self.ACCESS_PATTERN.match(line))
        error_matches = sum(1 for line in sample_lines if self.ERROR_PATTERN.match(line))
        return access_matches >= 3 or error_matches >= 3

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
        # Try access log match first
        access_match = self.ACCESS_PATTERN.match(line)
        if access_match:
            return self._parse_access_line(access_match, line, line_num, source_file)

        # Try error log match next
        error_match = self.ERROR_PATTERN.match(line)
        if error_match:
            return self._parse_error_line(error_match, line, line_num, source_file)

        return None

    def _parse_access_line(self, match: re.Match, raw_line: str, line_num: int, source_file: str) -> LogEntry:
        (
            ip,
            _,  # identd
            user,
            ts_str,
            method,
            path,
            query,
            protocol,
            status,
            size,
            referer,
            user_agent,
        ) = match.groups()

        timestamp = self._parse_timestamp(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        username = user if user != "-" else None
        query_str = query or ""
        decoded_path = urllib.parse.unquote(path)

        metadata = {
            "method": method,
            "path": decoded_path,
            "query": query_str,
            "protocol": protocol,
            "status": int(status),
            "size": int(size) if size.isdigit() else 0,
            "referer": referer if referer != "-" else "",
            "user_agent": user_agent or "",
        }

        return LogEntry(
            timestamp=timestamp,
            source_ip=ip,
            username=username,
            action=f"http_{method.lower()}",
            raw_line=raw_line,
            line_number=line_num,
            source_file=source_file,
            log_type=LogType.WEB_ACCESS,
            metadata=metadata,
        )

    def _parse_error_line(self, match: re.Match, raw_line: str, line_num: int, source_file: str) -> LogEntry:
        ts_str, module_level, pid, client_ip, message = match.groups()
        
        timestamp = self._parse_timestamp(ts_str, None)
        
        metadata = {
            "module_level": module_level,
            "pid": int(pid) if pid else None,
            "message": message,
        }

        return LogEntry(
            timestamp=timestamp,
            source_ip=client_ip if client_ip != "-" else None,
            action="web_error",
            raw_line=raw_line,
            line_number=line_num,
            source_file=source_file,
            log_type=LogType.WEB_ERROR,
            metadata=metadata,
        )

    def _parse_timestamp(self, ts_str: str, fmt: str | None) -> float | None:
        try:
            if fmt:
                # Direct format match (e.g. 10/Oct/2000:13:55:36 -0700)
                # Parse manually or with dateutil
                dt = datetime.strptime(ts_str.split()[0], fmt.split()[0])
                if " " in ts_str: # Has timezone offset
                    dt = date_parser.parse(ts_str.replace(":", " ", 1)) # standard replacement for dateutil
            else:
                dt = date_parser.parse(ts_str)
            return dt.timestamp()
        except Exception:
            try:
                # Try generic parser fallback
                return date_parser.parse(ts_str).timestamp()
            except Exception:
                return None
