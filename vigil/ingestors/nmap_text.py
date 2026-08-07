"""
Ingestor for Standard Nmap Plain Text Output Files (nmap -sV output).

Parses plain text Nmap terminal output reports:
    - 'Nmap scan report for <IP/Host>'
    - 'PORT STATE SERVICE VERSION' table rows
    - Product and version string extractions
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from vigil.ingestors.base import BaseIngestor
from vigil.models import LogEntry, LogType


class NmapTextIngestor(BaseIngestor):
    """
    Parses plain text Nmap scan reports (terminal output / redirect files).
    """

    HOST_REPORT_PATTERN = re.compile(r"Nmap scan report for\s+(?:([^\s()]+)\s+\(([^()]+)\)|(\S+))", re.IGNORECASE)
    PORT_LINE_PATTERN = re.compile(r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?$", re.IGNORECASE)

    def can_ingest(self, filepath: Path) -> bool:
        if not filepath.is_file():
            return False
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                sample = f.read(2048)
                return "Nmap scan report for" in sample or ("PORT" in sample and "SERVICE" in sample and "VERSION" in sample)
        except Exception:
            return False

    def detect_format(self, filepath: Path) -> LogType:
        return LogType.NMAP_XML

    def ingest(self, filepath: Path) -> list[LogEntry]:
        entries: list[LogEntry] = []
        source_name = filepath.name

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        current_host = ""
        current_hostname = ""

        for idx, line in enumerate(lines, 1):
            line_str = line.strip()
            if not line_str:
                continue

            # 1. Match Host Header line (e.g. Nmap scan report for 10.0.0.1 or target.local (10.0.0.1))
            host_match = self.HOST_REPORT_PATTERN.search(line_str)
            if host_match:
                if host_match.group(3):
                    current_host = host_match.group(3)
                    current_hostname = current_host
                elif host_match.group(2):
                    current_hostname = host_match.group(1)
                    current_host = host_match.group(2)
                continue

            # 2. Match Port Line (e.g. 53/tcp open domain dnsmasq 2.83)
            port_match = self.PORT_LINE_PATTERN.match(line_str)
            if port_match:
                port = int(port_match.group(1))
                protocol = port_match.group(2).lower()
                state = port_match.group(3).lower()
                service = port_match.group(4)
                version_raw = port_match.group(5) or ""

                if state != "open":
                    continue  # Only ingest open ports for vulnerability hunting

                # Separate product and version if possible
                product = service
                version = version_raw

                # Clean up version string
                if version_raw:
                    parts = version_raw.split(maxsplit=1)
                    if len(parts) == 2:
                        product = parts[0]
                        version = parts[1]
                    else:
                        version = parts[0]

                entry = LogEntry(
                    timestamp=time.time(),
                    source_ip=current_host or "127.0.0.1",
                    action="service_discovered",
                    raw_line=line_str,
                    line_number=idx,
                    source_file=source_name,
                    log_type=LogType.NMAP_XML,
                    metadata={
                        "port": port,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version_raw,
                        "hostname": current_hostname or current_host,
                    },
                )
                entries.append(entry)

        return entries
