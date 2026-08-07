"""
Web Page Source HTML Ingestor & Attack Surface Discovery Engine.

Parses raw HTML source code (e.g. 'Ctrl+U' output, scraped HTML, or saved web pages)
to identify attack surface indicators:
    - Hidden HTML comments (developer notes, passwords, internal paths)
    - Hidden input fields & form actions (CSRF tokens, admin parameters)
    - Exposed API endpoints & script references
    - Subdomain & internal URL harvesting
    - Outdated JavaScript library versions (jQuery, Bootstrap, React, etc.)
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from vigil.ingestors.base import BaseIngestor
from vigil.models import LogEntry, LogType


class HTMLSourceIngestor(BaseIngestor):
    """Ingestor that converts web page source HTML into structured attack surface LogEntry objects."""

    def can_ingest(self, filepath: Path) -> bool:
        if filepath.suffix.lower() in (".html", ".htm", ".xhtml", ".phtml", ".php", ".asp", ".aspx", ".jsp"):
            return True
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                sample = f.read(1024).lower()
                return "<html" in sample or "<!doctype html" in sample or "<head" in sample or "<script" in sample
        except Exception:
            return False

    def detect_format(self, filepath: Path) -> LogType:
        return LogType.WEB_ACCESS

    def ingest(self, filepath: Path) -> list[LogEntry]:
        entries: list[LogEntry] = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            return entries

        lines = content.splitlines()

        # 1. Extract HTML Comments (Developer notes, internal IPs, credentials)
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        for match in comment_pattern.finditer(content):
            comment_text = match.group(1).strip()
            if comment_text:
                line_no = content[: match.start()].count("\n") + 1
                entries.append(
                    LogEntry(
                        timestamp=time.time(),
                        action="html_comment_discovered",
                        raw_line=f"<!-- {comment_text} -->",
                        line_number=line_no,
                        source_file=filepath.name,
                        log_type=LogType.WEB_ACCESS,
                        metadata={
                            "type": "comment",
                            "comment": comment_text,
                            "suspicious": any(
                                k in comment_text.lower()
                                for k in ["todo", "fixme", "password", "pass", "key", "admin", "debug", "api", "internal"]
                            ),
                        },
                    )
                )

        # 2. Extract Forms & Hidden Inputs
        form_pattern = re.compile(r"<form.*?>", re.IGNORECASE)
        for match in form_pattern.finditer(content):
            form_tag = match.group(0)
            line_no = content[: match.start()].count("\n") + 1
            entries.append(
                LogEntry(
                    timestamp=time.time(),
                    action="html_form_discovered",
                    raw_line=form_tag,
                    line_number=line_no,
                    source_file=filepath.name,
                    log_type=LogType.WEB_ACCESS,
                    metadata={"type": "form", "raw": form_tag},
                )
            )

        hidden_input_pattern = re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*>', re.IGNORECASE)
        for match in hidden_input_pattern.finditer(content):
            input_tag = match.group(0)
            line_no = content[: match.start()].count("\n") + 1
            entries.append(
                LogEntry(
                    timestamp=time.time(),
                    action="hidden_input_discovered",
                    raw_line=input_tag,
                    line_number=line_no,
                    source_file=filepath.name,
                    log_type=LogType.WEB_ACCESS,
                    metadata={"type": "hidden_input", "raw": input_tag},
                )
            )

        # 3. Extract API Endpoints and JavaScript paths
        api_endpoint_pattern = re.compile(r"(/(?:api|v1|v2|admin|auth|upload|config)/[a-zA-Z0-9_\-/]+)", re.IGNORECASE)
        seen_endpoints = set()
        for match in api_endpoint_pattern.finditer(content):
            endpoint = match.group(1)
            if endpoint not in seen_endpoints:
                seen_endpoints.add(endpoint)
                line_no = content[: match.start()].count("\n") + 1
                entries.append(
                    LogEntry(
                        timestamp=time.time(),
                        action="api_endpoint_discovered",
                        raw_line=f"Endpoint reference: {endpoint}",
                        line_number=line_no,
                        source_file=filepath.name,
                        log_type=LogType.WEB_ACCESS,
                        metadata={"type": "api_endpoint", "endpoint": endpoint},
                    )
                )

        # 4. Outdated JS Library Version Fingerprinting
        js_libraries = [
            (r"jquery[.-](\d+\.\d+\.\d+)", "jQuery"),
            (r"bootstrap[.-](\d+\.\d+\.\d+)", "Bootstrap"),
            (r"angular[.-](\d+\.\d+\.\d+)", "Angular"),
            (r"vue[.-](\d+\.\d+\.\d+)", "Vue.js"),
            (r"react[.-](\d+\.\d+\.\d+)", "React"),
        ]
        for pattern, lib_name in js_libraries:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                version = match.group(1)
                line_no = content[: match.start()].count("\n") + 1
                entries.append(
                    LogEntry(
                        timestamp=time.time(),
                        action="js_library_detected",
                        raw_line=f"Detected {lib_name} v{version}",
                        line_number=line_no,
                        source_file=filepath.name,
                        log_type=LogType.WEB_ACCESS,
                        metadata={"type": "js_library", "library": lib_name, "version": version},
                    )
                )

        return entries
