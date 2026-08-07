"""
Credential extractor for log formats.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path

from vigil.models import Credential, LogEntry, LogType


class CredentialExtractor:
    """
    Scans LogEntries to extract usernames, passwords, tokens, or base64 credentials.
    """

    # Match HTTP Authorization headers: Basic BASE64_STR
    BASIC_AUTH_PATTERN = re.compile(r"Authorization:\s*Basic\s+([a-zA-Z0-9+/=]+)", re.IGNORECASE)

    # Match common credential forms in HTTP POST lines or queries (e.g. user=admin&pass=secret)
    CRED_PARAMS = re.compile(
        r"(?:user|username|usr|email|login|account|pass|password|pwd|passwd|token|key)="
        r"([^&\s]+)", re.IGNORECASE
    )

    def extract(self, entries: list[LogEntry]) -> list[Credential]:
        credentials: list[Credential] = []
        seen = set()

        for entry in entries:
            # 1. SSH log extracts
            if entry.log_type == LogType.AUTH_LOG:
                if entry.action == "ssh_login_failed" and entry.username:
                    cred = Credential(
                        username=entry.username,
                        context="failed_login_attempt",
                        source=f"{entry.source_file}:{entry.line_number}",
                        timestamp=entry.timestamp,
                        source_ip=entry.source_ip,
                    )
                    key = (cred.username, cred.secret, cred.context)
                    if key not in seen:
                        credentials.append(cred)
                        seen.add(key)

                elif entry.action == "ssh_login_success" and entry.username:
                    cred = Credential(
                        username=entry.username,
                        context="successful_login",
                        source=f"{entry.source_file}:{entry.line_number}",
                        timestamp=entry.timestamp,
                        source_ip=entry.source_ip,
                    )
                    key = (cred.username, cred.secret, cred.context)
                    if key not in seen:
                        credentials.append(cred)
                        seen.add(key)

            # 2. Web Access logs
            elif entry.log_type == LogType.WEB_ACCESS:
                # Check headers / raw line for HTTP basic auth
                auth_match = self.BASIC_AUTH_PATTERN.search(entry.raw_line)
                if auth_match:
                    encoded = auth_match.group(1)
                    user_pass = self._decode_basic_auth(encoded)
                    if user_pass:
                        user, pw = user_pass
                        cred = Credential(
                            username=user,
                            secret=pw,
                            secret_type="password",
                            context="http_basic_auth",
                            source=f"{entry.source_file}:{entry.line_number}",
                            timestamp=entry.timestamp,
                            source_ip=entry.source_ip,
                        )
                        key = (cred.username, cred.secret, cred.context)
                        if key not in seen:
                            credentials.append(cred)
                            seen.add(key)

                # Check URL query strings or payloads for parameter credentials
                query = entry.metadata.get("query", "")
                if query:
                    matches = self.CRED_PARAMS.findall(query)
                    # Simple heuristic: if we find multiple login-like parameter matches, let's log them
                    if len(matches) >= 1:
                        # Find distinct username/password tokens
                        for match in matches:
                            cred = Credential(
                                username=match,
                                secret="",
                                secret_type="potential_leak",
                                context="query_string_parameter",
                                source=f"{entry.source_file}:{entry.line_number}",
                                timestamp=entry.timestamp,
                                source_ip=entry.source_ip,
                            )
                            key = (cred.username, cred.secret, cred.context)
                            if key not in seen:
                                credentials.append(cred)
                                seen.add(key)

        return credentials

    def _decode_basic_auth(self, encoded_str: str) -> tuple[str, str] | None:
        try:
            decoded = base64.b64decode(encoded_str).decode("utf-8", errors="ignore")
            if ":" in decoded:
                parts = decoded.split(":", 1)
                return parts[0], parts[1]
        except Exception:
            pass
        return None
