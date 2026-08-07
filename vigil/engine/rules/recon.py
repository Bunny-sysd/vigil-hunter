"""
Detection rule for Reconnaissance and Active Scanning.
"""

from __future__ import annotations

from collections import defaultdict

from vigil.engine.rules.base_rule import DetectionRule
from vigil.models import Finding, FindingCategory, LogEntry, Severity


class ReconRule(DetectionRule):
    """
    Detects directory brute-forcing, automated scanner signatures, and port sweeps.
    """

    KNOWN_SCANNER_AGENTS = {
        "gobuster", "dirb", "dirbuster", "ffuf", "nikto", "sqlmap", "nmap",
        "w3af", "nessus", "zap", "acunetix", "hydra", "medusa",
    }

    def __init__(self, directory_brute_threshold: int = 15, window_seconds: int = 30):
        self.directory_brute_threshold = directory_brute_threshold
        self.window_seconds = window_seconds

    @property
    def name(self) -> str:
        return "Reconnaissance Detection"

    @property
    def attack_id(self) -> str:
        return "T1595"

    @property
    def attack_name(self) -> str:
        return "Active Scanning"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    def analyze(self, entries: list[LogEntry]) -> list[Finding]:
        findings: list[Finding] = []

        # Group access entries by IP
        ip_access: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in entries:
            if entry.log_type == LogType.WEB_ACCESS and entry.source_ip:
                ip_access[entry.source_ip].append(entry)

        # Process each IP for scanning behaviors
        for ip, logs in ip_access.items():
            logs.sort(key=lambda e: e.timestamp or 0)
            
            # Detect scanner user agents immediately
            scanners_triggered = set()
            for log in logs:
                ua = log.metadata.get("user_agent", "").lower()
                for scanner in self.KNOWN_SCANNER_AGENTS:
                    if scanner in ua:
                        scanners_triggered.add((scanner, ua))

            for scanner_name, full_ua in scanners_triggered:
                matching_logs = [l for l in logs if scanner_name in l.metadata.get("user_agent", "").lower()]
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=FindingCategory.RECONNAISSANCE,
                    title="Automated Security Scanner Detected",
                    description=(
                        f"A client at IP {ip} made web requests presenting an automated tool signature in the "
                        f"User-Agent header: '{full_ua}'."
                    ),
                    attack_technique=self.attack_id,
                    attack_technique_name=self.attack_name,
                    evidence=matching_logs[:5],
                    confidence=0.99,
                    remediation=f"Block IP {ip} at the web application firewall (WAF) or server configuration layer.",
                ))

            # Detect directory/file brute forcing (high density of 404 status codes)
            not_found_logs: list[LogEntry] = []
            for log in logs:
                t = log.timestamp or 0
                status = log.metadata.get("status", 200)

                if status == 404:
                    not_found_logs.append(log)
                    # Prune old 404s outside window
                    not_found_logs = [l for l in not_found_logs if (t - (l.timestamp or 0)) <= self.window_seconds]

                    if len(not_found_logs) >= self.directory_brute_threshold:
                        # Find directories discovered (HTTP 200/301 from same IP nearby)
                        discovered_paths = set()
                        for sibling in logs:
                            if sibling.metadata.get("status") in (200, 301, 302):
                                # If it falls within the scan window
                                if abs((sibling.timestamp or 0) - t) <= self.window_seconds * 2:
                                    discovered_paths.add(f"{sibling.metadata.get('path')} ({sibling.metadata.get('status')})")

                        discovered_str = ""
                        if discovered_paths:
                            discovered_str = f"\n\nPaths successfully discovered during scanning:\n" + "\n".join(f"  - {p}" for p in list(discovered_paths)[:5])

                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category=FindingCategory.RECONNAISSANCE,
                            title="Web Directory Brute-Forcing Detected",
                            description=(
                                f"Source IP {ip} made {len(not_found_logs)} request attempts to non-existent URLs (HTTP 404) "
                                f"within a {self.window_seconds}-second window, indicative of directory/file brute forcing.{discovered_str}"
                            ),
                            attack_technique="T1595.003",
                            attack_technique_name="Wordlist Scanning",
                            evidence=not_found_logs,
                            confidence=0.90,
                            remediation=f"Deploy rate limiting policies, implement IP throttling, or temporarily block IP {ip}.",
                        ))
                        # Reset window
                        not_found_logs = []

        return findings

# LogType needs importing
from vigil.models import LogType
