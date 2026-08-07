"""
Detection rule for brute force and credential stuffing patterns.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from vigil.engine.rules.base_rule import DetectionRule
from vigil.models import Finding, FindingCategory, LogEntry, Severity


class BruteForceRule(DetectionRule):
    """
    Detects SSH, Windows, or Web brute force attempts.

    Escalates severity if a successful login immediately follows a brute force from
    the same source IP.
    """

    def __init__(self, failure_threshold: int = 5, window_seconds: int = 60):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds

    @property
    def name(self) -> str:
        return "Brute Force Detection"

    @property
    def attack_id(self) -> str:
        return "T1110"

    @property
    def attack_name(self) -> str:
        return "Brute Force"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def analyze(self, entries: list[LogEntry]) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Group login events by IP and chronological order
        ip_login_attempts: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in entries:
            # Check for authentication events
            if entry.action in ("ssh_login_failed", "ssh_login_success", "http_login_failed", "http_login_success"):
                if entry.source_ip:
                    ip_login_attempts[entry.source_ip].append(entry)

        # 2. Analyze each IP
        for ip, attempts in ip_login_attempts.items():
            attempts.sort(key=lambda e: e.timestamp or 0)
            
            failures_window: list[LogEntry] = []
            flagged_brute_force = False
            
            for att in attempts:
                t = att.timestamp or 0
                
                # Check for failure vs success
                if "failed" in att.action:
                    failures_window.append(att)
                    # Prune old failures outside window
                    failures_window = [f for f in failures_window if (t - (f.timestamp or 0)) <= self.window_seconds]
                    
                    if len(failures_window) >= self.failure_threshold and not flagged_brute_force:
                        # Found brute force attempt
                        findings.append(self._create_brute_finding(ip, failures_window, success=False))
                        flagged_brute_force = True
                
                elif "success" in att.action:
                    # Successful login! Check if we had failures right before this from the same IP
                    # Prune old failures relative to this success
                    failures_window = [f for f in failures_window if (t - (f.timestamp or 0)) <= self.window_seconds]
                    
                    if len(failures_window) >= 3: # Lower threshold since success makes it high impact
                        findings.append(self._create_brute_finding(ip, failures_window + [att], success=True))
                    
                    # Reset after a success
                    failures_window = []
                    flagged_brute_force = False

        return findings

    def _create_brute_finding(self, ip: str, evidence: list[LogEntry], success: bool) -> Finding:
        users = list(set([e.username for e in evidence if e.username]))
        users_str = ", ".join(f"'{u}'" for u in users) or "unknown"
        
        if success:
            title = "Brute Force Attack → Successful Compromise"
            severity = Severity.CRITICAL
            desc = (
                f"A brute force attack from source IP {ip} against user accounts ({users_str}) "
                f"was followed by a successful login to '{evidence[-1].username}' at "
                f"{self._get_time_str(evidence[-1].timestamp)}. This indicates a highly probable compromised system."
            )
            remedy = f"Immediately disable/quarantine user '{evidence[-1].username}', revoke access tokens, block IP {ip}, and audit all actions performed after the login."
        else:
            title = "Active Brute Force Attack"
            severity = Severity.HIGH
            desc = (
                f"Multiple authentication failures ({len(evidence)}) were detected from source IP {ip} "
                f"targeting accounts ({users_str}) within a {self.window_seconds}-second window."
            )
            remedy = f"Apply immediate firewall blocks or fail2ban rules to IP {ip}. Verify target user accounts have not been locked out."

        return Finding(
            severity=severity,
            category=FindingCategory.BRUTE_FORCE,
            title=title,
            description=desc,
            attack_technique=self.attack_id,
            attack_technique_name=self.attack_name,
            evidence=evidence,
            confidence=0.95 if success else 0.85,
            remediation=remedy,
        )

    def _get_time_str(self, ts: float | None) -> str:
        if not ts:
            return "unknown time"
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S")
