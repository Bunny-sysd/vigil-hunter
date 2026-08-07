"""
Detection rule for Persistence Mechanisms in configurations.
"""

from __future__ import annotations

import re

from vigil.engine.rules.base_rule import DetectionRule
from vigil.models import Finding, FindingCategory, LogEntry, Severity


class PersistenceRule(DetectionRule):
    """
    Analyzes scheduled task / crontab structures to detect persistence setups.

    Flags reverse shells, download-and-execute strings, or base64 command decoders.
    """

    # Indicators commonly seen in cron reverse shells
    REV_SHELL_PATTERNS = [
        r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+", # bash tcp socket
        r"nc\s+(?:-e\s+\S+|[0-9.]+\s+[0-9]+)", # netcat connect
        r"socat\s+", # socket cat
        r"python(?:3)?\s+-c\s+['\"].*import\s+socket", # python inline shell
        r"perl\s+-e\s+['\"].*socket", # perl inline shell
        r"rm\s+/tmp/f;\s*mkfifo\s+/tmp/f", # netcat double redirection FIFO
    ]

    DOWNLOAD_EXEC_PATTERNS = [
        r"curl\s+.*\|\s*(?:bash|sh)", # curl download pipe to shell
        r"wget\s+.*-O-\s*\|\s*(?:bash|sh)", # wget download pipe to shell
    ]

    BASE64_DECODE = re.compile(r"base64\s+-d\s*\|\s*(?:bash|sh)")

    @property
    def name(self) -> str:
        return "Persistence Mechanism Detection"

    @property
    def attack_id(self) -> str:
        return "T1053.003"

    @property
    def attack_name(self) -> str:
        return "Scheduled Task/Job: Cron"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def analyze(self, entries: list[LogEntry]) -> list[Finding]:
        findings: list[Finding] = []

        for entry in entries:
            if entry.log_type == LogType.CRONTAB:
                cmd = entry.metadata.get("command", "")
                schedule = entry.metadata.get("schedule", "")
                user = entry.metadata.get("user", "")

                # 1. Reverse shell detection
                for pattern in self.REV_SHELL_PATTERNS:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            category=FindingCategory.PERSISTENCE,
                            title="Active Cron Reverse Shell (Persistence)",
                            description=(
                                f"An active reverse shell connection payload was detected inside user '{user}'s "
                                f"crontab configuration. Command: '{cmd}' scheduled on '{schedule}'."
                            ),
                            attack_technique=self.attack_id,
                            attack_technique_name=self.attack_name,
                            evidence=[entry],
                            confidence=0.99,
                            remediation=(
                                f"Immediately edit the crontab config file and delete/comment the entry. "
                                f"Terminate any active network processes connected to the target IP specified in the cron command."
                            ),
                        ))
                        break # Avoid duplicate triggers for same command

                # 2. Download and execute patterns
                for pattern in self.DOWNLOAD_EXEC_PATTERNS:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category=FindingCategory.PERSISTENCE,
                            title="Suspicious Cron Download and Execute Job",
                            description=(
                                f"A scheduled job was found that downloads a script from a remote URL "
                                f"and executes it directly into shell interpreter. Command: '{cmd}'."
                            ),
                            attack_technique="T1105",
                            attack_technique_name="Ingress Tool Transfer",
                            evidence=[entry],
                            confidence=0.95,
                            remediation="Inspect the remote URL resource. Block the domain/IP and remove the crontab configuration line.",
                        ))
                        break

                # 3. Base64 decoded commands
                if self.BASE64_DECODE.search(cmd):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=FindingCategory.PERSISTENCE,
                        title="Obfuscated Base64 Script Execution",
                        description=(
                            f"A scheduled job contains base64 encoded command instructions decoded "
                            f"and piped straight to a shell. Command: '{cmd}'."
                        ),
                        attack_technique="T1027",
                        attack_technique_name="Obfuscated Files or Information",
                        evidence=[entry],
                        confidence=0.95,
                        remediation="Base64 decode the string payload to reveal the underlying command commands. Clean the configuration.",
                    ))

        return findings

# Import LogType
from vigil.models import LogType
