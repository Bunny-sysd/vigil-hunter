"""
Detection rule for Privilege Escalation activity.
"""

from __future__ import annotations

from vigil.engine.rules.base_rule import DetectionRule
from vigil.models import Finding, FindingCategory, LogEntry, Severity


class PrivEscalationRule(DetectionRule):
    """
    Detects privilege escalation indicators in auth logs.

    Flags unauthorized sudo attempts, transitions to root, and execution of
    interactive shells or known GTFOBins patterns via sudo.
    """

    # Interactive shells and commands often used to escape environments (GTFOBins)
    GTFOBINS_INTERPRETERS = {
        "bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "lua",
        "find", "awk", "sed", "nmap", "git", "vim", "vi", "less", "more", "nc",
        "netcat", "socat", "base64", "cp", "mv", "dd", "chmod", "chown",
    }

    @property
    def name(self) -> str:
        return "Privilege Escalation Detection"

    @property
    def attack_id(self) -> str:
        return "T1548"

    @property
    def attack_name(self) -> str:
        return "Abuse Elevation Control Mechanism"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def analyze(self, entries: list[LogEntry]) -> list[Finding]:
        findings: list[Finding] = []

        for entry in entries:
            # 1. Sudo failures
            if entry.action == "sudo_command" and "incorrect password" in entry.raw_line.lower():
                findings.append(self._create_finding(
                    title="Failed Sudo Execution Attempt",
                    desc=f"User '{entry.username}' attempted to execute a command via sudo but failed authentication.",
                    remedy="Audit user sudo privileges and check for compromised account indicators if this is unusual.",
                    severity=Severity.MEDIUM,
                    evidence=[entry]
                ))
                continue

            # 2. Sudo execution to root shell/interpreters
            if entry.action == "sudo_command":
                cmd = entry.metadata.get("command", "")
                target_user = entry.metadata.get("target_user", "")
                
                if target_user in ("root", "admin", "0"):
                    # Check for GTFOBins patterns
                    is_interpreter = False
                    cmd_base = cmd.split()[0].split("/")[-1] if cmd else ""
                    if cmd_base in self.GTFOBINS_INTERPRETERS:
                        is_interpreter = True

                    if is_interpreter:
                        findings.append(self._create_finding(
                            title="Suspicious Sudo Command Execution (Potential Escape)",
                            desc=(
                                f"User '{entry.username}' executed a shell interpreter or environment escape command "
                                f"('{cmd}') via sudo as root. This is a common technique to spawn an interactive root shell."
                            ),
                            remedy="Review whether this user requires root privilege access to interactive commands. Inspect host command history.",
                            severity=Severity.CRITICAL,
                            evidence=[entry]
                        ))
                    elif verbose_root_cmd := (entry.username != "root"):
                        # Log general root command elevation by non-root users
                        findings.append(self._create_finding(
                            title="Privileged Sudo Execution by Non-Root",
                            desc=f"User '{entry.username}' elevated privileges via sudo to execute command: '{cmd}'.",
                            remedy="Ensure command logging is enabled and verify execution authorization.",
                            severity=Severity.MEDIUM,
                            evidence=[entry]
                        ))

            # 3. su to root sessionOpened
            if entry.action == "su_session" and entry.metadata.get("target_user") in ("root", "0"):
                findings.append(self._create_finding(
                    title="User Switched to Root via su",
                    desc=f"User '{entry.username}' successfully switched their session to root using the su command.",
                    remedy="Limit access to su shell operations. Enforce sudo with detailed command auditing instead.",
                    severity=Severity.HIGH,
                    evidence=[entry]
                ))

        return findings

    def _create_finding(self, title: str, desc: str, remedy: str, severity: Severity, evidence: list[LogEntry]) -> Finding:
        return Finding(
            severity=severity,
            category=FindingCategory.PRIVILEGE_ESCALATION,
            title=title,
            description=desc,
            attack_technique=self.attack_id,
            attack_technique_name=self.attack_name,
            evidence=evidence,
            confidence=0.90,
            remediation=remedy,
        )
