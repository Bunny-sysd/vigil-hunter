"""
Core data models for the Vigil engine.

Every component in Vigil — ingestors, rules, AI brain, reporters — communicates
through these models. They are the shared language of the entire system.

Key concepts:
    - LogEntry: A single parsed line from any log source.
    - Finding: A security-relevant detection (brute force, privesc, etc).
    - Credential: An extracted username/password pair from logs.
    - ServiceVersion: A detected service + version with CVE matches.
    - ExploitMatch: A known exploit for a detected vulnerability.
    - AttackTimeline: An ordered reconstruction of an attack.
    - ScanResult: The final output containing everything Vigil found.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ──────────────────────────────────────────────────────────────
#  Enums — Severity, categories, attack phases
# ──────────────────────────────────────────────────────────────

class Severity(Enum):
    """Finding severity levels, aligned with CVSS qualitative ratings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (higher = more severe)."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    @property
    def color(self) -> str:
        """Rich markup color for terminal display."""
        return {
            Severity.CRITICAL: "red",
            Severity.HIGH: "dark_orange",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]

    @property
    def icon(self) -> str:
        """Emoji icon for terminal display."""
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[self]


class FindingCategory(Enum):
    """Classification of what type of finding this is."""

    VULNERABILITY = "vulnerability"
    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    RECONNAISSANCE = "reconnaissance"
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_LEAK = "credential_leak"
    PHISHING = "phishing"
    CODE_VULNERABILITY = "code_vulnerability"
    MISCONFIGURATION = "misconfiguration"


class LogType(Enum):
    """Supported log source types."""

    AUTH_LOG = "auth_log"
    SYSLOG = "syslog"
    WEB_ACCESS = "web_access"
    WEB_ERROR = "web_error"
    WINDOWS_EVTX = "windows_evtx"
    NMAP_XML = "nmap_xml"
    EMAIL = "email"
    CRONTAB = "crontab"
    PEASS_OUTPUT = "peass_output"
    JSON_LINES = "json_lines"
    SOURCE_CODE = "source_code"
    UNKNOWN = "unknown"


class AttackPhase(Enum):
    """Kill chain phases (Lockheed Martin Cyber Kill Chain + MITRE)."""

    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_AND_CONTROL = "Command & Control"
    ACTIONS_ON_OBJECTIVES = "Actions on Objectives"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    LATERAL_MOVEMENT = "Lateral Movement"
    EXFILTRATION = "Exfiltration"
    PERSISTENCE = "Persistence"


# ──────────────────────────────────────────────────────────────
#  Core Data Models
# ──────────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    """
    A single parsed line from any log source.

    This is the universal data unit that all ingestors produce.
    Every log format (auth.log, Apache, nmap XML, etc.) gets normalized
    into LogEntry objects before reaching the analysis engine.
    """

    timestamp: float | None = None
    """Unix timestamp of the log event. None if unparseable."""

    source_ip: str | None = None
    """Source IP address associated with the event."""

    dest_ip: str | None = None
    """Destination IP address, if applicable."""

    username: str | None = None
    """Username involved in the event."""

    action: str = ""
    """What happened — e.g., 'login_failed', 'file_accessed', 'process_started'."""

    raw_line: str = ""
    """The original, unmodified log line."""

    line_number: int = 0
    """Line number in the source file (1-indexed)."""

    source_file: str = ""
    """Path to the log file this entry came from."""

    log_type: LogType = LogType.UNKNOWN
    """What kind of log this entry was parsed from."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """
    Flexible key-value store for log-type-specific data.
    
    Examples:
        auth_log:   {"service": "sshd", "pid": 1234, "port": 22}
        web_access: {"method": "GET", "path": "/admin", "status": 404, "user_agent": "gobuster/3.6"}
        nmap:       {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4.49"}
        email:      {"from": "...", "to": "...", "subject": "...", "has_attachment": True}
        crontab:    {"schedule": "*/5 * * * *", "command": "...", "user": "root"}
        peass:      {"section": "SUID", "category": "privesc"}
    """

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON export."""
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "username": self.username,
            "action": self.action,
            "raw_line": self.raw_line,
            "line_number": self.line_number,
            "source_file": self.source_file,
            "log_type": self.log_type.value,
            "metadata": self.metadata,
        }


@dataclass
class Finding:
    """
    A security-relevant detection produced by a rule or the AI brain.

    Findings are the primary output of the analysis engine. Each one
    represents something an analyst should investigate.
    """

    severity: Severity
    """How dangerous this finding is."""

    category: FindingCategory
    """What type of finding this is."""

    title: str
    """Short human-readable title (e.g., 'SSH Brute Force → Successful Login')."""

    description: str
    """Detailed explanation of what was found and why it matters."""

    attack_technique: str = ""
    """MITRE ATT&CK technique ID (e.g., 'T1110.001')."""

    attack_technique_name: str = ""
    """Human-readable ATT&CK name (e.g., 'Password Guessing')."""

    evidence: list[LogEntry] = field(default_factory=list)
    """The log entries that prove this finding."""

    confidence: float = 0.0
    """Confidence score from 0.0 to 1.0. AI findings include this."""

    remediation: str = ""
    """What the defender should do about this finding."""

    exploitation_path: str = ""
    """How an attacker could (or did) exploit this. For offensive use."""

    references: list[str] = field(default_factory=list)
    """URLs to CVEs, writeups, or exploit databases."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Additional context (e.g., source_auditor findings include CWE IDs)."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON export."""
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "attack_technique": self.attack_technique,
            "attack_technique_name": self.attack_technique_name,
            "evidence_count": len(self.evidence),
            "evidence_lines": [e.raw_line for e in self.evidence[:10]],
            "confidence": self.confidence,
            "remediation": self.remediation,
            "exploitation_path": self.exploitation_path,
            "references": self.references,
            "metadata": self.metadata,
        }


@dataclass
class Credential:
    """An extracted or attempted credential from log analysis."""

    username: str
    """The username."""

    secret: str = ""
    """Password, hash, or token. Empty if only username was found."""

    secret_type: str = "password"
    """Type of secret: 'password', 'hash', 'token', 'key', 'base64'."""

    source: str = ""
    """Where this credential was found (file + line)."""

    context: str = ""
    """How it was used: 'successful_login', 'failed_attempt', 'leaked', 'hardcoded'."""

    timestamp: float | None = None
    """When this credential was used/found."""

    source_ip: str | None = None
    """IP that used this credential, if applicable."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "secret": self.secret,
            "secret_type": self.secret_type,
            "source": self.source,
            "context": self.context,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
        }


@dataclass
class ExploitMatch:
    """A known exploit matching a detected vulnerability."""

    source: str
    """Where the exploit was found: 'nvd', 'exploitdb', 'github'."""

    exploit_id: str
    """ID or URL of the exploit."""

    title: str
    """Short description of the exploit."""

    url: str = ""
    """Direct link to the exploit."""

    language: str = ""
    """Programming language of the PoC (python, bash, c, etc.)."""

    stars: int = 0
    """GitHub stars (for GitHub PoCs)."""

    verified: bool = False
    """Whether we confirmed the URL/exploit actually exists."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "exploit_id": self.exploit_id,
            "title": self.title,
            "url": self.url,
            "language": self.language,
            "stars": self.stars,
            "verified": self.verified,
        }


@dataclass
class ServiceVersion:
    """A detected service and its version with associated vulnerabilities."""

    service_name: str
    """Service name (e.g., 'OpenSSH', 'Apache', 'MySQL')."""

    version: str
    """Version string (e.g., '8.2p1', '2.4.49')."""

    host: str = ""
    """Host IP or hostname where this service was detected."""

    port: int = 0
    """Port number."""

    protocol: str = "tcp"
    """Protocol (tcp/udp)."""

    cpe: str = ""
    """Common Platform Enumeration string for NVD lookups."""

    cve_matches: list[dict[str, Any]] = field(default_factory=list)
    """
    List of CVE matches. Each entry:
    {"cve_id": "CVE-2021-41773", "cvss": 7.5, "summary": "...", "exploits": [ExploitMatch]}
    """

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_name": self.service_name,
            "version": self.version,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "cpe": self.cpe,
            "cve_count": len(self.cve_matches),
            "cve_matches": self.cve_matches,
        }


@dataclass
class TimelineEvent:
    """A single event in the reconstructed attack timeline."""

    timestamp: float
    """Unix timestamp of the event."""

    description: str
    """Human-readable description of what happened."""

    phase: AttackPhase
    """Kill chain phase this event belongs to."""

    severity: Severity
    """Severity of this specific event."""

    finding_ref: Finding | None = None
    """Reference to the Finding that generated this event, if any."""

    source_ip: str | None = None
    """IP involved in this event."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "description": self.description,
            "phase": self.phase.value,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
        }


@dataclass
class AttackTimeline:
    """Ordered reconstruction of an attack from start to finish."""

    events: list[TimelineEvent] = field(default_factory=list)
    """Chronologically ordered events."""

    narrative: str = ""
    """AI-generated narrative describing the full attack story."""

    total_duration_seconds: float = 0.0
    """Total time from first to last event."""

    def add_event(self, event: TimelineEvent) -> None:
        """Insert event in chronological order."""
        self.events.append(event)
        self.events.sort(key=lambda e: e.timestamp)
        if len(self.events) >= 2:
            self.total_duration_seconds = (
                self.events[-1].timestamp - self.events[0].timestamp
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": [e.to_dict() for e in self.events],
            "narrative": self.narrative,
            "total_duration_seconds": self.total_duration_seconds,
            "event_count": len(self.events),
        }


@dataclass
class PrivescPath:
    """
    A privilege escalation path identified from PEASS output or analysis.

    Each path represents a specific way to escalate privileges,
    with the exact command to run and confidence level.
    """

    technique: str
    """What the privesc technique is (e.g., 'SUID find binary')."""

    command: str
    """The exact command to execute for escalation."""

    confidence: float = 0.0
    """Confidence that this will work (0.0-1.0)."""

    risk: str = ""
    """Risk level of attempting this (e.g., 'safe', 'may crash service')."""

    reference: str = ""
    """Reference URL (GTFOBins, CVE, etc.)."""

    cve: str = ""
    """Associated CVE if kernel/software exploit."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "command": self.command,
            "confidence": self.confidence,
            "risk": self.risk,
            "reference": self.reference,
            "cve": self.cve,
        }


@dataclass
class ScanResult:
    """
    The complete output of a Vigil analysis run.

    This is the top-level container that holds everything Vigil found.
    Reporters consume this to generate CLI output, JSON, HTML, etc.
    """

    findings: list[Finding] = field(default_factory=list)
    """All security findings, sorted by severity."""

    credentials: list[Credential] = field(default_factory=list)
    """Extracted credentials."""

    services: list[ServiceVersion] = field(default_factory=list)
    """Detected services and versions."""

    timeline: AttackTimeline = field(default_factory=AttackTimeline)
    """Reconstructed attack timeline."""

    privesc_paths: list[PrivescPath] = field(default_factory=list)
    """Privilege escalation paths (from PEASS analysis)."""

    log_entries_processed: int = 0
    """Total number of log entries analyzed."""

    files_analyzed: list[str] = field(default_factory=list)
    """List of files that were analyzed."""

    scan_start: float = field(default_factory=time.time)
    """Scan start timestamp."""

    scan_duration: float = 0.0
    """How long the scan took in seconds."""

    ai_provider: str = ""
    """Which AI provider was used (if any)."""

    mode: str = "default"
    """Analysis mode: 'default', 'htb', 'incident'."""

    errors: list[str] = field(default_factory=list)
    """Non-fatal errors encountered during analysis."""

    def sort_findings(self) -> None:
        """Sort findings by severity (CRITICAL first)."""
        self.findings.sort(key=lambda f: f.severity.rank, reverse=True)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def threat_score(self) -> int:
        """
        Overall threat score (0-100) based on findings.

        Weighted: CRITICAL=25, HIGH=15, MEDIUM=5, LOW=1
        Capped at 100.
        """
        score = (
            self.critical_count * 25
            + self.high_count * 15
            + self.medium_count * 5
            + self.low_count * 1
        )
        return min(score, 100)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "threat_score": self.threat_score,
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "credentials_found": len(self.credentials),
                "services_detected": len(self.services),
                "privesc_paths": len(self.privesc_paths),
                "log_entries_processed": self.log_entries_processed,
                "files_analyzed": self.files_analyzed,
                "scan_duration": self.scan_duration,
                "ai_provider": self.ai_provider,
                "mode": self.mode,
            },
            "findings": [f.to_dict() for f in self.findings],
            "credentials": [c.to_dict() for c in self.credentials],
            "services": [s.to_dict() for s in self.services],
            "timeline": self.timeline.to_dict(),
            "privesc_paths": [p.to_dict() for p in self.privesc_paths],
            "errors": self.errors,
        }
