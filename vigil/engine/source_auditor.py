"""
Source code vulnerability auditor.

Combines multi-pattern static pre-scanning (SAST) with deep LLM semantic code analysis.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from vigil.ai.brain import AIBrain
from vigil.ai.prompts import CODE_AUDIT_SCHEMA, CODE_AUDIT_SYSTEM
from vigil.models import Finding, FindingCategory, LogEntry, LogType, Severity

logger = logging.getLogger("vigil.engine.source_auditor")


class SourceAuditor:
    """
    Audits source code files for security vulnerabilities using a hybrid rule-based
    pre-scanner and AI reasoning engine.
    """

    def __init__(self, ai_brain: AIBrain | None = None):
        self.ai_brain = ai_brain

    def audit_file(self, filepath: Path) -> list[Finding]:
        findings: list[Finding] = []
        source_name = filepath.name

        try:
            code_content = filepath.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            logger.error(f"Failed to read source code file {filepath}: {e}")
            return []

        # 1. Rule-based static check for obvious security issues (Pre-scan)
        findings.extend(self._rule_pre_scan(code_content, source_name))

        # 2. AI Brain structured code auditing (Deep-scan)
        if self.ai_brain and self.ai_brain.provider:
            try:
                logger.info(f"Submitting {source_name} to AI for code security audit...")
                ai_data = self.ai_brain.structured_output(
                    system_prompt=CODE_AUDIT_SYSTEM,
                    user_content=f"File: {source_name}\n\nCode Content:\n{code_content}",
                    response_schema=CODE_AUDIT_SCHEMA,
                )
                
                # Parse AI vulnerabilities into structured findings
                ai_vulns = ai_data.get("vulnerabilities", [])
                for vuln in ai_vulns:
                    findings.append(self._parse_ai_vuln(vuln, code_content, source_name))
            except Exception as e:
                logger.error(f"AI source audit failed for {source_name}: {e}")

        return findings

    def _rule_pre_scan(self, code: str, filename: str) -> list[Finding]:
        """Perform static SAST scans across multiple vulnerability classes."""
        findings: list[Finding] = []
        lines = code.splitlines()

        # 1. Hardcoded Credentials & API Keys
        key_pattern = re.compile(
            r'(?:api_key|password|passwd|secret_key|token|private_key|aws_secret)\s*=\s*[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE,
        )
        for m in key_pattern.finditer(code):
            secret = m.group(1)
            if len(secret) > 4 and not any(p in secret.lower() for p in ("config", "secret", "password", "key", "token", "env")):
                line_no = code[:m.start()].count("\n") + 1
                entry = LogEntry(
                    raw_line=lines[line_no - 1] if line_no <= len(lines) else m.group(0),
                    line_number=line_no,
                    source_file=filename,
                    log_type=LogType.SOURCE_CODE,
                )
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=FindingCategory.CREDENTIAL_LEAK,
                    title="Hardcoded Secret or API Key in Code",
                    description=f"A potential hardcoded secret was found: '{m.group(0)}'.",
                    attack_technique="T1552.001",
                    attack_technique_name="Credentials in Files",
                    evidence=[entry],
                    confidence=0.85,
                    remediation="Move secrets out of source code into environment variables or a secret vault.",
                ))

        # 2. Dangerous Shell Execution
        shell_pattern = re.compile(r'(?:eval|exec|os\.system|subprocess\.run|subprocess\.Popen)\s*\(')
        for m in shell_pattern.finditer(code):
            line_no = code[:m.start()].count("\n") + 1
            entry = LogEntry(
                raw_line=lines[line_no - 1] if line_no <= len(lines) else m.group(0),
                line_number=line_no,
                source_file=filename,
                log_type=LogType.SOURCE_CODE,
            )
            findings.append(Finding(
                severity=Severity.HIGH,
                category=FindingCategory.CODE_VULNERABILITY,
                title="Dangerous Shell Execution Trigger (CWE-78)",
                description=f"Code invokes command execution: '{m.group(0)}'. Unsanitized inputs can lead to RCE.",
                attack_technique="T1059",
                attack_technique_name="Command and Scripting Interpreter",
                evidence=[entry],
                confidence=0.75,
                remediation="Avoid raw shell execution. Use parameterized APIs or strict validation.",
            ))

        # 3. SQL Injection (String Formatting in Queries)
        sqli_pattern = re.compile(r'(?:execute|query|raw)\s*\(\s*f?[\'"].*?(?:SELECT|INSERT|UPDATE|DELETE).*?[\'"]', re.IGNORECASE)
        for m in sqli_pattern.finditer(code):
            line_no = code[:m.start()].count("\n") + 1
            entry = LogEntry(
                raw_line=lines[line_no - 1] if line_no <= len(lines) else m.group(0),
                line_number=line_no,
                source_file=filename,
                log_type=LogType.SOURCE_CODE,
            )
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=FindingCategory.CODE_VULNERABILITY,
                title="Potential SQL Injection (CWE-89)",
                description="Raw string formatting or concatenation detected in SQL query context.",
                attack_technique="T1190",
                attack_technique_name="Exploit Public-Facing Application",
                evidence=[entry],
                confidence=0.80,
                remediation="Use parameterized queries or ORM query builders.",
            ))

        # 4. Insecure Deserialization
        deserial_pattern = re.compile(r'(?:pickle\.loads|yaml\.load\s*\([^,)]*\)|marshal\.loads|shelve\.open)\s*\(')
        for m in deserial_pattern.finditer(code):
            line_no = code[:m.start()].count("\n") + 1
            entry = LogEntry(
                raw_line=lines[line_no - 1] if line_no <= len(lines) else m.group(0),
                line_number=line_no,
                source_file=filename,
                log_type=LogType.SOURCE_CODE,
            )
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=FindingCategory.CODE_VULNERABILITY,
                title="Insecure Deserialization (CWE-502)",
                description=f"Unsafe deserialization call: '{m.group(0)}'. May allow arbitrary code execution.",
                attack_technique="T1203",
                attack_technique_name="Exploitation for Client Execution",
                evidence=[entry],
                confidence=0.85,
                remediation="Use safe parsers such as yaml.safe_load() or JSON deserialization.",
            ))

        # 5. SSRF / Unvalidated Network Requests
        ssrf_pattern = re.compile(r'(?:requests\.get|requests\.post|urllib\.request\.urlopen|httpx\.get)\s*\(\s*(?!\s*[\'"]http)')
        for m in ssrf_pattern.finditer(code):
            line_no = code[:m.start()].count("\n") + 1
            entry = LogEntry(
                raw_line=lines[line_no - 1] if line_no <= len(lines) else m.group(0),
                line_number=line_no,
                source_file=filename,
                log_type=LogType.SOURCE_CODE,
            )
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.CODE_VULNERABILITY,
                title="Potential Server-Side Request Forgery / SSRF (CWE-918)",
                description="Network call uses dynamic variable URL instead of hardcoded/validated host.",
                attack_technique="T1090",
                attack_technique_name="Proxy",
                evidence=[entry],
                confidence=0.65,
                remediation="Validate request target URLs against strict domain allowlists.",
            ))

        # 6. Weak Cryptography
        crypto_pattern = re.compile(r'(?:hashlib\.md5|hashlib\.sha1|DES\.new|RC4\.new)\s*\(')
        for m in crypto_pattern.finditer(code):
            line_no = code[:m.start()].count("\n") + 1
            entry = LogEntry(
                raw_line=lines[line_no - 1] if line_no <= len(lines) else m.group(0),
                line_number=line_no,
                source_file=filename,
                log_type=LogType.SOURCE_CODE,
            )
            findings.append(Finding(
                severity=Severity.LOW,
                category=FindingCategory.CODE_VULNERABILITY,
                title="Use of Weak Cryptographic Primitive (CWE-327)",
                description=f"Weak hash/cipher detected: '{m.group(0)}'.",
                attack_technique="T1600",
                attack_technique_name="Weaken Encryption",
                evidence=[entry],
                confidence=0.90,
                remediation="Upgrade to modern primitives such as SHA-256, Argon2, or AES-GCM.",
            ))

        return findings

    def _parse_ai_vuln(self, vuln: dict[str, Any], full_code: str, filename: str) -> Finding:
        line_start = vuln.get("line_start", 1)
        line_end = vuln.get("line_end", line_start)
        
        lines = full_code.splitlines()
        evidence_lines = []
        for i in range(max(1, line_start), min(len(lines) + 1, line_end + 1)):
            evidence_lines.append(LogEntry(
                raw_line=lines[i - 1],
                line_number=i,
                source_file=filename,
                log_type=LogType.SOURCE_CODE,
            ))

        severity_str = vuln.get("severity", "MEDIUM")
        severity = Severity.MEDIUM
        try:
            severity = Severity[severity_str.upper()]
        except KeyError:
            pass

        title = vuln.get("title", "Code Security Vulnerability")
        desc = vuln.get("root_cause", "")
        remedy = vuln.get("remediation", "")
        secure_snippet = vuln.get("secure_code_snippet", "")
        cwe_id = vuln.get("cwe_id", "")

        if cwe_id:
            title = f"{title} ({cwe_id})"

        return Finding(
            severity=severity,
            category=FindingCategory.CODE_VULNERABILITY,
            title=title,
            description=desc,
            evidence=evidence_lines,
            confidence=0.90,
            remediation=remedy,
            metadata={
                "cwe_id": cwe_id,
                "secure_code_snippet": secure_snippet,
            }
        )
