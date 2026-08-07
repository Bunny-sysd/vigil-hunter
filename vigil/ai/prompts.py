"""
System prompts and structured schemas for Vigil's AI features.

These prompts configure the behavior of LLMs, ensuring strict evidence-grounding,
anti-hallucination guardrails, and professional formatting.
"""

from __future__ import annotations

# ──────────────────────────────────────────────────────────────
#  1. Red Team Compass & Pentest Tactical Advisor
# ──────────────────────────────────────────────────────────────

RED_TEAM_COMPASS_SYSTEM = """
You are a Principal Security Consultant, Red Team Strategist, and Lead Penetration Tester.

YOUR MISSION:
- Analyze the provided target scan data, service banners, open ports, web headers, and security findings.
- Apply standard Penetration Testing Frameworks (PTES, OWASP, MITRE ATT&CK, NIST).
- Determine the target's current Kill-Chain Phase (Reconnaissance, Initial Access, Credential Access, Privilege Escalation, Lateral Movement).
- Identify high-priority attack surface vectors and configuration risks.
- Provide a prioritized, step-by-step pentesting directive containing concrete verification commands.

CRITICAL COMPLIANCE & HONESTY RULES:
1. DO NOT invent, hallucinate, or force fake security vulnerabilities or CVEs if none are present in the provided target data.
2. If the target scan or logs show NO security issues or open vulnerable vectors, explicitly report:
   "No security vulnerabilities or threat signatures detected on target." and set threat_level to "LOW".
3. ONLY reference services, versions, ports, and headers directly present in the provided target data.
4. Be precise, highly technical, professional, and thorough.
"""

RED_TEAM_COMPASS_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "kill_chain_phase": {
            "type": "STRING",
            "description": "Reconnaissance | Initial Access | Credential Access | Privilege Escalation | Lateral Movement"
        },
        "threat_level": {
            "type": "STRING",
            "description": "CRITICAL | HIGH | MEDIUM | LOW"
        },
        "strategic_summary": {
            "type": "STRING",
            "description": "Detailed strategic assessment of the target's attack surface or clean status declaration."
        },
        "tactical_next_steps": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "priority": {"type": "INTEGER", "description": "1 = Highest Priority"},
                    "title": {"type": "STRING", "description": "Short title of the tactical directive"},
                    "phase": {"type": "STRING", "description": "MITRE ATT&CK Phase"},
                    "description": {"type": "STRING", "description": "Detailed explanation of the vulnerability or risk"},
                    "command_template": {"type": "STRING", "description": "Standard CLI command template for auditing"},
                    "tool": {"type": "STRING", "description": "Recommended tool (nmap, gobuster, hydra, etc.)"},
                    "target": {"type": "STRING", "description": "Target IP, domain, or port"}
                },
                "required": ["priority", "title", "phase", "description", "command_template", "tool"]
            }
        },
        "mitre_techniques": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "id": {"type": "STRING", "description": "MITRE Technique ID (e.g. T1595)"},
                    "name": {"type": "STRING", "description": "Technique Name"},
                    "tactic": {"type": "STRING", "description": "ATT&CK Tactic"}
                },
                "required": ["id", "name", "tactic"]
            }
        },
        "remediation_checklist": {
            "type": "ARRAY",
            "items": {"type": "STRING"},
            "description": "Defensive hardening checklist for blue teams."
        }
    },
    "required": ["kill_chain_phase", "threat_level", "strategic_summary", "tactical_next_steps", "mitre_techniques", "remediation_checklist"]
}

# ──────────────────────────────────────────────────────────────
#  2. General Threat Forensics & Timeline Narrative
# ──────────────────────────────────────────────────────────────

THREAT_FORENSICS_SYSTEM = """
You are a Lead Incident Response Analyst investigating log files to detect compromise.

YOUR MISSION:
- Review the security findings and raw log excerpts.
- Synthesize them into a clear, unified narrative explaining what the attacker did, how they got in, and what their likely objective was.
- Group findings chronologically.
- Map the attacks to MITRE ATT&CK tactics (e.g. Initial Access, Persistence, Privilege Escalation).
- Suggest immediate defense remediation steps (firewall blocks, credential rotation, log auditing).

CRITICAL COMPLIANCE RULES:
1. ONLY report findings based on direct evidence in the log inputs.
2. NEVER invent IP addresses, hostnames, usernames, or timestamps.
3. If logs show no evidence of compromise, explicitly report "No suspicious activity detected."
4. Be precise, technical, and objective.
"""

THREAT_FORENSICS_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "overall_summary": {
            "type": "STRING",
            "description": "Executive summary of the attack timeline and impact."
        },
        "attack_chain_steps": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "timestamp": {"type": "STRING", "description": "ISO timestamp or log date format"},
                    "phase": {"type": "STRING", "description": "MITRE ATT&CK Phase"},
                    "description": {"type": "STRING", "description": "Detail of the action"},
                    "attacker_ip": {"type": "STRING", "description": "Attacker IP if known"}
                },
                "required": ["timestamp", "phase", "description"]
            }
        },
        "likely_objective": {
            "type": "STRING",
            "description": "The attacker's probable objective (e.g., exfiltration, persistence, lateral movement)."
        },
        "remediation_checklist": {
            "type": "ARRAY",
            "items": {"type": "STRING"},
            "description": "Actionable checklist of defensive remediations."
        }
    },
    "required": ["overall_summary", "attack_chain_steps", "likely_objective", "remediation_checklist"]
}

# ──────────────────────────────────────────────────────────────
#  3. Email Phishing & Conversation Intelligence
# ──────────────────────────────────────────────────────────────

EMAIL_ANALYSIS_SYSTEM = """
You are a Mail Security Specialist and Social Engineering Auditor.

YOUR MISSION:
- Read raw email headers and the email body/thread.
- Identify phishing, spoofing, social engineering, or credential harvesting.
- Analyze header routing to detect hop manipulation.
- Read conversation threads to identify:
  - Who is trying to manipulate whom.
  - What sensitive items (passwords, server configs, internal URLs) have been leaked or requested.
  - The psychological triggers used (urgency, authority, fear).

CRITICAL COMPLIANCE RULES:
- Ground all analysis strictly in the provided email text.
- Do not assume external threat actor identities unless indicated by metadata.
"""

EMAIL_ANALYSIS_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "is_suspicious": {"type": "BOOLEAN"},
        "threat_category": {"type": "STRING", "description": "e.g. Phishing, Spearphishing, Social Engineering, None"},
        "confidence_score": {"type": "NUMBER", "description": "Confidence from 0.0 to 1.0"},
        "indicators": {
            "type": "ARRAY",
            "items": {"type": "STRING"},
            "description": "Leaked indicators (homoglyph domains, spoofed headers, urgency language, attachment extensions)"
        },
        "sensitive_info_disclosed": {
            "type": "ARRAY",
            "items": {"type": "STRING"},
            "description": "Any passwords, internal hostnames, or credentials disclosed in the conversation thread"
        },
        "attacker_tactics": {
            "type": "ARRAY",
            "items": {"type": "STRING"},
            "description": "Psychological triggers or delivery mechanisms used"
        },
        "summary_of_interaction": {
            "type": "STRING",
            "description": "Brief description of the interaction and the email thread flow."
        }
    },
    "required": ["is_suspicious", "threat_category", "confidence_score", "indicators", "sensitive_info_disclosed", "attacker_tactics", "summary_of_interaction"]
}

# ──────────────────────────────────────────────────────────────
#  4. Source Code Vulnerability Auditor (SAST)
# ──────────────────────────────────────────────────────────────

CODE_AUDIT_SYSTEM = """
You are a Secure Static Application Security Testing (SAST) Engine.

YOUR MISSION:
- Review the provided source code for programming security vulnerabilities (CWE).
- Identify injection points, path traversals, insecure deserialization, template injections, etc.
- Detail the exact line number, root cause, and how the vulnerability can theoretically manifest.
- Provide a clean, secure code replacement showing how to fix/remediate the issue (parameterized queries, input validation, safe deserializers).

CRITICAL SAFETY & DEFENSIVE RULES:
1. DO NOT generate actionable exploit scripts or ready-to-run weaponized payloads designed to compromise systems.
2. Focus primarily on the CODE MECHANICS, the ROOT CAUSE, and the CORRECTIVE REFACTOR.
3. Every finding MUST include the specific lines of code as evidence.
"""

CODE_AUDIT_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "vulnerabilities": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "title": {"type": "STRING", "description": "Vulnerability name (e.g. SQL Injection)"},
                    "severity": {"type": "STRING", "description": "CRITICAL | HIGH | MEDIUM | LOW"},
                    "cwe_id": {"type": "STRING", "description": "CWE-XX identifier"},
                    "file_path": {"type": "STRING"},
                    "line_start": {"type": "INTEGER"},
                    "line_end": {"type": "INTEGER"},
                    "root_cause": {"type": "STRING", "description": "Description of why the code is unsafe."},
                    "remediation": {"type": "STRING", "description": "Instruction on how to secure the code."},
                    "secure_code_snippet": {"type": "STRING", "description": "Corrected code snippet demonstrating the fix."}
                },
                "required": ["title", "severity", "cwe_id", "line_start", "line_end", "root_cause", "remediation", "secure_code_snippet"]
            }
        }
    },
    "required": ["vulnerabilities"]
}

# ──────────────────────────────────────────────────────────────
#  5. PEASS Privilege Escalation Output Analyzer
# ──────────────────────────────────────────────────────────────

PEASS_ANALYSIS_SYSTEM = """
You are a Threat Hunter and Post-Exploitation Forensics Analyst.

YOUR MISSION:
- Review the parsed section of linPEAS or winPEAS output.
- Identify paths for privilege escalation (SUID binaries, writable configs, vulnerable kernel version, active services, credentials).
- Filter out benign configuration items and false positives.
- Prioritize findings based on how standard, reliable, and non-destructive the escalation path is.
- Suggest next steps to safely audit or test the finding, providing standard command templates.

CRITICAL COMPLIANCE RULES:
1. DO NOT fabricate commands that cause permanent system destruction.
2. Structure recommendations clearly, highlighting risk levels and references.
"""

PEASS_ANALYSIS_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "privesc_paths": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "technique": {"type": "STRING", "description": "The category (e.g., SUID binary / Writable file)"},
                    "description": {"type": "STRING", "description": "Detail of the potential escalation path."},
                    "verification_command": {"type": "STRING", "description": "Standard command to check exploitability."},
                    "remediation_command": {"type": "STRING", "description": "How to fix the configuration leak."},
                    "confidence_score": {"type": "NUMBER", "description": "Confidence from 0.0 to 1.0"},
                    "risk_level": {"type": "STRING", "description": "low | medium | high risk of crash/disruption"},
                    "reference": {"type": "STRING", "description": "GTFOBins link or reference CVE URL"}
                },
                "required": ["technique", "description", "verification_command", "remediation_command", "confidence_score", "risk_level"]
            }
        }
    },
    "required": ["privesc_paths"]
}
