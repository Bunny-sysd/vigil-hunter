"""
MITRE ATT&CK Knowledge Base & Mapping Engine.

Provides both an offline embedded database and live dynamic querying capabilities
against official MITRE ATT&CK CTI resources.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger("vigil.engine.mitre_attack")

# Tactical progression order in the MITRE ATT&CK matrix
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Database of key MITRE ATT&CK techniques with detection regex signatures
MITRE_TECHNIQUES_DB: list[dict[str, Any]] = [
    # Initial Access & Recon
    {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may execute active reconnaissance scans to gather information on host, port, or service availability.",
        "signatures": [r"nmap", r"masscan", r"nikto", r"gobuster", r"dirbuster", r"ffuf", r"sqlmap", r"wpscan"],
        "url": "https://attack.mitre.org/techniques/T1595/",
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing application to gain access.",
        "signatures": [r"CVE-\d{4}-\d+", r"UNION SELECT", r"<\s*script", r"\.\./\.\./", r"etc/passwd"],
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and use credentials of existing accounts for initial access.",
        "signatures": [r"Accepted password for", r"Accepted publickey for", r"session opened for user"],
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    # Credential Access
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force mechanisms to guess user credentials.",
        "signatures": [r"Failed password for", r"authentication failure", r"HTTP/1\.1 401", r"Invalid user"],
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search for credentials stored in insecure files, code, or environment variables.",
        "signatures": [r"api_key\s*=", r"password\s*=", r"secret_key", r"BEGIN PRIVATE KEY", r"AWS_SECRET_ACCESS_KEY"],
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from OS memory or security databases.",
        "signatures": [r"/etc/shadow", r"lsass\.exe", r"sam\.hive", r"mimikatz", r"procdump"],
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    # Execution & Persistence
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "signatures": [r"subprocess\.", r"os\.system", r"exec\(", r"eval\(", r"/bin/sh", r"/bin/bash", r"cmd\.exe", r"powershell"],
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Adversaries may abuse task scheduling functionality to execute programs at system startup or on a repeating schedule.",
        "signatures": [r"crontab", r"/etc/cron", r"schtasks", r"at\s+"],
        "url": "https://attack.mitre.org/techniques/T1053/",
    },
    {
        "id": "T1543",
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "description": "Adversaries may create or modify system services, daemons, or startup items to achieve persistence.",
        "signatures": [r"systemctl enable", r"/etc/init\.d/", r"service\s+.*start", r"systemd/system"],
        "url": "https://attack.mitre.org/techniques/T1543/",
    },
    # Privilege Escalation
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevation of privileges (SUID/SGID, sudoers, UAC).",
        "signatures": [r"chmod\s+\+s", r"chmod\s+4\d{3}", r"sudoers", r"NOPASSWD", r"GTFOBins"],
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to elevate system privileges.",
        "signatures": [r"linpeas", r"winpeas", r"kernel vulnerability", r"DirtyCOW", r"PwnKit", r"CVE-2021-4034"],
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
    # Discovery & Collection
    {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate files and directories to find sensitive data or system configurations.",
        "signatures": [r"find / -perm", r"ls -la", r"tree", r"dir /s"],
        "url": "https://attack.mitre.org/techniques/T1083/",
    },
    {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get detailed information about the operating system and hardware.",
        "signatures": [r"uname -a", r"cat /etc/os-release", r"systeminfo", r"hostnamectl"],
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
    # Lateral Movement & Exfiltration
    {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid credentials to log into remote services (SSH, RDP, SMB, WinRM).",
        "signatures": [r"ssh -i", r"rdesktop", r"evil-winrm", r"smbclient", r"psexec"],
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by transferring it over an existing command and control channel.",
        "signatures": [r"curl\s+-X\s+POST", r"wget\s+--post-data", r"nc\s+-e", r"base64\s+--encode"],
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
]


def query_mitre_live(query: str) -> dict[str, Any] | None:
    """
    Perform a live HTTP query directly to the official MITRE ATT&CK website/CTI repository.
    Falls back gracefully if offline or network unavailable.
    """
    clean_query = query.strip().upper()
    
    # Format technique ID URL e.g. T1110 -> T1110
    match = re.match(r"^(T\d{4}(?:\.\d{3})?)", clean_query)
    tech_id = match.group(1) if match else None

    if tech_id:
        url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Vigil/0.2.0 ThreatHunter"},
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                html = response.read().decode("utf-8", errors="ignore")

                # Extract Title
                title_match = re.search(r"<h1[^>]*>\s*(.*?)\s*</h1>", html, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip() if title_match else tech_id

                # Extract Description paragraph
                desc_match = re.search(r'<div class="description-body">(.*?)</div>', html, re.IGNORECASE | re.DOTALL)
                desc = desc_match.group(1).strip() if desc_match else "Live MITRE ATT&CK Technique entry."
                desc_clean = re.sub(r"<[^>]+>", "", desc).strip()

                return {
                    "id": tech_id,
                    "name": title,
                    "tactic": "Enterprise ATT&CK",
                    "description": desc_clean[:500] + "..." if len(desc_clean) > 500 else desc_clean,
                    "url": url,
                    "signatures": [],
                    "source": "live_mitre_org",
                }
        except Exception as e:
            logger.debug(f"Live MITRE query for '{tech_id}' failed ({e}). Using local database.")

    return None


def get_technique(technique_id: str, online: bool = False) -> dict[str, Any] | None:
    """
    Retrieve details for a specific MITRE ATT&CK technique by ID.
    If online=True, attempts to query attack.mitre.org directly before falling back to local DB.
    """
    tid = technique_id.upper().strip()

    if online:
        live_result = query_mitre_live(tid)
        if live_result:
            return live_result

    for tech in MITRE_TECHNIQUES_DB:
        if tech["id"] == tid or tid.startswith(tech["id"]):
            return tech
    return None


def search_techniques(query: str, online: bool = False) -> list[dict[str, Any]]:
    """Search techniques by name, ID, tactic, or keyword."""
    q = query.lower().strip()
    results = []

    if online and q.upper().startswith("T"):
        live = query_mitre_live(q)
        if live:
            results.append(live)

    for tech in MITRE_TECHNIQUES_DB:
        if (
            q in tech["id"].lower()
            or q in tech["name"].lower()
            or q in tech["tactic"].lower()
            or q in tech["description"].lower()
        ):
            if not any(r["id"] == tech["id"] for r in results):
                results.append(tech)

    return results


def match_log_to_techniques(text: str) -> list[dict[str, Any]]:
    """Scan raw text/log data and return matching MITRE ATT&CK techniques."""
    matched: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for tech in MITRE_TECHNIQUES_DB:
        if tech["id"] in seen_ids:
            continue
        for sig in tech["signatures"]:
            if re.search(sig, text, re.IGNORECASE):
                matched.append(tech)
                seen_ids.add(tech["id"])
                break

    return matched


def suggest_next_tactics(current_tactic: str) -> list[str]:
    """Given the current attack tactic, suggest the logical next tactics in the kill chain."""
    try:
        idx = TACTIC_ORDER.index(current_tactic)
        return TACTIC_ORDER[idx + 1 : min(idx + 4, len(TACTIC_ORDER))]
    except ValueError:
        return ["Initial Access", "Execution", "Privilege Escalation"]
