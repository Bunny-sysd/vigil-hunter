"""
Semantic & Fuzzy Vulnerability Database & Version Comparator.

Implements robust semantic version matching (SemVer + packaging rules)
instead of primitive string matching.
"""

from __future__ import annotations

import re
from typing import Any


def parse_version_tuple(ver_str: str) -> tuple[int, ...]:
    """
    Extract clean numeric version components from banner strings.

    Examples:
        "2.4.49p1" -> (2, 4, 49)
        "8.2p1-Ubuntu" -> (8, 2, 1)
        "v1.13.0" -> (1, 13, 0)
    """
    nums = re.findall(r"\d+", ver_str)
    if not nums:
        return (0,)
    return tuple(int(n) for n in nums[:4])


# ──────────────────────────────────────────────────────────────
#  Structured Known Vulnerability Registry with Version Constraints
# ──────────────────────────────────────────────────────────────

STRUCTURED_VULN_DB: list[dict[str, Any]] = [
    {
        "service_aliases": ["apache", "httpd", "apache httpd", "apache2"],
        "min_version": (2, 4, 49),
        "max_version": (2, 4, 49),
        "cve_id": "CVE-2021-41773",
        "cvss": 7.5,
        "summary": "Path traversal and file disclosure in Apache HTTP Server 2.4.49 via unnormalized URL paths.",
        "exploits": [
            "https://github.com/blasty/CVE-2021-41773",
            "https://www.exploit-db.com/exploits/50383",
        ],
    },
    {
        "service_aliases": ["apache", "httpd", "apache httpd", "apache2"],
        "min_version": (2, 4, 50),
        "max_version": (2, 4, 50),
        "cve_id": "CVE-2021-42013",
        "cvss": 9.8,
        "summary": "Path traversal and RCE in Apache HTTP Server 2.4.50 (incomplete fix for CVE-2021-41773).",
        "exploits": [
            "https://github.com/inbug-team/CVE-2021-42013",
            "https://www.exploit-db.com/exploits/50406",
        ],
    },
    {
        "service_aliases": ["vsftpd"],
        "min_version": (2, 3, 4),
        "max_version": (2, 3, 4),
        "cve_id": "CVE-2011-2523",
        "cvss": 10.0,
        "summary": "vsftpd 2.3.4 backdoor command execution via ':)' string in username.",
        "exploits": [
            "https://www.exploit-db.com/exploits/17491",
            "https://github.com/ahervias77/vsftpd-2.3.4-exploit",
        ],
    },
    {
        "service_aliases": ["proftpd"],
        "min_version": (1, 3, 5),
        "max_version": (1, 3, 5),
        "cve_id": "CVE-2015-3306",
        "cvss": 10.0,
        "summary": "ProFTPD 1.3.5 mod_copy unauthenticated file copy & command execution.",
        "exploits": [
            "https://www.exploit-db.com/exploits/36742",
        ],
    },
    {
        "service_aliases": ["openssh", "ssh"],
        "min_version": (8, 2, 0),
        "max_version": (8, 2, 9),
        "cve_id": "CVE-2020-15778",
        "cvss": 6.8,
        "summary": "scp command injection in OpenSSH 8.2p1 via shell expansion.",
        "exploits": [],
    },
    {
        "service_aliases": ["openssh", "ssh"],
        "min_version": (9, 1, 0),
        "max_version": (9, 3, 1),
        "cve_id": "CVE-2023-38408",
        "cvss": 9.8,
        "summary": "PKCS#11 remote code execution in ssh-agent forwarding.",
        "exploits": [],
    },
    {
        "service_aliases": ["samba", "smb"],
        "min_version": (3, 5, 0),
        "max_version": (4, 6, 4),
        "cve_id": "CVE-2017-7494",
        "cvss": 9.8,
        "summary": "SambaCry — remote code execution via shared library upload.",
        "exploits": [
            "https://github.com/joxeankoret/CVE-2017-7494",
            "https://www.exploit-db.com/exploits/42084",
        ],
    },
    {
        "service_aliases": ["tomcat"],
        "min_version": (9, 0, 0),
        "max_version": (9, 0, 30),
        "cve_id": "CVE-2020-1938",
        "cvss": 9.8,
        "summary": "Ghostcat — Apache Tomcat AJP connector arbitrary file read / LFI.",
        "exploits": [
            "https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi",
            "https://www.exploit-db.com/exploits/48143",
        ],
    },
    {
        "service_aliases": ["log4j", "log4j2"],
        "min_version": (2, 0, 0),
        "max_version": (2, 14, 1),
        "cve_id": "CVE-2021-44228",
        "cvss": 10.0,
        "summary": "Log4Shell — unauthenticated JNDI injection RCE in Apache Log4j 2.x.",
        "exploits": [
            "https://github.com/kozmer/log4j-shell-poc",
            "https://github.com/fullhunt/log4j-scan",
        ],
    },
    {
        "service_aliases": ["sudo"],
        "min_version": (1, 9, 0),
        "max_version": (1, 9, 5),
        "cve_id": "CVE-2021-3156",
        "cvss": 7.8,
        "summary": "Baron Samedit — heap-based buffer overflow in sudo for local privilege escalation.",
        "exploits": [
            "https://github.com/blasty/CVE-2021-3156",
        ],
    },
    {
        "service_aliases": ["polkit", "pkexec"],
        "min_version": (0, 105, 0),
        "max_version": (0, 120, 0),
        "cve_id": "CVE-2021-4034",
        "cvss": 7.8,
        "summary": "PwnKit — local privilege escalation via pkexec in polkit.",
        "exploits": [
            "https://github.com/ly4k/PwnKit",
            "https://www.exploit-db.com/exploits/50689",
        ],
    },
    {
        "service_aliases": ["php"],
        "min_version": (8, 1, 0),
        "max_version": (8, 1, 28),
        "cve_id": "CVE-2024-4577",
        "cvss": 9.8,
        "summary": "PHP-CGI argument injection leading to RCE on Windows servers.",
        "exploits": [
            "https://github.com/watchtowrlabs/CVE-2024-4577",
        ],
    },
]


def lookup_known_vulns(service_name: str, version: str) -> list[dict[str, Any]]:
    """
    Perform semantic version range matching against the structured vulnerability database.

    Args:
        service_name: Service banner or product name.
        version: Target version string.

    Returns:
        List of matching CVE dictionaries.
    """
    results: list[dict[str, Any]] = []
    srv_lower = service_name.lower().strip()
    target_ver = parse_version_tuple(version)

    if not srv_lower or target_ver == (0,):
        return results

    for entry in STRUCTURED_VULN_DB:
        # Check service alias match
        if not any(alias in srv_lower or srv_lower in alias for alias in entry["service_aliases"]):
            continue

        min_v = entry["min_version"]
        max_v = entry["max_version"]

        # Normalize comparison tuples to equal length
        max_len = max(len(target_ver), len(min_v), len(max_v))
        t_norm = target_ver + (0,) * (max_len - len(target_ver))
        min_norm = min_v + (0,) * (max_len - len(min_v))
        max_norm = max_v + (0,) * (max_len - len(max_v))

        # Check version range condition
        if min_norm <= t_norm <= max_norm:
            results.append({
                "id": entry["cve_id"],
                "cvss": entry["cvss"],
                "summary": entry["summary"],
                "exploits": entry["exploits"],
            })

    return results
