"""
Dynamic Version-to-Exploit Matcher.

Correlates discovered ServiceVersion objects against live vulnerability feeds,
local known-vuln databases, and exploit repositories in real time.

This is the central orchestrator that composes NVDClient, GitHubPoCFinder,
MultiSourceCVESearch (OSV.dev + CVEDetails), and the known_vulns fallback
database to produce enriched vulnerability data.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from vigil.engine.cve_search import MultiSourceCVESearch
from vigil.engine.github_poc_finder import GitHubPoCFinder
from vigil.engine.known_vulns import lookup_known_vulns
from vigil.engine.nvd_client import NVDClient
from vigil.models import (
    ExploitMatch,
    Finding,
    FindingCategory,
    LogEntry,
    LogType,
    ServiceVersion,
    Severity,
)

logger = logging.getLogger("vigil.engine.version_matcher")

# Map CVSS score to Severity enum
CVSS_SEVERITY_MAP = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
]


class VersionMatcher:
    """
    Matches discovered services against vulnerability databases and produces
    enriched CVE data with linked exploit PoCs.
    """

    def __init__(
        self,
        nvd_client: NVDClient | None = None,
        poc_finder: GitHubPoCFinder | None = None,
        cve_search: MultiSourceCVESearch | None = None,
        cvss_threshold: float = 4.0,
        offline_mode: bool = False,
    ):
        self.nvd_client = nvd_client
        self.poc_finder = poc_finder
        self.cve_search = cve_search or (MultiSourceCVESearch() if not offline_mode else None)
        self.cvss_threshold = cvss_threshold
        self.offline_mode = offline_mode

    def match_services(self, services: list[ServiceVersion]) -> list[Finding]:
        """
        Enrich each ServiceVersion with CVE matches and exploit links.
        Returns Finding objects for notable vulnerabilities.
        """
        findings: list[Finding] = []
        seen_cves: set[str] = set()

        for srv in services:
            try:
                cve_matches = self._lookup_cves_for_service(srv)

                # Deduplicate across services
                unique_cves = []
                for cve in cve_matches:
                    cve_id = cve.get("id") or cve.get("cve_id", "")
                    if cve_id and cve_id not in seen_cves:
                        seen_cves.add(cve_id)
                        unique_cves.append(cve)

                # Enrich with exploit PoCs
                for cve in unique_cves:
                    cve_id = cve.get("id") or cve.get("cve_id", "")
                    exploits = self._find_exploits(cve_id, srv.service_name)
                    cve["exploits"] = [e.to_dict() for e in exploits]

                # Filter by CVSS threshold
                filtered = [c for c in unique_cves if c.get("cvss", 0) >= self.cvss_threshold]
                srv.cve_matches.extend(filtered)

                # Generate findings for significant CVEs
                for cve in filtered:
                    finding = self._cve_to_finding(cve, srv)
                    if finding:
                        findings.append(finding)

            except Exception as e:
                logger.error(f"Version matching failed for {srv.service_name} {srv.version}: {e}")

        return findings

    def _lookup_cves_for_service(self, srv: ServiceVersion) -> list[dict[str, Any]]:
        """Look up CVEs for a service using local known_vulns database and optional NVD API."""
        results: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        # Layer 1: Local known vulnerabilities (always available, no network)
        local_hits = lookup_known_vulns(srv.service_name, srv.version)
        for hit in local_hits:
            cve_id = hit.get("cve_id") or hit.get("id", "")
            if cve_id and cve_id not in seen_ids:
                results.append({
                    "id": cve_id,
                    "cve_id": cve_id,
                    "cvss": hit.get("cvss", 0.0),
                    "summary": hit.get("summary", ""),
                    "references": hit.get("exploits", []),
                    "source": "local_db",
                })
                seen_ids.add(cve_id)

        # Layer 2: OSV.dev + CVEDetails (skip in offline mode)
        if not self.offline_mode and self.cve_search:
            try:
                multi_hits = self.cve_search.search_by_service(srv.service_name, srv.version)
                for hit in multi_hits:
                    cve_id = hit.get("cve_id") or hit.get("id", "")
                    if cve_id and cve_id not in seen_ids:
                        hit["id"] = cve_id
                        hit["cve_id"] = cve_id
                        results.append(hit)
                        seen_ids.add(cve_id)
            except Exception as e:
                logger.debug(f"Multi-source CVE search failed for {srv.service_name}: {e}")

        # Layer 3: NVD API (skip in offline mode)
        if not self.offline_mode and self.nvd_client:
            nvd_results = []

            if srv.cpe:
                nvd_results = self.nvd_client.search_by_cpe(srv.cpe, max_results=5)

            if not nvd_results:
                cpe_str = self._build_cpe_string(srv.service_name, srv.version)
                if cpe_str:
                    nvd_results = self.nvd_client.search_by_cpe(cpe_str, max_results=5)

            if not nvd_results:
                keyword = f"{srv.service_name} {srv.version}"
                nvd_results = self.nvd_client.search_by_keyword(keyword, max_results=5)

            for nvd_cve in nvd_results:
                cve_id = nvd_cve.get("id") or nvd_cve.get("cve_id", "")
                if cve_id and cve_id not in seen_ids:
                    nvd_cve["source"] = "nvd_api"
                    nvd_cve["cve_id"] = cve_id
                    nvd_cve["id"] = cve_id
                    results.append(nvd_cve)
                    seen_ids.add(cve_id)

        return results

    def _find_exploits(self, cve_id: str, service_name: str) -> list[ExploitMatch]:
        """Search GitHub PoCFinder if available."""
        if not self.poc_finder or self.offline_mode:
            return []
        try:
            return self.poc_finder.search_exploits(cve_id, max_results=3)
        except Exception as e:
            logger.debug(f"Exploit search failed for {cve_id}: {e}")
            return []

    def _cve_to_finding(self, cve: dict[str, Any], srv: ServiceVersion) -> Finding:
        """Convert a raw CVE dictionary into a rich Finding object."""
        cve_id = cve.get("id") or cve.get("cve_id", "CVE-UNKNOWN")
        cvss = cve.get("cvss", 0.0)
        summary = cve.get("summary", "Known vulnerability detected.")

        severity = Severity.LOW
        for threshold, sev in CVSS_SEVERITY_MAP:
            if cvss >= threshold:
                severity = sev
                break

        exploits = cve.get("exploits", [])
        exploit_urls = [e.get("url", "") for e in exploits if isinstance(e, dict) and e.get("url")]

        return Finding(
            severity=severity,
            category=FindingCategory.VULNERABILITY,
            title=f"Vulnerability Discovered: {cve_id} in {srv.service_name} {srv.version}",
            description=(
                f"Detected vulnerable service banner: {srv.service_name} {srv.version} on port {srv.port}.\n"
                f"CVE ID: {cve_id} (CVSS Score: {cvss})\n"
                f"Summary: {summary}"
            ),
            attack_technique="T1190",
            attack_technique_name="Exploit Public-Facing Application",
            confidence=0.9,
            remediation=f"Upgrade {srv.service_name} from version {srv.version} to a patched release.",
            exploitation_path=f"Attacker can search for public PoC exploits for {cve_id} and target port {srv.port}.",
            references=cve.get("references", []) + exploit_urls,
            metadata={"cve_id": cve_id, "cvss": cvss, "service": srv.service_name, "version": srv.version, "port": srv.port},
        )

    def _build_cpe_string(self, service_name: str, version: str) -> str:
        """Build CPE 2.3 formatted string."""
        s = service_name.lower().strip()
        v = version.strip()
        cpe_map = {
            "apache": "cpe:2.3:a:apache:http_server",
            "apache httpd": "cpe:2.3:a:apache:http_server",
            "httpd": "cpe:2.3:a:apache:http_server",
            "openssh": "cpe:2.3:a:openbsd:openssh",
            "nginx": "cpe:2.3:a:f5:nginx",
            "mysql": "cpe:2.3:a:oracle:mysql",
            "vsftpd": "cpe:2.3:a:vsftpd_project:vsftpd",
        }
        prefix = cpe_map.get(s, "")
        return f"{prefix}:{v}" if prefix else ""
