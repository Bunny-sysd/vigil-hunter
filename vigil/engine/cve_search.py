"""
Multi-Source Live CVE Lookup Client.

Queries multiple public vulnerability databases in real time to maximize
coverage and reduce dependence on any single API:

    1. OSV.dev (Google) — Open Source Vulnerabilities. No key required.
    2. CVEDetails.com API — Rich CVE metadata with CVSS, EPSS, references.
    3. NVD API v2.0 — Already implemented in nvd_client.py (used separately).

This module acts as a secondary enrichment layer alongside the existing
NVD client, providing broader coverage and redundancy.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import requests

logger = logging.getLogger("vigil.engine.cve_search")


# ──────────────────────────────────────────────────────────────
#  OSV.dev API (Google Open Source Vulnerabilities)
# ──────────────────────────────────────────────────────────────

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"


class OSVClient:
    """
    Client for the OSV.dev API (Google Open Source Vulnerabilities).

    No API key required. Supports package-based and version-based queries
    across multiple ecosystems (PyPI, npm, Go, Maven, Linux, etc.).
    Rate-limited to be respectful of the free public API.
    """

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self._last_request: float = 0.0
        self._min_delay: float = 0.5

    def query_by_package(
        self, package_name: str, version: str, ecosystem: str = ""
    ) -> list[dict[str, Any]]:
        """
        Query OSV for vulnerabilities affecting a specific package + version.

        Args:
            package_name: Package name (e.g., 'apache2', 'openssh').
            version: Version string (e.g., '2.4.49', '8.2p1').
            ecosystem: Optional ecosystem hint (e.g., 'PyPI', 'Debian', 'Alpine').

        Returns:
            List of simplified vulnerability dicts with CVE IDs and summaries.
        """
        if not package_name:
            return []

        payload: dict[str, Any] = {
            "package": {"name": package_name.lower().strip()},
        }

        if version:
            payload["version"] = version.strip()

        if ecosystem:
            payload["package"]["ecosystem"] = ecosystem

        return self._post_query(payload)

    def query_by_cve(self, cve_id: str) -> dict[str, Any] | None:
        """
        Retrieve detailed vulnerability information by CVE ID.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2021-44228').

        Returns:
            Vulnerability dict or None if not found.
        """
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            return None

        url = f"{OSV_VULN_URL}/{cve_id.upper()}"
        self._rate_limit()

        try:
            response = requests.get(url, timeout=self.timeout)
            self._last_request = time.time()

            if response.status_code == 200:
                data = response.json()
                return self._normalize_osv_vuln(data)
            return None

        except Exception as e:
            logger.debug(f"OSV lookup for {cve_id} failed: {e}")
            return None

    def _post_query(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Execute an OSV query and return normalized results."""
        self._rate_limit()

        try:
            response = requests.post(
                OSV_API_URL,
                json=payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )
            self._last_request = time.time()

            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                return [self._normalize_osv_vuln(v) for v in vulns[:10]]

            return []

        except Exception as e:
            logger.debug(f"OSV query failed: {e}")
            return []

    def _normalize_osv_vuln(self, vuln: dict[str, Any]) -> dict[str, Any]:
        """Normalize an OSV vulnerability record into Vigil's standard format."""
        vuln_id = vuln.get("id", "")

        # Extract CVE alias if available
        cve_id = ""
        aliases = vuln.get("aliases", [])
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_id = alias
                break
        if not cve_id:
            cve_id = vuln_id

        # Extract CVSS score from severity array
        cvss = 0.0
        severity_entries = vuln.get("severity", [])
        for sev in severity_entries:
            if sev.get("type") == "CVSS_V3":
                score_str = sev.get("score", "")
                # CVSS vector string — extract base score from it
                try:
                    # Try to parse from vector string
                    cvss = float(score_str) if score_str.replace(".", "").isdigit() else 0.0
                except (ValueError, TypeError):
                    cvss = 0.0

        summary = vuln.get("summary", vuln.get("details", ""))[:300]

        references = []
        for ref in vuln.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

        return {
            "id": cve_id,
            "cve_id": cve_id,
            "osv_id": vuln_id,
            "cvss": cvss,
            "summary": summary,
            "references": references[:5],
            "source": "osv_dev",
        }

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_request
        if elapsed < self._min_delay:
            time.sleep(self._min_delay - elapsed)


# ──────────────────────────────────────────────────────────────
#  CVEDetails.com Search (Web scraping-free, API-based approach)
# ──────────────────────────────────────────────────────────────

CVEDETAILS_API_URL = "https://www.cvedetails.com/api/v1"


class CVEDetailsClient:
    """
    Client for the CVEDetails.com public API.

    CVEDetails provides rich CVE metadata including CVSS scores, EPSS
    (Exploit Prediction Scoring System), affected product versions,
    and categorized vulnerability types.

    Note: The public API has rate limits. Use respectfully.
    """

    def __init__(self, api_key: str = "", timeout: int = 5):
        self.api_key = api_key
        self.timeout = timeout
        self._last_request: float = 0.0
        self._min_delay: float = 1.5  # Conservative rate limit

    def search_by_product(
        self, vendor: str, product: str, version: str = ""
    ) -> list[dict[str, Any]]:
        """
        Search CVEDetails for vulnerabilities by vendor/product/version.

        Args:
            vendor: Vendor name (e.g., 'apache', 'openbsd').
            product: Product name (e.g., 'http_server', 'openssh').
            version: Optional version string.

        Returns:
            List of CVE dicts with CVSS, summary, and references.
        """
        if not vendor or not product:
            return []

        params: dict[str, str] = {
            "vendor": vendor.strip().lower(),
            "product": product.strip().lower(),
        }
        if version:
            params["version"] = version.strip()

        return self._query(f"{CVEDETAILS_API_URL}/vulnerability/search", params)

    def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        """
        Retrieve detailed CVE information by ID.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2021-44228').

        Returns:
            CVE detail dict or None.
        """
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            return None

        params = {"cveId": cve_id.upper()}
        results = self._query(f"{CVEDETAILS_API_URL}/vulnerability/details", params)
        return results[0] if results else None

    def _query(self, url: str, params: dict[str, str]) -> list[dict[str, Any]]:
        """Execute a CVEDetails API query."""
        self._rate_limit()

        headers: dict[str, str] = {
            "User-Agent": "Vigil-Security-Engine/0.4",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout,
            )
            self._last_request = time.time()

            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    return [self._normalize(item) for item in data[:10]]
                elif isinstance(data, dict):
                    results = data.get("results", data.get("vulnerabilities", []))
                    if isinstance(results, list):
                        return [self._normalize(item) for item in results[:10]]
                    return [self._normalize(data)]
                return []

            if response.status_code in (403, 429):
                logger.warning("CVEDetails rate limited. Skipping.")
                return []

            return []

        except Exception as e:
            logger.debug(f"CVEDetails query failed: {e}")
            return []

    def _normalize(self, item: dict[str, Any]) -> dict[str, Any]:
        """Normalize a CVEDetails response into Vigil's standard format."""
        cve_id = item.get("cve_id", item.get("cveId", item.get("id", "")))
        cvss = item.get("cvss_score", item.get("cvssScore", item.get("cvss", 0.0)))
        summary = item.get("summary", item.get("description", ""))[:300]
        epss = item.get("epss_score", item.get("epssScore", 0.0))

        try:
            cvss = float(cvss)
        except (ValueError, TypeError):
            cvss = 0.0

        try:
            epss = float(epss)
        except (ValueError, TypeError):
            epss = 0.0

        return {
            "id": cve_id,
            "cve_id": cve_id,
            "cvss": cvss,
            "epss": epss,
            "summary": summary,
            "references": [],
            "source": "cvedetails",
        }

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_request
        if elapsed < self._min_delay:
            time.sleep(self._min_delay - elapsed)


# ──────────────────────────────────────────────────────────────
#  Unified Multi-Source CVE Search Facade
# ──────────────────────────────────────────────────────────────

# Service name to vendor/product mapping for CVEDetails lookups
SERVICE_PRODUCT_MAP: dict[str, tuple[str, str]] = {
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "apache2": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "ssh": ("openbsd", "openssh"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd_project", "proftpd"),
    "tomcat": ("apache", "tomcat"),
    "samba": ("samba", "samba"),
    "php": ("php", "php"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "docker": ("docker", "docker"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
}


class MultiSourceCVESearch:
    """
    Unified facade that queries multiple CVE databases in parallel
    and merges deduplicated results.

    Query order:
        1. OSV.dev (fastest, no key needed)
        2. CVEDetails.com (rich metadata, EPSS scores)
        3. NVD (handled separately in nvd_client.py)
    """

    def __init__(
        self,
        osv_client: OSVClient | None = None,
        cvedetails_client: CVEDetailsClient | None = None,
    ):
        self.osv = osv_client or OSVClient()
        self.cvedetails = cvedetails_client or CVEDetailsClient()

    def search_by_service(
        self, service_name: str, version: str
    ) -> list[dict[str, Any]]:
        """
        Search all configured CVE sources for vulnerabilities affecting
        a specific service and version.

        Returns:
            Deduplicated list of CVE dicts from all sources.
        """
        results: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        # 1. OSV.dev query
        try:
            osv_hits = self.osv.query_by_package(service_name, version)
            for hit in osv_hits:
                cve_id = hit.get("cve_id", hit.get("id", ""))
                if cve_id and cve_id not in seen_ids:
                    results.append(hit)
                    seen_ids.add(cve_id)
        except Exception as e:
            logger.debug(f"OSV search failed for {service_name} {version}: {e}")

        # 2. CVEDetails query (needs vendor/product mapping)
        srv_lower = service_name.lower().strip()
        mapping = SERVICE_PRODUCT_MAP.get(srv_lower)
        if mapping:
            vendor, product = mapping
            try:
                cd_hits = self.cvedetails.search_by_product(vendor, product, version)
                for hit in cd_hits:
                    cve_id = hit.get("cve_id", hit.get("id", ""))
                    if cve_id and cve_id not in seen_ids:
                        results.append(hit)
                        seen_ids.add(cve_id)
            except Exception as e:
                logger.debug(f"CVEDetails search failed for {vendor}/{product}: {e}")

        return results

    def lookup_cve(self, cve_id: str) -> dict[str, Any] | None:
        """
        Retrieve detailed CVE info from the first source that responds.
        """
        # Try OSV first (fastest, no key)
        try:
            result = self.osv.query_by_cve(cve_id)
            if result:
                return result
        except Exception:
            pass

        # Fallback to CVEDetails
        try:
            result = self.cvedetails.get_cve(cve_id)
            if result:
                return result
        except Exception:
            pass

        return None
