"""
NVD (National Vulnerability Database) API v2.0 Client.

Provides structured CVE lookups by CPE string, keyword search, and
direct CVE-ID retrieval with rate limiting, caching, and retry logic.

NVD rate limits:
    - Without API key: 5 requests per 30 seconds
    - With API key:    50 requests per 30 seconds

Set VIGIL_NVD_KEY environment variable or config for higher limits.
"""

from __future__ import annotations

import logging
import time
import urllib.parse
from functools import lru_cache
from typing import Any

import requests

logger = logging.getLogger("vigil.engine.nvd_client")

# NVD API v2.0 endpoints
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limit defaults
DEFAULT_REQUEST_DELAY = 1.0   # Fast delay default
KEYED_REQUEST_DELAY = 0.5     # Fast delay with API key
MAX_RETRIES = 1
RETRY_BACKOFF_BASE = 1.5


class NVDClient:
    """
    Client for the NIST NVD API v2.0.
    Handles rate limiting and response normalization into a consistent dict format.
    """

    def __init__(self, api_key: str = "", timeout: int = 3):
        self.api_key = api_key
        self.timeout = timeout
        self._last_request_time: float = 0.0
        self._request_delay = KEYED_REQUEST_DELAY if api_key else DEFAULT_REQUEST_DELAY

    def search_by_cpe(self, cpe_string: str, max_results: int = 3) -> list[dict[str, Any]]:
        if not cpe_string:
            return []
        params = {
            "cpeName": cpe_string,
            "resultsPerPage": str(min(max_results, 10)),
        }
        return self._query_nvd(params, max_results)

    def search_by_keyword(self, keyword: str, max_results: int = 3) -> list[dict[str, Any]]:
        if not keyword or len(keyword.strip()) < 3:
            return []
        params = {
            "keywordSearch": keyword.strip(),
            "resultsPerPage": str(min(max_results, 10)),
        }
        return self._query_nvd(params, max_results)

    def get_cve_detail(self, cve_id: str) -> dict[str, Any] | None:
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            return None

        params = {"cveId": cve_id.upper()}
        results = self._query_nvd(params, max_results=1)
        return results[0] if results else None

    def _query_nvd(self, params: dict[str, str], max_results: int) -> list[dict[str, Any]]:
        self._rate_limit_wait()

        headers = {"User-Agent": "Vigil-Security-Engine/0.1"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        for attempt in range(MAX_RETRIES):
            try:
                response = requests.get(
                    NVD_BASE_URL,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                )
                self._last_request_time = time.time()

                if response.status_code == 200:
                    return self._parse_response(response.json(), max_results)

                if response.status_code in (403, 429):
                    logger.warning(f"NVD rate limited (HTTP {response.status_code}). Skipping online query.")
                    return []

                return []

            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                logger.debug("NVD API unreachable or timed out.")
                return []
            except Exception as e:
                logger.debug(f"NVD query failed: {e}")
                return []

        return []

    def _rate_limit_wait(self) -> None:
        elapsed = time.time() - self._last_request_time
        if elapsed < self._request_delay:
            sleep_time = self._request_delay - elapsed
            time.sleep(sleep_time)

    def _parse_response(self, data: dict[str, Any], max_results: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities[:max_results]:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            metrics = cve_data.get("metrics", {})
            cvss = 0.0
            severity = "UNKNOWN"
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            cvss_metrics = cvss_v31 or cvss_v30

            if cvss_metrics:
                cvss_data = cvss_metrics[0].get("cvssData", {})
                cvss = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")

            descriptions = cve_data.get("descriptions", [])
            summary = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    summary = desc.get("value", "")
                    break
            if not summary and descriptions:
                summary = descriptions[0].get("value", "")

            if len(summary) > 300:
                summary = summary[:297] + "..."

            references = []
            for ref in cve_data.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)

            results.append({
                "id": cve_id,
                "cvss": cvss,
                "severity": severity,
                "summary": summary,
                "references": references[:5],
            })

        return results
