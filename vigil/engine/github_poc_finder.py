"""
GitHub PoC / Exploit Repository Discovery & Quality Verification Engine.

Searches GitHub for proof-of-concept exploit repositories, verifies repository
availability, inspects README.md files for research authenticity, and ranks results.

GitHub rate limits:
    - Without token: 10 search requests per minute
    - With token:    30 search requests per minute

Set VIGIL_GITHUB_TOKEN environment variable or config for higher limits.
"""

from __future__ import annotations

import logging
import time
import urllib.parse
from typing import Any

import requests

from vigil.models import ExploitMatch

logger = logging.getLogger("vigil.engine.github_poc_finder")

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"

DEFAULT_SEARCH_DELAY = 6.5
KEYED_SEARCH_DELAY = 2.5
MAX_RETRIES = 2
VERIFY_TIMEOUT = 4


class GitHubPoCFinder:
    """
    Discovers exploit PoC repositories on GitHub for given CVE IDs or
    service+version combinations. Evaluates README quality to filter spam/fake repos.
    """

    def __init__(self, token: str = "", timeout: int = 8):
        self.token = token
        self.timeout = timeout
        self._last_search_time: float = 0.0
        self._search_delay = KEYED_SEARCH_DELAY if token else DEFAULT_SEARCH_DELAY

    def search_exploits(self, cve_id: str, max_results: int = 5) -> list[ExploitMatch]:
        if not cve_id:
            return []

        query = f"{cve_id} exploit OR poc OR proof-of-concept OR RCE"
        results = self._github_search(query, max_results)
        results.append(self._exploitdb_reference(cve_id))

        return results

    def search_by_service(self, service_name: str, version: str, max_results: int = 3) -> list[ExploitMatch]:
        if not service_name:
            return []

        query = f"{service_name} {version} exploit OR vulnerability OR RCE"
        return self._github_search(query, max_results)

    def verify_repo_url(self, url: str) -> bool:
        try:
            headers = self._build_headers()
            response = requests.head(url, headers=headers, timeout=VERIFY_TIMEOUT, allow_redirects=True)
            return response.status_code == 200
        except Exception:
            return False

    def evaluate_readme_quality(self, full_name: str) -> float:
        """
        Fetch repo README.md to score authenticity (0.0 = junk/spam, 1.0 = quality research).

        Checks for technical keywords, usage code snippets, and length.
        """
        if not full_name:
            return 0.0

        for branch in ("main", "master"):
            url = f"https://raw.githubusercontent.com/{full_name}/{branch}/README.md"
            try:
                resp = requests.get(url, timeout=3)
                if resp.status_code == 200:
                    text = resp.text
                    if len(text.strip()) < 50:
                        return 0.2  # Nearly empty README

                    score = 0.5
                    text_lower = text.lower()

                    # Technical indicators boost score
                    tech_keywords = ("usage", "cve", "poc", "exploit", "requirements", "python", "docker", "payload", "vulnerability")
                    matches = sum(1 for kw in tech_keywords if kw in text_lower)
                    score += min(0.4, matches * 0.08)

                    # Penalty for obvious spam redirects or single-line affiliate links
                    if "bit.ly" in text_lower or "t.me" in text_lower or "whatsapp" in text_lower:
                        score -= 0.4

                    return max(0.1, min(1.0, score))
            except Exception:
                continue

        return 0.5  # Neutral default if README fetch fails

    def _github_search(self, query: str, max_results: int) -> list[ExploitMatch]:
        self._rate_limit_wait()

        headers = self._build_headers()
        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": str(min(max_results, 10)),
        }

        for attempt in range(MAX_RETRIES):
            try:
                response = requests.get(
                    GITHUB_SEARCH_URL,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                )
                self._last_search_time = time.time()

                if response.status_code == 200:
                    return self._parse_search_results(response.json(), max_results)

                if response.status_code in (403, 429, 422):
                    retry_after = int(response.headers.get("Retry-After", 10))
                    logger.warning(f"GitHub rate limited. Retrying in {retry_after}s.")
                    time.sleep(retry_after)
                    continue

                return []

            except Exception as e:
                logger.debug(f"GitHub search failed: {e}")
                return []

        return []

    def _parse_search_results(self, data: dict[str, Any], max_results: int) -> list[ExploitMatch]:
        exploits: list[ExploitMatch] = []
        items = data.get("items", [])

        for item in items[:max_results]:
            full_name = item.get("full_name", "")
            html_url = item.get("html_url", "")
            description = item.get("description") or "Proof of Concept repository"
            language = (item.get("language") or "").lower()
            stars = item.get("stargazers_count", 0)

            verified = self.verify_repo_url(html_url) if html_url else False

            # Assess README quality
            readme_quality = self.evaluate_readme_quality(full_name) if verified else 0.0
            if readme_quality < 0.3 and verified:
                verified = False  # Mark unverified if README scores poorly

            exploits.append(ExploitMatch(
                source="github",
                exploit_id=full_name,
                title=description[:200] if len(description) > 200 else description,
                url=html_url,
                language=language,
                stars=stars,
                verified=verified,
            ))

        return exploits

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Vigil-Security-Engine/0.1",
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers

    def _rate_limit_wait(self) -> None:
        elapsed = time.time() - self._last_request_time
        if elapsed < self._search_delay:
            time.sleep(self._search_delay - elapsed)

    @staticmethod
    def _exploitdb_reference(cve_id: str) -> ExploitMatch:
        cve_query = urllib.parse.quote(cve_id)
        return ExploitMatch(
            source="exploitdb",
            exploit_id=f"search_{cve_id}",
            title=f"ExploitDB search for {cve_id}",
            url=f"https://www.exploit-db.com/search?cve={cve_query}",
            verified=True,
        )
