"""
Tests for NVD Client, Version Matcher, and GitHub PoC Finder.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from vigil.engine.known_vulns import lookup_known_vulns, parse_version_tuple
from vigil.engine.version_matcher import VersionMatcher
from vigil.models import ServiceVersion


def test_parse_version_tuple() -> None:
    assert parse_version_tuple("2.4.49p1") == (2, 4, 49, 1)
    assert parse_version_tuple("8.2p1-Ubuntu") == (8, 2, 1)
    assert parse_version_tuple("v1.13.0") == (1, 13, 0)
    assert parse_version_tuple("unknown") == (0,)


def test_semver_known_vulns_lookup() -> None:
    # Exact match test
    hits_49 = lookup_known_vulns("Apache HTTPd", "2.4.49")
    assert len(hits_49) == 1
    assert hits_49[0]["id"] == "CVE-2021-41773"

    # Version range test (Log4j 2.14.0 is within 2.0.0 <= v <= 2.14.1)
    log4j_hits = lookup_known_vulns("log4j", "2.14.0")
    assert len(log4j_hits) == 1
    assert log4j_hits[0]["id"] == "CVE-2021-44228"

    # Non-vulnerable version test (Log4j 2.16.0 should have 0 hits)
    safe_log4j = lookup_known_vulns("log4j", "2.16.0")
    assert len(safe_log4j) == 0


def test_version_matcher_offline_mode() -> None:
    matcher = VersionMatcher(offline_mode=True)
    services = [
        ServiceVersion(service_name="Apache httpd", version="2.4.49", host="10.10.10.10", port=80),
        ServiceVersion(service_name="vsftpd", version="2.3.4", host="10.10.10.10", port=21),
    ]

    findings = matcher.match_services(services)
    assert len(findings) == 2

    cve_ids = {f.metadata.get("cve_id") for f in findings}
    assert "CVE-2021-41773" in cve_ids
    assert "CVE-2011-2523" in cve_ids
