"""
Tests for DiffEngine.
"""

from __future__ import annotations

from vigil.engine.diff_engine import DiffEngine
from vigil.models import Finding, FindingCategory, ScanResult, ServiceVersion, Severity


def test_diff_engine_added_and_removed_services() -> None:
    res1 = ScanResult()
    res1.services.append(ServiceVersion(service_name="http", version="2.4.49", host="10.0.0.1", port=80))
    res1.services.append(ServiceVersion(service_name="telnet", version="1.0", host="10.0.0.1", port=23))

    res2 = ScanResult()
    res2.services.append(ServiceVersion(service_name="http", version="2.4.50", host="10.0.0.1", port=80))  # Modified
    res2.services.append(ServiceVersion(service_name="ssh", version="8.2", host="10.0.0.1", port=22))     # Added
    # Telnet removed

    engine = DiffEngine()
    diff = engine.compare_scans(res1, res2)

    assert len(diff.added_services) == 1
    assert diff.added_services[0].port == 22
    assert diff.added_services[0].change_type == "ADDED"

    assert len(diff.removed_services) == 1
    assert diff.removed_services[0].port == 23
    assert diff.removed_services[0].change_type == "REMOVED"

    assert len(diff.changed_services) == 1
    assert diff.changed_services[0].port == 80
    assert diff.changed_services[0].old_version == "http 2.4.49"
    assert diff.changed_services[0].new_version == "http 2.4.50"


def test_diff_engine_findings() -> None:
    res1 = ScanResult()
    res1.findings.append(Finding(title="Vulnerable Apache", description="Path traversal", severity=Severity.HIGH, category=FindingCategory.VULNERABILITY))

    res2 = ScanResult()
    res2.findings.append(Finding(title="SSH Weak Password", description="Brute force", severity=Severity.CRITICAL, category=FindingCategory.BRUTE_FORCE))

    engine = DiffEngine()
    diff = engine.compare_scans(res1, res2)

    assert len(diff.new_findings) == 1
    assert diff.new_findings[0].title == "SSH Weak Password"

    assert len(diff.resolved_findings) == 1
    assert diff.resolved_findings[0].title == "Vulnerable Apache"
