"""
Tests for The Compass Engine module.
"""

from __future__ import annotations

from vigil.engine.compass import CompassEngine
from vigil.models import Credential, Finding, FindingCategory, ScanResult, Severity


def test_compass_engine_report_generation() -> None:
    result = ScanResult()
    result.findings.append(
        Finding(
            severity=Severity.HIGH,
            category=FindingCategory.BRUTE_FORCE,
            title="SSH Brute Force",
            description="Failed password for root 50 times",
        )
    )
    result.credentials.append(
        Credential(
            username="admin",
            secret="password123",
            source="auth.log:42",
            context="successful_login",
        )
    )

    engine = CompassEngine()
    report = engine.generate_report(result)

    assert report.current_kill_chain_phase == "Credential Access"
    assert len(report.recommendations) >= 1
    assert "admin" in report.recommendations[0].title
    assert len(report.mitre_techniques_detected) >= 1
