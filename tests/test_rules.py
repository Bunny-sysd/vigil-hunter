"""
Tests for Vigil analysis rules.
"""

from __future__ import annotations

from pathlib import Path

from vigil.engine.rules.brute_force import BruteForceRule
from vigil.engine.rules.persistence import PersistenceRule
from vigil.engine.rules.priv_escalation import PrivEscalationRule
from vigil.ingestors.auth_log import AuthLogIngestor
from vigil.ingestors.crontab_parser import CrontabParser
from vigil.models import Severity


def test_brute_force_rule() -> None:
    # Set threshold lower to match our mock fixture easily
    rule = BruteForceRule(failure_threshold=3, window_seconds=60)
    
    ingestor = AuthLogIngestor()
    fixture_path = Path(__file__).parent / "fixtures" / "auth_brute_force.log"
    entries = ingestor.ingest(fixture_path)

    findings = rule.analyze(entries)
    
    # We should have triggered:
    # 1. One active brute force finding
    # 2. One successful login/compromise finding (escalated to CRITICAL)
    assert len(findings) >= 2
    
    criticals = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(criticals) == 1
    assert "compromise" in criticals[0].title.lower()


def test_privesc_rule() -> None:
    rule = PrivEscalationRule()
    ingestor = AuthLogIngestor()
    fixture_path = Path(__file__).parent / "fixtures" / "auth_brute_force.log"
    entries = ingestor.ingest(fixture_path)

    findings = rule.analyze(entries)

    # We should have triggered a critical finding for sudo execution of /bin/bash (interpreter escape)
    assert len(findings) >= 1
    criticals = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(criticals) == 1
    assert "interpreter" in criticals[0].title.lower() or "escape" in criticals[0].title.lower()


def test_persistence_rule() -> None:
    rule = PersistenceRule()
    ingestor = CrontabParser()
    fixture_path = Path(__file__).parent / "fixtures" / "suspicious_crontab.txt"
    entries = ingestor.ingest(fixture_path)

    findings = rule.analyze(entries)

    # Should have triggered findings for the reverse shell cron job and curl downloader
    assert len(findings) >= 2
    criticals = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(criticals) == 2
    assert any("reverse shell" in c.title.lower() for c in criticals)
