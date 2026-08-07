"""
Tests for SourceAuditor SAST scanning.
"""

from __future__ import annotations

from pathlib import Path

from vigil.engine.source_auditor import SourceAuditor
from vigil.models import Severity


def test_source_auditor_sast() -> None:
    auditor = SourceAuditor(ai_brain=None)
    sample_path = Path(__file__).parent / "fixtures" / "vulnerable_sample.py"

    findings = auditor.audit_file(sample_path)
    assert len(findings) >= 5

    titles = [f.title.lower() for f in findings]
    
    # Check that each vulnerability class was detected
    assert any("secret" in t or "key" in t for t in titles)
    assert any("shell execution" in t or "cwe-78" in t for t in titles)
    assert any("sql injection" in t or "cwe-89" in t for t in titles)
    assert any("deserialization" in t or "cwe-502" in t for t in titles)
    assert any("weak cryptographic" in t or "cwe-327" in t for t in titles)
