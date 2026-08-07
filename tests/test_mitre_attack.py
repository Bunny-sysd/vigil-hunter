"""
Tests for MITRE ATT&CK Knowledge Base & Mapping Engine.
"""

from __future__ import annotations

from vigil.engine.mitre_attack import get_technique, match_log_to_techniques, search_techniques, suggest_next_tactics


def test_get_technique() -> None:
    tech = get_technique("T1110")
    assert tech is not None
    assert tech["name"] == "Brute Force"
    assert tech["tactic"] == "Credential Access"


def test_search_techniques() -> None:
    results = search_techniques("active scanning")
    assert len(results) >= 1
    assert results[0]["id"] == "T1595"


def test_match_log_to_techniques() -> None:
    sample_log = "Failed password for root from 192.168.1.100 port 22 ssh2"
    matched = match_log_to_techniques(sample_log)
    assert len(matched) >= 1
    assert any(t["id"] == "T1110" for t in matched)


def test_suggest_next_tactics() -> None:
    tactics = suggest_next_tactics("Reconnaissance")
    assert "Resource Development" in tactics or "Initial Access" in tactics
