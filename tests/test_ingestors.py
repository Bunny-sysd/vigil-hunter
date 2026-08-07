"""
Tests for Vigil log file ingestors.
"""

from __future__ import annotations

from pathlib import Path

from vigil.ingestors.auth_log import AuthLogIngestor
from vigil.ingestors.crontab_parser import CrontabParser
from vigil.models import LogType


def test_auth_log_ingestion() -> None:
    ingestor = AuthLogIngestor()
    fixture_path = Path(__file__).parent / "fixtures" / "auth_brute_force.log"
    
    assert ingestor.can_ingest(fixture_path) is True
    
    entries = ingestor.ingest(fixture_path)
    # We have 7 lines of events in the log fixture
    assert len(entries) == 7
    
    # Check failed login parsing
    failed_attempts = [e for e in entries if e.action == "ssh_login_failed"]
    assert len(failed_attempts) == 5
    for att in failed_attempts:
        assert att.source_ip == "10.10.14.5"
        assert att.username == "admin"

    # Check successful login parsing
    success_login = [e for e in entries if e.action == "ssh_login_success"]
    assert len(success_login) == 1
    assert success_login[0].username == "admin"
    assert success_login[0].source_ip == "10.10.14.5"

    # Check sudo elevation parsing
    sudo_cmds = [e for e in entries if e.action == "sudo_command"]
    assert len(sudo_cmds) == 1
    assert sudo_cmds[0].username == "admin"
    assert sudo_cmds[0].metadata.get("target_user") == "root"
    assert sudo_cmds[0].metadata.get("command") == "/bin/bash"


def test_crontab_ingestion() -> None:
    ingestor = CrontabParser()
    fixture_path = Path(__file__).parent / "fixtures" / "suspicious_crontab.txt"

    assert ingestor.can_ingest(fixture_path) is True

    entries = ingestor.ingest(fixture_path)
    # We should have parsed 4 cron jobs (skipping blank, comments, and env lines)
    assert len(entries) == 4

    # Verify parsed schedules
    schedules = [e.metadata.get("schedule") for e in entries]
    assert "*/5 * * * *" in schedules
    assert "0 */6 * * *" in schedules
