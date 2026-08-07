"""
Tests for Universal Log Ingestor module.
"""

from __future__ import annotations

from pathlib import Path

from vigil.ingestors.universal_log import UniversalLogIngestor


def test_universal_log_ingestor(tmp_path: Path) -> None:
    custom_log = tmp_path / "custom_app.log"
    custom_log.write_text(
        "2026-07-21 14:00:00 [ERROR] User admin failed login from 10.0.0.50\n"
        "2026-07-21 14:01:00 [INFO] Process executed by user root\n",
        encoding="utf-8",
    )

    ingestor = UniversalLogIngestor()
    assert ingestor.can_ingest(custom_log) is True

    entries = ingestor.ingest(custom_log)
    assert len(entries) == 2
    assert entries[0].source_ip == "10.0.0.50"
    assert entries[0].username == "admin"
    assert entries[0].action == "failed"
