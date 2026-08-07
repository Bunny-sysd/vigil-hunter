"""
Tests for NmapTextIngestor.
"""

from __future__ import annotations

from pathlib import Path

from vigil.ingestors.nmap_text import NmapTextIngestor


def test_nmap_text_ingestor(tmp_path: Path) -> None:
    scan_file = tmp_path / "target_scan.txt"
    scan_file.write_text(
        "Nmap scan report for 10.0.0.120\n"
        "Host is up (0.013s latency).\n"
        "PORT     STATE SERVICE VERSION\n"
        "23/tcp   open  telnet  Grandstream HT-502 VoIP router telnetd 2.0A\n"
        "53/tcp   open  domain  Unbound\n"
        "80/tcp   open  http    Grandstream HT502 VoIP router http config\n",
        encoding="utf-8",
    )

    ingestor = NmapTextIngestor()
    assert ingestor.can_ingest(scan_file) is True

    entries = ingestor.ingest(scan_file)
    assert len(entries) == 3
    assert entries[0].source_ip == "10.0.0.120"
    assert entries[0].metadata["port"] == 23
    assert entries[0].metadata["service"] == "telnet"
