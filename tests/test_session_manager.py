"""
Tests for SessionManager.
"""

from __future__ import annotations

from pathlib import Path
from vigil.engine.blackboard import BlackboardMemory, HandoffNote
from vigil.engine.session_manager import SessionManager


def test_session_manager_save_and_load(tmp_path: Path) -> None:
    sm = SessionManager(sessions_dir=tmp_path)

    mem = BlackboardMemory(session_id="acme_corp", storage_dir=tmp_path)
    mem.add_handoff(
        HandoffNote(
            source_agent="ReconAgent",
            target_agent="InitialAccessAgent",
            phase_completed="reconnaissance",
            key_findings=["dnsmasq on 53"],
        )
    )

    path = sm.save_session("acme_corp", mem)
    assert path.exists() is True

    loaded_mem = sm.load_session("acme_corp")
    assert loaded_mem is not None
    assert loaded_mem.is_phase_completed("reconnaissance") is True

    sessions = sm.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].name == "acme_corp"
