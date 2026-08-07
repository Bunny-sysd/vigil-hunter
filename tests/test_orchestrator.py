"""
Tests for Shared Blackboard Memory and RedTeamOrchestrator.
"""

from __future__ import annotations

from pathlib import Path
from vigil.engine.blackboard import BlackboardMemory, HandoffNote
from vigil.engine.orchestrator import RedTeamOrchestrator
from vigil.models import ScanResult, ServiceVersion


def test_blackboard_memory_persistence(tmp_path: Path) -> None:
    mem = BlackboardMemory(session_id="test_sess", storage_dir=tmp_path)
    note = HandoffNote(
        source_agent="ReconAgent",
        target_agent="InitialAccessAgent",
        phase_completed="reconnaissance",
        key_findings=["dnsmasq 2.83 on port 53"],
        recommended_focus="Focus on dnsmasq CVEs",
    )
    mem.add_handoff(note)

    assert mem.is_phase_completed("reconnaissance") is True
    assert mem.latest_handoff().source_agent == "ReconAgent"

    # Reload memory from disk
    mem2 = BlackboardMemory(session_id="test_sess", storage_dir=tmp_path)
    assert mem2.is_phase_completed("reconnaissance") is True
    assert len(mem2.handoff_history) == 1


def test_orchestrator_phase_lock(tmp_path: Path) -> None:
    orch = RedTeamOrchestrator(session_id="test_lock_sess")
    orch.memory.storage_dir = tmp_path
    orch.memory.filepath = tmp_path / "test_lock_sess.json"

    scan_res = ScanResult()
    scan_res.services.append(ServiceVersion(service_name="http", version="2.4", host="10.0.0.1", port=80))

    # First execution (reconnaissance)
    res1 = orch.execute_phase(scan_res, phase="reconnaissance")
    assert res1["status"] == "success"

    # Second execution of same phase (should be blocked by anti-loop guardrail)
    res2 = orch.execute_phase(scan_res, phase="reconnaissance")
    assert res2["status"] == "blocked"

    # Advance to next phase (initial_access)
    res3 = orch.execute_phase(scan_res, phase="initial_access")
    assert res3["status"] == "success"
