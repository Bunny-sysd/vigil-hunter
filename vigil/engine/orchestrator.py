"""
Red Team Multi-Agent Orchestrator & State Machine Controller.

Manages Red Team phase progression (Recon -> Initial Access -> Discovery -> PrivEsc -> Remediation),
enforces anti-loop locks, passes Inter-Agent Handoff Notes, and coordinates with BlackboardMemory.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from vigil.ai.agents.initial_access_agent import InitialAccessAgent
from vigil.ai.agents.privesc_agent import PrivEscAgent
from vigil.ai.agents.recon_agent import ReconAgent
from vigil.ai.brain import AIBrain
from vigil.engine.blackboard import BlackboardMemory, HandoffNote, TargetProfile
from vigil.models import ScanResult

logger = logging.getLogger("vigil.engine.orchestrator")


class RedTeamOrchestrator:
    """
    Coordinates specialized phase agents and manages Blackboard session state.
    """

    def __init__(self, ai_brain: AIBrain | None = None, session_id: str = "default_session"):
        self.ai_brain = ai_brain
        self.memory = BlackboardMemory(session_id=session_id)
        self.recon_agent = ReconAgent(ai_brain=ai_brain)
        self.initial_access_agent = InitialAccessAgent(ai_brain=ai_brain)
        self.privesc_agent = PrivEscAgent(ai_brain=ai_brain)

    def execute_phase(
        self,
        scan_result: ScanResult,
        phase: str = "reconnaissance",
        force: bool = False,
        human_note: str = "",
    ) -> Dict[str, Any]:
        """
        Execute the specified red team phase agent while respecting phase locks.
        """
        phase_clean = phase.lower().strip()

        # Check anti-loop lock
        if not force and self.memory.is_phase_completed(phase_clean):
            logger.warning(f"Phase '{phase_clean}' already completed for session '{self.memory.session_id}'.")
            return {
                "status": "blocked",
                "message": (
                    f"Guardrail Alert: Phase '{phase_clean}' has already been completed for this target session. "
                    f"To advance, specify a new phase (e.g. '--phase initial_access' or '--phase privesc') "
                    f"or pass '--force' to re-run."
                ),
            }

        # Apply human override note if provided
        if human_note:
            self.memory.add_human_note(human_note)

        # Update blackboard memory model with scan results
        for s in scan_result.services:
            target = self.memory.get_target(s.host or "127.0.0.1")
            if s.port and s.port not in target.open_ports:
                target.open_ports.append(s.port)
            target.services.append({"name": s.service_name, "version": s.version, "port": s.port})

        self.memory.save()

        # Route to specialized agent based on requested phase
        result: Dict[str, Any] = {}
        if phase_clean == "reconnaissance":
            result = self.recon_agent.execute(scan_result, self.memory)
        elif phase_clean in ("initial_access", "vulnerability_analysis"):
            result = self.initial_access_agent.execute(scan_result, self.memory)
        elif phase_clean in ("privilege_escalation", "privesc"):
            result = self.privesc_agent.execute(scan_result, self.memory)
        else:
            # Default fallback to initial access agent
            result = self.initial_access_agent.execute(scan_result, self.memory)

        return {
            "status": "success",
            "phase": phase_clean,
            "agent_result": result,
            "handoff": self.memory.latest_handoff().to_dict() if self.memory.latest_handoff() else {},
        }
