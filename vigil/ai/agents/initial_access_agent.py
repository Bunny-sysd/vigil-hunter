"""
Initial Access & Exploitation Vectors Sub-Agent.
"""

from __future__ import annotations

from typing import Any, Dict
from vigil.ai.brain import AIBrain
from vigil.engine.blackboard import BlackboardMemory, HandoffNote
from vigil.models import ScanResult

INITIAL_ACCESS_SYSTEM_PROMPT = """
You are an Initial Access & Exploit Specialist (InitialAccessAgent).

YOUR MISSION:
- Review the Handoff Note from ReconAgent and shared Blackboard memory.
- Analyze exposed CVEs, web application endpoints, default credentials, and service vulnerabilities.
- Provide actionable attack vectors to gain an initial foothold.
"""

INITIAL_ACCESS_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "strategic_summary": {"type": "STRING"},
        "key_findings": {"type": "ARRAY", "items": {"type": "STRING"}},
        "recommended_focus": {"type": "STRING"},
        "tactical_directives": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "priority": {"type": "INTEGER"},
                    "title": {"type": "STRING"},
                    "phase": {"type": "STRING"},
                    "description": {"type": "STRING"},
                    "command_template": {"type": "STRING"},
                    "tool": {"type": "STRING"},
                    "target": {"type": "STRING"},
                },
                "required": ["priority", "title", "phase", "description", "command_template", "tool"],
            },
        },
    },
    "required": ["strategic_summary", "key_findings", "recommended_focus", "tactical_directives"],
}


class InitialAccessAgent:
    def __init__(self, ai_brain: AIBrain | None = None):
        self.ai_brain = ai_brain

    def execute(self, scan_result: ScanResult, memory: BlackboardMemory) -> Dict[str, Any]:
        res: Dict[str, Any] = {}

        if self.ai_brain and self.ai_brain.provider:
            handoff = memory.latest_handoff()
            handoff_str = ""
            if handoff:
                handoff_str = (
                    f"HANDOFF FROM {handoff.source_agent}:\n"
                    f"Key Findings: {', '.join(handoff.key_findings)}\n"
                    f"Recommended Focus: {handoff.recommended_focus}\n"
                    f"Human Override Note: {handoff.human_notes}\n\n"
                )

            target_summary = []
            for s in scan_result.services[:10]:
                target_summary.append(f"Host: {s.host} | Port: {s.port} | Service: {s.service_name} {s.version}")

            payload = handoff_str + f"TARGET SERVICES & CVEs:\n" + "\n".join(target_summary)

            res = self.ai_brain.structured_output(
                system_prompt=INITIAL_ACCESS_SYSTEM_PROMPT,
                user_content=payload,
                response_schema=INITIAL_ACCESS_SCHEMA,
            )

        key_findings = res.get("key_findings") or ["Evaluated initial access vectors and service CVEs"]
        rec_focus = res.get("recommended_focus") or "Execute non-destructive vulnerability probing"

        note = HandoffNote(
            source_agent="InitialAccessAgent",
            target_agent="DiscoveryAgent",
            phase_completed="initial_access",
            key_findings=key_findings,
            recommended_focus=rec_focus,
        )
        memory.add_handoff(note)

        return res
