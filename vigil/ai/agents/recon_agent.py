"""
Reconnaissance & OSINT Specialized AI Sub-Agent.
"""

from __future__ import annotations

from typing import Any, Dict
from vigil.ai.brain import AIBrain
from vigil.engine.blackboard import BlackboardMemory, HandoffNote
from vigil.models import ScanResult

RECON_SYSTEM_PROMPT = """
You are a Reconnaissance & External Attack Surface Specialist (ReconAgent).

YOUR MISSION:
- Analyze target scan data, open ports, IP ranges, hostnames, and service banners.
- Focus strictly on mapping attack surface boundaries and identifying entry vectors.
- Prepare a structured Handoff Note for the InitialAccessAgent.

CRITICAL RULES:
1. Ground analysis only in provided scan data.
2. Output clear tactical directives and key findings.
"""

RECON_SCHEMA = {
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


class ReconAgent:
    def __init__(self, ai_brain: AIBrain | None = None):
        self.ai_brain = ai_brain

    def execute(self, scan_result: ScanResult, memory: BlackboardMemory) -> Dict[str, Any]:
        res: Dict[str, Any] = {}

        if self.ai_brain and self.ai_brain.provider:
            target_summary = []
            for s in scan_result.services[:10]:
                target_summary.append(f"Host: {s.host} | Port: {s.port}/{s.protocol} | Service: {s.service_name} {s.version}")

            payload = f"RECON TARGET DATA:\n" + "\n".join(target_summary)

            res = self.ai_brain.structured_output(
                system_prompt=RECON_SYSTEM_PROMPT,
                user_content=payload,
                response_schema=RECON_SCHEMA,
            )

        key_findings = res.get("key_findings") or [f"Mapped {len(scan_result.services)} services on target"]
        rec_focus = res.get("recommended_focus") or "Audit open HTTP/HTTPS and administrative services"

        note = HandoffNote(
            source_agent="ReconAgent",
            target_agent="InitialAccessAgent",
            phase_completed="reconnaissance",
            key_findings=key_findings,
            recommended_focus=rec_focus,
        )
        memory.add_handoff(note)

        return res
