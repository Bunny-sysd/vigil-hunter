"""
Privilege Escalation & Post-Exploitation AI Sub-Agent.
"""

from __future__ import annotations

from typing import Any, Dict
from vigil.ai.brain import AIBrain
from vigil.engine.blackboard import BlackboardMemory, HandoffNote
from vigil.models import ScanResult

PRIVESC_SYSTEM_PROMPT = """
You are a Privilege Escalation Specialist & GTFOBins Auditor (PrivEscAgent).

YOUR MISSION:
- Review PEASS logs (linPEAS/winPEAS), SUID binaries, sudoers misconfigurations, and cron jobs.
- Evaluate paths to gain administrator or root privileges.
- Output prioritized GTFOBins verification commands and defensive remediation steps.
"""

PRIVESC_SCHEMA = {
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


class PrivEscAgent:
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
                    f"Human Note: {handoff.human_notes}\n\n"
                )

            priv_summary = []
            for p in scan_result.privesc_paths[:10]:
                priv_summary.append(f"Technique: {p.technique} | Command: {p.command} | Risk: {p.risk}")

            payload = handoff_str + f"DISCOVERED PRIVESC PATHS:\n" + "\n".join(priv_summary)

            res = self.ai_brain.structured_output(
                system_prompt=PRIVESC_SYSTEM_PROMPT,
                user_content=payload,
                response_schema=PRIVESC_SCHEMA,
            )

        key_findings = res.get("key_findings") or ["Audited local SUID binaries and privilege escalation vectors"]
        rec_focus = res.get("recommended_focus") or "Remediate GTFOBins SUID permissions"

        note = HandoffNote(
            source_agent="PrivEscAgent",
            target_agent="RemediationAgent",
            phase_completed="privilege_escalation",
            key_findings=key_findings,
            recommended_focus=rec_focus,
        )
        memory.add_handoff(note)

        return res
