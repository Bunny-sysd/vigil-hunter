"""
Engagement Campaign Session Snapshot Manager.

Save, load, and snapshot complete target campaign sessions with Blackboard memory intact.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from vigil.engine.blackboard import BlackboardMemory


@dataclass
class CampaignSessionInfo:
    """Summary metadata for a saved campaign session."""

    name: str
    created_at: str
    target_count: int
    completed_phases: List[str]
    filepath: str


class SessionManager:
    """
    Manages named campaign sessions in ~/.vigil/sessions or workspace .vigil/sessions.
    """

    def __init__(self, sessions_dir: Optional[Path] = None):
        self.sessions_dir = sessions_dir or (Path.cwd() / ".vigil" / "sessions")
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def save_session(self, name: str, memory: BlackboardMemory) -> Path:
        clean_name = name.replace(" ", "_").lower()
        filepath = self.sessions_dir / f"{clean_name}.json"

        memory.filepath = filepath
        memory.save()

        return filepath

    def load_session(self, name: str) -> Optional[BlackboardMemory]:
        clean_name = name.replace(" ", "_").lower()
        filepath = self.sessions_dir / f"{clean_name}.json"

        if not filepath.exists():
            return None

        memory = BlackboardMemory(session_id=clean_name, storage_dir=self.sessions_dir)
        return memory

    def list_sessions(self) -> List[CampaignSessionInfo]:
        sessions: List[CampaignSessionInfo] = []

        for p in self.sessions_dir.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                sessions.append(
                    CampaignSessionInfo(
                        name=p.stem,
                        created_at=data.get("created_at", "N/A"),
                        target_count=len(data.get("targets", {})),
                        completed_phases=data.get("completed_phases", []),
                        filepath=str(p),
                    )
                )
            except Exception:
                continue

        return sessions
