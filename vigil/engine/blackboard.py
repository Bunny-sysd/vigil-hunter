"""
Shared Blackboard Session Memory & Inter-Agent Handoff Protocol.

Provides a unified, persistent session memory layer (CoALA framework) where specialized
AI sub-agents write findings, share target surface models, and pass structured Handoff Notes.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, List, Dict, Optional


@dataclass
class HandoffNote:
    """Structured memorandum passed from one specialized phase agent to the next."""

    source_agent: str
    target_agent: str
    phase_completed: str
    timestamp: float = field(default_factory=time.time)
    key_findings: List[str] = field(default_factory=list)
    recommended_focus: str = ""
    human_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HandoffNote:
        return cls(
            source_agent=data.get("source_agent", ""),
            target_agent=data.get("target_agent", ""),
            phase_completed=data.get("phase_completed", ""),
            timestamp=data.get("timestamp", time.time()),
            key_findings=data.get("key_findings", []),
            recommended_focus=data.get("recommended_focus", ""),
            human_notes=data.get("human_notes", ""),
        )


@dataclass
class TargetProfile:
    """Host-centric surface model aggregating open ports, services, endpoints, and credentials."""

    host_ip: str
    hostname: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    web_endpoints: List[str] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    overall_risk: str = "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TargetProfile:
        return cls(
            host_ip=data.get("host_ip", ""),
            hostname=data.get("hostname", ""),
            open_ports=data.get("open_ports", []),
            services=data.get("services", []),
            web_endpoints=data.get("web_endpoints", []),
            credentials=data.get("credentials", []),
            findings=data.get("findings", []),
            overall_risk=data.get("overall_risk", "LOW"),
        )


class BlackboardMemory:
    """
    Central Blackboard Memory store for a target session.
    Persists target models, completed phases, and agent handoff memorandums.
    """

    def __init__(self, session_id: str, storage_dir: Optional[Path] = None):
        self.session_id = session_id
        self.storage_dir = storage_dir or (Path.cwd() / ".vigil" / "sessions")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.filepath = self.storage_dir / f"{session_id}.json"

        self.targets: Dict[str, TargetProfile] = {}
        self.completed_phases: List[str] = []
        self.handoff_history: List[HandoffNote] = []
        self.human_overrides: List[str] = []

        self.load()

    def get_target(self, host_ip: str) -> TargetProfile:
        if host_ip not in self.targets:
            self.targets[host_ip] = TargetProfile(host_ip=host_ip)
        return self.targets[host_ip]

    def add_handoff(self, note: HandoffNote) -> None:
        self.handoff_history.append(note)
        if note.phase_completed and note.phase_completed not in self.completed_phases:
            self.completed_phases.append(note.phase_completed)
        self.save()

    def add_human_note(self, note: str) -> None:
        if note:
            self.human_overrides.append(note)
            if self.handoff_history:
                self.handoff_history[-1].human_notes = note
            self.save()

    def latest_handoff(self) -> Optional[HandoffNote]:
        return self.handoff_history[-1] if self.handoff_history else None

    def is_phase_completed(self, phase_name: str) -> bool:
        return phase_name.lower() in [p.lower() for p in self.completed_phases]

    def save(self) -> None:
        data = {
            "session_id": self.session_id,
            "completed_phases": self.completed_phases,
            "human_overrides": self.human_overrides,
            "targets": {ip: t.to_dict() for ip, t in self.targets.items()},
            "handoff_history": [h.to_dict() for h in self.handoff_history],
        }
        self.filepath.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load(self) -> None:
        if not self.filepath.exists():
            return
        try:
            data = json.loads(self.filepath.read_text(encoding="utf-8"))
            self.completed_phases = data.get("completed_phases", [])
            self.human_overrides = data.get("human_overrides", [])
            self.targets = {
                ip: TargetProfile.from_dict(t)
                for ip, t in data.get("targets", {}).items()
            }
            self.handoff_history = [
                HandoffNote.from_dict(h)
                for h in data.get("handoff_history", [])
            ]
        except Exception:
            pass
