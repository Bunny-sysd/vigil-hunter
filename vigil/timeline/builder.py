"""
Attack timeline builder.
"""

from __future__ import annotations

import time

from vigil.models import AttackPhase, ScanResult, Severity, TimelineEvent


class AttackTimelineBuilder:
    """
    Sorts findings, extracts timestamps, and maps security events into a
    chronological AttackTimeline representation.
    """

    def build_timeline(self, result: ScanResult) -> None:
        """
        Populate the scan result's timeline by ordering findings and security events
        chronologically.
        """
        timeline = result.timeline
        seen_events = set()

        # 1. Map findings to timeline events
        for finding in result.findings:
            # Check if we have logs with timestamps in the evidence list
            ts = None
            source_ip = None
            
            # Find the earliest timestamp in the evidence logs
            dated_evidence = [e for e in finding.evidence if e.timestamp is not None]
            if dated_evidence:
                dated_evidence.sort(key=lambda e: e.timestamp or 0)
                ts = dated_evidence[0].timestamp
                source_ip = dated_evidence[0].source_ip

            # Fallback to scan start time if no timestamp is present in the logs
            if ts is None:
                ts = result.scan_start

            # Determine the kill chain phase
            phase = self._map_category_to_phase(finding.category)

            # Avoid adding duplicate timeline entries
            event_key = (ts, finding.title)
            if event_key not in seen_events:
                event = TimelineEvent(
                    timestamp=ts,
                    description=finding.title,
                    phase=phase,
                    severity=finding.severity,
                    finding_ref=finding,
                    source_ip=source_ip,
                )
                timeline.add_event(event)
                seen_events.add(event_key)

        # 2. Add credential discoveries as timeline milestones
        for cred in result.credentials:
            if cred.timestamp is not None:
                event_key = (cred.timestamp, f"Credential discovery: {cred.username}")
                if event_key not in seen_events:
                    desc = f"Credential extracted: '{cred.username}' (type: {cred.secret_type}, status: {cred.context})"
                    event = TimelineEvent(
                        timestamp=cred.timestamp,
                        description=desc,
                        phase=AttackPhase.EXPLOITATION,
                        severity=Severity.HIGH if "success" in cred.context else Severity.INFO,
                        source_ip=cred.source_ip,
                    )
                    timeline.add_event(event)
                    seen_events.add(event_key)

    def _map_category_to_phase(self, category: Any) -> AttackPhase:
        from vigil.models import FindingCategory
        
        mapping = {
            FindingCategory.BRUTE_FORCE: AttackPhase.DELIVERY,
            FindingCategory.PRIVILEGE_ESCALATION: AttackPhase.PRIVILEGE_ESCALATION,
            FindingCategory.LATERAL_MOVEMENT: AttackPhase.LATERAL_MOVEMENT,
            FindingCategory.RECONNAISSANCE: AttackPhase.RECONNAISSANCE,
            FindingCategory.PERSISTENCE: AttackPhase.PERSISTENCE,
            FindingCategory.DATA_EXFILTRATION: AttackPhase.EXFILTRATION,
            FindingCategory.CREDENTIAL_LEAK: AttackPhase.EXPLOITATION,
            FindingCategory.PHISHING: AttackPhase.DELIVERY,
            FindingCategory.CODE_VULNERABILITY: AttackPhase.EXPLOITATION,
        }
        
        return mapping.get(category, AttackPhase.EXPLOITATION)

from typing import Any
