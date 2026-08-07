"""
Delta & Diff Engine for Vigil Security Engine.

Compares two ScanResult instances or scan files to detect:
    - Newly opened ports & discovered services
    - Removed or patched services
    - Service version modifications
    - New vs resolved vulnerability findings
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Tuple

from vigil.models import Finding, ScanResult, ServiceVersion


@dataclass
class ServiceDiff:
    """Represents a change in a service or port status."""

    host: str
    port: int
    protocol: str
    change_type: str  # 'ADDED', 'REMOVED', 'MODIFIED'
    old_version: str = ""
    new_version: str = ""
    service_name: str = ""


@dataclass
class FindingDiff:
    """Represents a change in security findings between scans."""

    title: str
    severity: str
    change_type: str  # 'NEW_FINDING', 'RESOLVED'
    description: str = ""


@dataclass
class ScanDiff:
    """Complete summary diff between two scan results."""

    target1_name: str
    target2_name: str
    added_services: List[ServiceDiff] = field(default_factory=list)
    removed_services: List[ServiceDiff] = field(default_factory=list)
    changed_services: List[ServiceDiff] = field(default_factory=list)
    new_findings: List[FindingDiff] = field(default_factory=list)
    resolved_findings: List[FindingDiff] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (
            self.added_services
            or self.removed_services
            or self.changed_services
            or self.new_findings
            or self.resolved_findings
        )


class DiffEngine:
    """
    Computes delta and structural differences between two scan results.
    """

    def compare_scans(self, result1: ScanResult, result2: ScanResult) -> ScanDiff:
        t1_name = ", ".join(result1.files_analyzed) or "Scan 1"
        t2_name = ", ".join(result2.files_analyzed) or "Scan 2"

        diff = ScanDiff(target1_name=t1_name, target2_name=t2_name)

        # 1. Map services by (host, port, protocol) key
        srv_map1: Dict[Tuple[str, int, str], ServiceVersion] = {
            (s.host, s.port, s.protocol): s for s in result1.services
        }
        srv_map2: Dict[Tuple[str, int, str], ServiceVersion] = {
            (s.host, s.port, s.protocol): s for s in result2.services
        }

        all_keys = set(srv_map1.keys()).union(set(srv_map2.keys()))

        for key in all_keys:
            host, port, protocol = key
            in_s1 = key in srv_map1
            in_s2 = key in srv_map2

            if in_s2 and not in_s1:
                srv = srv_map2[key]
                diff.added_services.append(
                    ServiceDiff(
                        host=host,
                        port=port,
                        protocol=protocol,
                        change_type="ADDED",
                        new_version=f"{srv.service_name} {srv.version}".strip(),
                        service_name=srv.service_name,
                    )
                )
            elif in_s1 and not in_s2:
                srv = srv_map1[key]
                diff.removed_services.append(
                    ServiceDiff(
                        host=host,
                        port=port,
                        protocol=protocol,
                        change_type="REMOVED",
                        old_version=f"{srv.service_name} {srv.version}".strip(),
                        service_name=srv.service_name,
                    )
                )
            else:
                s1 = srv_map1[key]
                s2 = srv_map2[key]
                v1_str = f"{s1.service_name} {s1.version}".strip()
                v2_str = f"{s2.service_name} {s2.version}".strip()

                if v1_str != v2_str:
                    diff.changed_services.append(
                        ServiceDiff(
                            host=host,
                            port=port,
                            protocol=protocol,
                            change_type="MODIFIED",
                            old_version=v1_str,
                            new_version=v2_str,
                            service_name=s2.service_name,
                        )
                    )

        # 2. Compare Findings
        findings1: Dict[str, Finding] = {f.title: f for f in result1.findings}
        findings2: Dict[str, Finding] = {f.title: f for f in result2.findings}

        all_finding_titles = set(findings1.keys()).union(set(findings2.keys()))

        for title in all_finding_titles:
            in_f1 = title in findings1
            in_f2 = title in findings2

            if in_f2 and not in_f1:
                f = findings2[title]
                diff.new_findings.append(
                    FindingDiff(
                        title=f.title,
                        severity=f.severity.value,
                        change_type="NEW_FINDING",
                        description=f.description,
                    )
                )
            elif in_f1 and not in_f2:
                f = findings1[title]
                diff.resolved_findings.append(
                    FindingDiff(
                        title=f.title,
                        severity=f.severity.value,
                        change_type="RESOLVED",
                        description=f.description,
                    )
                )

        return diff
