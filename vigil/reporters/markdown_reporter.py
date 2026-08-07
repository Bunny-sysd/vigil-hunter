"""
GitHub-Flavored Markdown Report Generator for Pentest Deliverables.
"""

from __future__ import annotations

from vigil.models import ScanResult


class MarkdownReporter:
    """
    Renders ScanResult objects into clean Markdown reports ideal for Obsidian, Notion, or Git.
    """

    def generate(self, scan_result: ScanResult) -> str:
        lines = []
        lines.append("# 🛡️ Vigil Security Assessment Report")
        lines.append("")
        lines.append(f"**Target Files Analyzed:** {', '.join(scan_result.files_analyzed) or 'Target'}")
        lines.append(f"**AI Provider:** {scan_result.ai_provider or 'Heuristic Engine'}")
        lines.append(f"**Scan Duration:** {scan_result.scan_duration:.2f} seconds")
        lines.append("")

        lines.append("## Executive Summary Metrics")
        lines.append("")
        lines.append(f"- **Critical Vulnerabilities:** {scan_result.critical_count}")
        lines.append(f"- **High Severity Issues:** {scan_result.high_count}")
        lines.append(f"- **Medium Severity Issues:** {scan_result.medium_count}")
        lines.append(f"- **Low Severity Issues:** {scan_result.low_count}")
        lines.append("")

        if scan_result.services:
            lines.append("## Discovered Attack Surface (Services & Ports)")
            lines.append("")
            lines.append("| Host IP | Port | Protocol | Service Name | Version |")
            lines.append("|---|---|---|---|---|")
            for s in scan_result.services:
                lines.append(f"| {s.host} | {s.port} | {s.protocol} | {s.service_name} | {s.version} |")
            lines.append("")

        if scan_result.findings:
            lines.append("## Detailed Vulnerability & Risk Findings")
            lines.append("")
            for idx, f in enumerate(scan_result.findings, 1):
                lines.append(f"### {idx}. {f.title} ({f.severity.value})")
                lines.append(f"- **Category:** {f.category.value}")
                if f.attack_technique:
                    lines.append(f"- **MITRE ATT&CK:** {f.attack_technique} ({f.attack_technique_name})")
                lines.append(f"- **Description:** {f.description}")
                lines.append(f"- **Remediation:** {f.remediation}")
                lines.append("")

        return "\n".join(lines)
