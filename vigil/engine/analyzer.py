"""
Main threat analysis orchestrator for Vigil.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from vigil.ai.brain import AIBrain
from vigil.ai.prompts import THREAT_FORENSICS_SCHEMA, THREAT_FORENSICS_SYSTEM
from vigil.config import VigilConfig
from vigil.engine.compass import CompassEngine
from vigil.engine.credential_extractor import CredentialExtractor
from vigil.engine.exploit_linker import ExploitLinker
from vigil.engine.github_poc_finder import GitHubPoCFinder
from vigil.engine.mitre_attack import match_log_to_techniques
from vigil.engine.nvd_client import NVDClient
from vigil.engine.peass_analyzer import PeassAnalyzer
from vigil.engine.rules.brute_force import BruteForceRule
from vigil.engine.rules.persistence import PersistenceRule
from vigil.engine.rules.priv_escalation import PrivEscalationRule
from vigil.engine.rules.recon import ReconRule
from vigil.engine.source_auditor import SourceAuditor
from vigil.engine.version_hunter import VersionHunter
from vigil.ingestors import ingest_file
from vigil.models import (
    AttackPhase,
    LogEntry,
    LogType,
    ScanResult,
    Severity,
    TimelineEvent,
)
from vigil.timeline.builder import AttackTimelineBuilder

logger = logging.getLogger("vigil.engine.analyzer")


class ThreatAnalyzer:
    """
    Coordinates log ingestion, executes heuristic rules, extracts metadata,
    and enriches findings via the AI brain and Compass Engine.
    """

    def __init__(self, config: VigilConfig):
        self.config = config
        self.ai_brain = AIBrain(config) if config.has_ai or config.provider == "ollama" else None

        # Initialize NVD Client & GitHub PoC Finder
        self.nvd_client = NVDClient(api_key=config.nvd_api_key)
        self.poc_finder = GitHubPoCFinder(token=config.github_token)

        # Initialize sub-analyzers
        self.cred_extractor = CredentialExtractor()
        self.version_hunter = VersionHunter()
        self.exploit_linker = ExploitLinker(
            nvd_client=self.nvd_client,
            poc_finder=self.poc_finder,
            offline_mode=config.offline_mode,
        )
        self.source_auditor = SourceAuditor(self.ai_brain)
        self.peass_analyzer = PeassAnalyzer(self.ai_brain)
        self.timeline_builder = AttackTimelineBuilder()
        self.compass_engine = CompassEngine()

        # Instantiate rule detection suite
        self.rules = [
            BruteForceRule(
                failure_threshold=config.brute_force_threshold,
                window_seconds=config.brute_force_window,
            ),
            PrivEscalationRule(),
            ReconRule(),
            PersistenceRule(),
        ]

    def run_scan(self, filepaths: list[Path], mode: str = "default") -> ScanResult:
        """Execute a full threat hunt across the provided targets."""
        start_time = time.time()

        result = ScanResult(
            ai_provider=self.config.provider if self.ai_brain and self.ai_brain.provider else "",
            mode=mode,
        )

        all_entries: list[LogEntry] = []

        # 1. Ingest files
        for filepath in filepaths:
            try:
                result.files_analyzed.append(filepath.name)

                # Check for source code files
                if filepath.suffix.lower() in (".py", ".js", ".php", ".go", ".c", ".cpp", ".java"):
                    findings = self.source_auditor.audit_file(filepath)
                    result.findings.extend(findings)
                    result.log_entries_processed += 1
                    continue

                # Check for PEASS logs
                if "peas" in filepath.name.lower():
                    paths = self.peass_analyzer.analyze_file(filepath)
                    result.privesc_paths.extend(paths)
                    result.log_entries_processed += 1
                    continue

                # Ingest through registry / universal fallback
                entries = ingest_file(filepath)
                if entries:
                    all_entries.extend(entries)

            except Exception as e:
                err_msg = f"Error scanning file '{filepath.name}': {e}"
                logger.error(err_msg)
                result.errors.append(err_msg)

        result.log_entries_processed += len(all_entries)

        # Apply safety threshold cap on massive files
        if len(all_entries) > self.config.max_log_lines:
            logger.warning(f"Scan entries count ({len(all_entries)}) exceeds max log lines limits. Truncating.")
            all_entries = all_entries[: self.config.max_log_lines]

        # 2. Heuristic rule analysis
        for rule in self.rules:
            try:
                rule_findings = rule.analyze(all_entries)
                result.findings.extend(rule_findings)
            except Exception as e:
                logger.error(f"Rule '{rule.name}' execution failed: {e}")

        # 3. Credential extraction
        try:
            result.credentials = self.cred_extractor.extract(all_entries)
        except Exception as e:
            logger.error(f"Credential extraction failed: {e}")

        # 4. Version Hunting + Exploit database mapping
        try:
            discovered_services = self.version_hunter.extract_versions(all_entries)
            cve_findings = self.exploit_linker.link_exploits(discovered_services)
            result.services = discovered_services
            if cve_findings:
                result.findings.extend(cve_findings)
        except Exception as e:
            logger.error(f"Service version analysis failed: {e}")

        # 5. Build Attack Timeline
        try:
            self.timeline_builder.build_timeline(result)
        except Exception as e:
            logger.error(f"Timeline generation failed: {e}")

        # 6. Map MITRE ATT&CK Techniques to Findings
        for finding in result.findings:
            if not finding.attack_technique:
                matched = match_log_to_techniques(f"{finding.title} {finding.description}")
                if matched:
                    finding.attack_technique = matched[0]["id"]
                    finding.attack_technique_name = matched[0]["name"]

        # 7. AI enrichment & deep threat forensic reporting
        if self.ai_brain and self.ai_brain.provider and result.findings:
            try:
                self._enrich_with_ai(result)
            except Exception as e:
                logger.error(f"AI enrichment failed: {e}")

        # Final cleanup and calculations
        result.sort_findings()
        result.scan_duration = time.time() - start_time
        return result

    def _enrich_with_ai(self, result: ScanResult) -> None:
        """Request the AI brain to synthesize findings and build a clean narrative summary."""
        findings_summary = []
        for idx, f in enumerate(result.findings, 1):
            findings_summary.append(
                f"Finding #{idx}: {f.title} (Severity: {f.severity.value})\n"
                f"Description: {f.description}\n"
                f"Category: {f.category.value}\n"
            )

        context_payload = (
            f"Findings detected:\n"
            f"{chr(10).join(findings_summary)}\n\n"
            f"Please compile the final forensic synthesis report."
        )

        try:
            ai_data = self.ai_brain.structured_output(
                system_prompt=THREAT_FORENSICS_SYSTEM,
                user_content=context_payload,
                response_schema=THREAT_FORENSICS_SCHEMA,
            )

            result.timeline.narrative = ai_data.get("overall_summary", "")

            remediations = ai_data.get("remediation_checklist", [])
            if remediations and result.findings:
                result.findings[0].remediation += "\n\nAI Recommendations:\n" + "\n".join(f"- {r}" for r in remediations)
        except Exception as e:
            logger.debug(f"AI forensic narrative synthesis failed: {e}")
