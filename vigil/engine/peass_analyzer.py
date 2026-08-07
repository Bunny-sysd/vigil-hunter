"""
PEASS Privilege Escalation Log Analyzer.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from vigil.ai.brain import AIBrain
from vigil.ai.prompts import PEASS_ANALYSIS_SCHEMA, PEASS_ANALYSIS_SYSTEM
from vigil.models import PrivescPath

logger = logging.getLogger("vigil.engine.peass_analyzer")


class PeassAnalyzer:
    """
    Cleans ANSI escapes from linPEAS/winPEAS logs, groups findings into sections,
    and analyzes potential privilege escalation pathways.
    """

    # Matches ANSI escape sequences (e.g. color formatting codes \x1b[1;31m)
    ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    # Section indicator headers used in PEASS outputs
    SECTION_HEADER = re.compile(r"^[╚╔═══]")

    def __init__(self, ai_brain: AIBrain | None = None):
        self.ai_brain = ai_brain

    def analyze_file(self, filepath: Path) -> list[PrivescPath]:
        paths: list[PrivescPath] = []
        source_name = filepath.name

        try:
            raw_content = filepath.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            logger.error(f"Failed to read PEASS file {filepath}: {e}")
            return []

        # 1. Clean the logs to plain text
        clean_content = self.strip_ansi(raw_content)

        # 2. Extract sections
        sections = self.split_sections(clean_content)
        logger.info(f"Parsed {len(sections)} distinct PEASS log sections in {source_name}.")

        # 3. Analyze sections using rules + AI
        paths.extend(self._rule_peass_scan(clean_content))

        # AI deep review of high-probability paths
        if self.ai_brain and self.ai_brain.provider:
            for title, sec_lines in list(sections.items())[:5]:
                sec_text = "\n".join(sec_lines)
                if len(sec_text) < 150:
                    continue

                try:
                    logger.info(f"Submitting PEASS section '{title}' to AI for privesc audit...")
                    ai_data = self.ai_brain.structured_output(
                        system_prompt=PEASS_ANALYSIS_SYSTEM,
                        user_content=f"Section: {title}\n\nContent:\n{sec_text[:6000]}",
                        response_schema=PEASS_ANALYSIS_SCHEMA,
                    )

                    ai_paths = ai_data.get("privesc_paths", [])
                    for p in ai_paths:
                        paths.append(
                            PrivescPath(
                                technique=p.get("technique", ""),
                                command=p.get("verification_command", ""),
                                confidence=p.get("confidence_score", 0.5),
                                risk=p.get("risk_level", "low"),
                                reference=p.get("reference", ""),
                            )
                        )
                except Exception as e:
                    logger.debug(f"AI PEASS analysis failed for section '{title}': {e}")

        return paths

    def strip_ansi(self, text: str) -> str:
        """Strip ANSI terminal color escapes."""
        return self.ANSI_ESCAPE.sub("", text)

    def split_sections(self, clean_text: str) -> dict[str, list[str]]:
        """Parse clean log lines into mapped sections using structural headers."""
        sections = {}
        current_section = "General Information"
        sections[current_section] = []

        lines = clean_text.splitlines()
        for line in lines:
            line_strip = line.strip()
            if not line_strip:
                continue

            if self.SECTION_HEADER.match(line_strip) and len(line_strip) > 10:
                current_section = line_strip.strip("═╚╔═ ")
                if not current_section:
                    current_section = f"Section_{len(sections)}"
                sections[current_section] = []
            else:
                sections[current_section].append(line)

        return sections

    def _rule_peass_scan(self, text: str) -> list[PrivescPath]:
        """Rule-based parsing to check SUID and writable file lines in PEASS output."""
        paths: list[PrivescPath] = []
        lines = text.splitlines()
        in_suid_section = False

        for line in lines:
            line_lower = line.lower()

            if "suid" in line_lower:
                in_suid_section = True
            elif line.startswith("[+]") and "suid" not in line_lower:
                in_suid_section = False

            # Check SUID binary permissions (-rwsr-xr-x) or SUID section matches
            if (in_suid_section or "-rws" in line_lower or "suid" in line_lower) and any(
                b in line_lower for b in ["find", "cp", "dd", "vim", "bash", "nmap", "python", "perl", "env"]
            ):
                match = re.search(r"(/usr/\S+|/bin/\S+|/opt/\S+)", line)
                if match:
                    binary_path = match.group(1)
                    bin_name = binary_path.split("/")[-1]
                    paths.append(
                        PrivescPath(
                            technique=f"SUID Binary Discovered: {bin_name}",
                            command=f"{binary_path} . -exec /bin/sh -p \\; -quit" if bin_name == "find" else f"{binary_path}",
                            confidence=0.95,
                            risk="low",
                            reference=f"https://gtfobins.github.io/gtfobins/{bin_name}/#suid",
                        )
                    )

            if "/etc/passwd" in line_lower and ("write" in line_lower or "writable" in line_lower):
                paths.append(
                    PrivescPath(
                        technique="World-Writable /etc/passwd",
                        command="echo 'hacker:$(openssl passwd password123):0:0::/root:/bin/bash' >> /etc/passwd",
                        confidence=0.99,
                        risk="medium",
                        reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-etc-passwd",
                    )
                )

        return paths
