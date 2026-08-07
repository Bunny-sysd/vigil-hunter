"""
Abstract base class for all rule-based threat detection heuristics.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from vigil.models import Finding, LogEntry, Severity


class DetectionRule(ABC):
    """
    Abstract detection rule.

    Each rule takes a list of parsed LogEntry objects and processes them to find
    specific attack patterns (recon, brute force, persistence, etc.).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Friendly name of the rule."""
        pass

    @property
    @abstractmethod
    def attack_id(self) -> str:
        """MITRE ATT&CK Technique ID (e.g. T1110)."""
        pass

    @property
    @abstractmethod
    def attack_name(self) -> str:
        """MITRE ATT&CK Technique Name (e.g. Brute Force)."""
        pass

    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Default severity of findings produced by this rule."""
        pass

    @abstractmethod
    def analyze(self, entries: list[LogEntry]) -> list[Finding]:
        """
        Analyze entries to find matching threat indicators.

        Args:
            entries: The full list of parsed LogEntry objects.

        Returns:
            List of findings discovered.
        """
        pass
