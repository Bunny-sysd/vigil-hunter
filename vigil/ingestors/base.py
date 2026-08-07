"""
Base ingestor class that all log format ingestors must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from vigil.models import LogEntry


class BaseIngestor(ABC):
    """
    Abstract Base Ingestor.

    Ingestors are responsible for reading file sources and parsing them into
    standardized LogEntry objects.
    """

    @abstractmethod
    def can_ingest(self, filepath: Path) -> bool:
        """
        Check if this ingestor is capable of parsing the given file.

        Args:
            filepath: Path to the log file.

        Returns:
            True if this ingestor can parse it, False otherwise.
        """
        pass

    @abstractmethod
    def ingest(self, filepath: Path) -> list[LogEntry]:
        """
        Parse the log file into a list of LogEntry objects.

        Args:
            filepath: Path to the log file.

        Returns:
            List of parsed LogEntry objects.
        """
        pass

    @abstractmethod
    def detect_format(self, sample_lines: list[str]) -> bool:
        """
        Heuristic method to check if the file format matches this parser.

        Args:
            sample_lines: A few sample lines from the start of the file.

        Returns:
            True if the lines match expected patterns of this log type.
        """
        pass
