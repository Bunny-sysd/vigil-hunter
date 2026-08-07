"""
Log Ingestor index.

Provides a unified interface to load, detect, and parse any supported log formats.
"""

from __future__ import annotations

import logging
from pathlib import Path

from vigil.ingestors.auth_log import AuthLogIngestor
from vigil.ingestors.base import BaseIngestor
from vigil.ingestors.crontab_parser import CrontabParser
from vigil.ingestors.email_parser import EmailParser
from vigil.ingestors.html_source import HTMLSourceIngestor
from vigil.ingestors.nmap_text import NmapTextIngestor
from vigil.ingestors.nmap_xml import NmapXmlIngestor
from vigil.ingestors.universal_log import UniversalLogIngestor
from vigil.ingestors.web_server import WebServerLogIngestor
from vigil.models import LogEntry

logger = logging.getLogger("vigil.ingestors")

# Primary format ingestors
PRIMARY_INGESTORS: list[BaseIngestor] = [
    AuthLogIngestor(),
    WebServerLogIngestor(),
    NmapXmlIngestor(),
    NmapTextIngestor(),
    EmailParser(),
    CrontabParser(),
    HTMLSourceIngestor(),
]

# Fallback ingestor for raw/unknown logs
UNIVERSAL_INGESTOR = UniversalLogIngestor()


def ingest_file(filepath: Path) -> list[LogEntry]:
    """
    Auto-detect the format of the file and parse it.
    Falls back to UniversalLogIngestor if no primary ingestor matches.
    """
    if not filepath.exists():
        logger.error(f"File not found: {filepath}")
        return []

    for ingestor in PRIMARY_INGESTORS:
        try:
            if ingestor.can_ingest(filepath):
                logger.info(f"Ingesting '{filepath.name}' using {ingestor.__class__.__name__}")
                return ingestor.ingest(filepath)
        except Exception as e:
            logger.warning(f"Error checking/parsing {filepath.name} with {ingestor.__class__.__name__}: {e}")

    # Fallback to Universal log ingestor
    try:
        if UNIVERSAL_INGESTOR.can_ingest(filepath):
            logger.info(f"Ingesting '{filepath.name}' using UniversalLogIngestor fallback")
            return UNIVERSAL_INGESTOR.ingest(filepath)
    except Exception as e:
        logger.error(f"Universal ingestor failed on '{filepath.name}': {e}")

    logger.warning(f"Unrecognized binary file '{filepath.name}'. Skipping.")
    return []
