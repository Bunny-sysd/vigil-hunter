"""
OASIS SARIF v2.1.0 Standard Exporter.
"""

from __future__ import annotations

import json
from typing import Any, Dict
from vigil.models import ScanResult


class SARIFReporter:
    """
    Renders ScanResult objects into standard OASIS SARIF v2.1.0 JSON documents.
    """

    def generate(self, scan_result: ScanResult) -> str:
        results = []

        for f in scan_result.findings:
            results.append({
                "ruleId": f.cve_id or f.category.value,
                "level": self._severity_to_sarif_level(f.severity.value),
                "message": {
                    "text": f"{f.title}: {f.description}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.source_file or "target"
                            }
                        }
                    }
                ]
            })

        sarif_doc: Dict[str, Any] = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Vigil Security Engine",
                            "version": "0.4.0",
                            "informationUri": "https://github.com/vigil-security/vigil"
                        }
                    },
                    "results": results
                }
            ]
        }

        return json.dumps(sarif_doc, indent=2)

    @staticmethod
    def _severity_to_sarif_level(sev: str) -> str:
        s = sev.upper()
        if s in ("CRITICAL", "HIGH"):
            return "error"
        if s == "MEDIUM":
            return "warning"
        return "note"
