"""
End-to-End Integration Test for Vigil Hunter Engine on a realistic target.
"""

from __future__ import annotations

from pathlib import Path

from vigil.config import VigilConfig
from vigil.engine.analyzer import ThreatAnalyzer
from vigil.engine.compass import CompassEngine


def test_realistic_target_scenario() -> None:
    scenario_dir = Path(__file__).parent / "fixtures" / "realistic_scenario"
    assert scenario_dir.exists()

    config = VigilConfig.load()
    config.offline_mode = True

    analyzer = ThreatAnalyzer(config)
    files = [f for f in scenario_dir.glob("*") if f.is_file()]

    scan_result = analyzer.run_scan(files)

    # 1. Verify files analyzed
    assert len(scan_result.files_analyzed) >= 4

    # 2. Verify service detection (Apache 2.4.49)
    assert len(scan_result.services) >= 1
    apache_srv = next((s for s in scan_result.services if "Apache" in s.service_name), None)
    assert apache_srv is not None
    assert apache_srv.version == "2.4.49"

    # 3. Verify CVE linking (CVE-2021-41773 RCE)
    assert len(apache_srv.cve_matches) >= 1
    assert any(c["cve_id"] == "CVE-2021-41773" for c in apache_srv.cve_matches)

    # 4. Verify privilege escalation path from linPEAS
    assert len(scan_result.privesc_paths) >= 1

    # 5. Verify Compass directives
    compass_engine = CompassEngine()
    compass_report = compass_engine.generate_report(scan_result)

    assert compass_report.current_kill_chain_phase in ("Privilege Escalation", "Initial Access", "Credential Access")
    assert len(compass_report.recommendations) >= 1
    assert len(compass_report.mitre_techniques_detected) >= 1
