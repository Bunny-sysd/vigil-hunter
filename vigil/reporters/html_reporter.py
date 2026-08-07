"""
HTML forensic report generator for Vigil.
"""

from __future__ import annotations

import json
from datetime import datetime

from vigil.models import ScanResult


class HTMLReporter:
    """Generates self-contained executive HTML forensic reports."""

    def generate(self, result: ScanResult) -> str:
        """Generate a clean, modern HTML/CSS forensic report for findings visualization."""
        return generate_html_report(result)


def generate_html_report(result: ScanResult) -> str:
    """Generate a clean, modern HTML/CSS forensic report for findings visualization."""
    
    start_date = datetime.fromtimestamp(result.scan_start).strftime("%Y-%m-%d %H:%M:%S")
    findings_list = [f.to_dict() for f in result.findings]
    creds_list = [c.to_dict() for c in result.credentials]
    services_list = [s.to_dict() for s in result.services]
    paths_list = [p.to_dict() for p in result.privesc_paths]
    timeline_events = [e.to_dict() for e in result.timeline.events]

    # Overall summary fields
    threat_score = result.threat_score
    score_color = _get_score_color(threat_score)
    score_label = _get_score_label(threat_score)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vigil Forensic Report — {start_date}</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --panel-bg: #111827;
            --border-color: #1f2937;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-cyan: #06b6d4;
            --accent-purple: #a855f7;
            
            --sev-critical: #ef4444;
            --sev-high: #f97316;
            --sev-medium: #eab308;
            --sev-low: #3b82f6;
            --sev-info: #6b7280;
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 40px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 40px;
        }}

        .logo {{
            font-size: 24px;
            font-weight: 700;
            color: var(--accent-cyan);
            letter-spacing: 1px;
        }}

        .timestamp {{
            color: var(--text-secondary);
            font-size: 14px;
        }}

        /* Dashboard widgets */
        .dashboard {{
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr 1fr;
            gap: 20px;
            margin-bottom: 40px;
        }}

        .widget {{
            background-color: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
        }}

        .threat-meter {{
            grid-column: span 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }}

        .score-val {{
            font-size: 48px;
            font-weight: 800;
            color: {score_color};
            margin: 10px 0 5px;
        }}

        .score-lbl {{
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-secondary);
        }}

        .counter-val {{
            font-size: 36px;
            font-weight: 700;
            margin-top: 10px;
        }}

        /* Tabs configuration */
        .tabs-header {{
            display: flex;
            gap: 10px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 30px;
        }}

        .tab-btn {{
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 16px;
            font-weight: 600;
            padding: 12px 20px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
        }}

        .tab-btn:hover, .tab-btn.active {{
            color: var(--text-primary);
            border-bottom-color: var(--accent-cyan);
        }}

        .tab-content {{
            display: none;
        }}

        .tab-content.active {{
            display: block;
        }}

        /* Findings Layout */
        .finding-card {{
            background-color: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
        }}

        .finding-header {{
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
        }}

        .finding-title-block {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        .severity-badge {{
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }}

        .badge-critical {{ background-color: rgba(239, 68, 68, 0.15); color: var(--sev-critical); border: 1px solid var(--sev-critical); }}
        .badge-high {{ background-color: rgba(249, 115, 22, 0.15); color: var(--sev-high); border: 1px solid var(--sev-high); }}
        .badge-medium {{ background-color: rgba(234, 179, 8, 0.15); color: var(--sev-medium); border: 1px solid var(--sev-medium); }}
        .badge-low {{ background-color: rgba(59, 130, 246, 0.15); color: var(--sev-low); border: 1px solid var(--sev-low); }}
        .badge-info {{ background-color: rgba(107, 114, 128, 0.15); color: var(--sev-info); border: 1px solid var(--sev-info); }}

        .finding-body {{
            padding: 24px;
            background-color: rgba(17, 24, 39, 0.5);
        }}

        .finding-field {{
            margin-bottom: 20px;
        }}

        .field-label {{
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }}

        .evidence-box {{
            background-color: #030712;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            font-family: 'Courier New', Courier, monospace;
            font-size: 14px;
            overflow-x: auto;
            white-space: pre-wrap;
        }}

        /* Timeline Layout */
        .timeline-container {{
            position: relative;
            padding-left: 30px;
            margin-top: 20px;
        }}

        .timeline-container::before {{
            content: '';
            position: absolute;
            left: 8px;
            top: 0;
            bottom: 0;
            width: 2px;
            background-color: var(--border-color);
        }}

        .timeline-item {{
            position: relative;
            margin-bottom: 30px;
        }}

        .timeline-dot {{
            position: absolute;
            left: -30px;
            top: 5px;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background-color: var(--bg-color);
            border: 3px solid var(--accent-cyan);
        }}

        .timeline-meta {{
            display: flex;
            gap: 15px;
            font-size: 14px;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}

        .timeline-desc {{
            font-size: 16px;
            font-weight: 600;
        }}

        /* General tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}

        th, td {{
            text-align: left;
            padding: 14px 18px;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        tr:hover td {{
            background-color: rgba(31, 41, 55, 0.2);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">🔍 VIGIL FORENSIC ENRICHMENT</div>
            <div class="timestamp">Generated: {start_date}</div>
        </header>

        <section class="dashboard">
            <div class="widget threat-meter">
                <div class="score-val">{threat_score}</div>
                <div class="score-lbl">{score_label} RISK</div>
            </div>
            <div class="widget">
                <div class="score-lbl">Findings</div>
                <div class="counter-val" style="color: var(--sev-critical)">{len(findings_list)}</div>
            </div>
            <div class="widget">
                <div class="score-lbl">Credentials</div>
                <div class="counter-val" style="color: var(--sev-medium)">{len(creds_list)}</div>
            </div>
            <div class="widget">
                <div class="score-lbl">Services</div>
                <div class="counter-val" style="color: var(--sev-low)">{len(services_list)}</div>
            </div>
            <div class="widget">
                <div class="score-lbl">PrivEsc Paths</div>
                <div class="counter-val" style="color: #10b981">{len(paths_list)}</div>
            </div>
        </section>

        <!-- Narrative panel -->
        {f'''<section class="widget" style="text-align: left; margin-bottom: 40px;">
            <div class="score-lbl" style="margin-bottom: 10px;">Forensic Threat Narrative Synthesis</div>
            <p style="line-height: 1.6; margin: 0; font-size: 16px; color: var(--text-primary);">{result.timeline.narrative}</p>
        </section>''' if result.timeline.narrative else ''}

        <div class="tabs-header">
            <button class="tab-btn active" onclick="switchTab('findings')">Findings ({len(findings_list)})</button>
            <button class="tab-btn" onclick="switchTab('timeline')">Timeline ({len(timeline_events)})</button>
            <button class="tab-btn" onclick="switchTab('creds')">Credentials ({len(creds_list)})</button>
            <button class="tab-btn" onclick="switchTab('services')">Services ({len(services_list)})</button>
            <button class="tab-btn" onclick="switchTab('privesc')">PrivEsc ({len(paths_list)})</button>
        </div>

        <!-- Tab contents -->
        <div id="findings" class="tab-content active">
            {_render_findings_html(findings_list)}
        </div>

        <div id="timeline" class="tab-content">
            <div class="timeline-container">
                {_render_timeline_html(timeline_events)}
            </div>
        </div>

        <div id="creds" class="tab-content">
            {_render_creds_table(creds_list)}
        </div>

        <div id="services" class="tab-content">
            {_render_services_table(services_list)}
        </div>

        <div id="privesc" class="tab-content">
            {_render_privesc_table(paths_list)}
        </div>
    </div>

    <script>
        function switchTab(tabId) {{
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }}
    </script>
</body>
</html>
"""
    return html


def _render_findings_html(findings: list[dict]) -> str:
    if not findings:
        return "<p style='color: var(--text-secondary);'>No findings recorded during scan.</p>"
        
    cards = []
    for f in findings:
        badge_cls = f"badge-{f['severity'].lower()}"
        evidence_lines = f.get("evidence_lines", [])
        evidence_html = ""
        if evidence_lines:
            ev_str = "\n".join(evidence_lines)
            evidence_html = f"""<div class="finding-field">
                <div class="field-label">Evidence Excerpts</div>
                <div class="evidence-box">{ev_str}</div>
            </div>"""

        metadata_html = ""
        meta = f.get("metadata", {})
        if meta and "secure_code_snippet" in meta:
            # Code auditor specific details
            metadata_html = f"""<div class="finding-field">
                <div class="field-label">Secure Code Refactoring Remediation</div>
                <div class="evidence-box" style="border-color: #10b981; color: #a7f3d0;">{meta['secure_code_snippet']}</div>
            </div>"""

        remedy_html = ""
        if f.get('remediation'):
            remedy_html = f"""<div class="finding-field">
                <div class="field-label">Remediation Steps</div>
                <p style="margin: 0; line-height: 1.5; color: #34d399;">{f['remediation']}</p>
            </div>"""

        cards.append(f"""
        <div class="finding-card">
            <div class="finding-header">
                <div class="finding-title-block">
                    <span class="severity-badge {badge_cls}">{f['severity']}</span>
                    <strong style="font-size: 16px;">{f['title']}</strong>
                </div>
            </div>
            <div class="finding-body">
                <div class="finding-field">
                    <p style="margin: 0; line-height: 1.6; font-size: 15px;">{f['description']}</p>
                </div>
                {remedy_html}
                {metadata_html}
                {evidence_html}
            </div>
        </div>
        """)
    return "\n".join(cards)


def _render_timeline_html(events: list[dict]) -> str:
    if not events:
        return "<p style='color: var(--text-secondary);'>No timeline events recorded.</p>"

    items = []
    for ev in events:
        dt = datetime.fromtimestamp(ev["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        items.append(f"""
        <div class="timeline-item">
            <div class="timeline-dot"></div>
            <div class="timeline-meta">
                <span>{dt}</span>
                <span style="color: var(--accent-cyan); font-weight: bold;">{ev['phase']}</span>
                {f"<span>IP: {ev['source_ip']}</span>" if ev.get('source_ip') else ''}
            </div>
            <div class="timeline-desc">{ev['description']}</div>
        </div>
        """)
    return "\n".join(items)


def _render_creds_table(creds: list[dict]) -> str:
    if not creds:
        return "<p style='color: var(--text-secondary);'>No credentials extracted.</p>"

    rows = []
    for c in creds:
        secret = c['secret'] if c['secret'] else "<i style='color: var(--text-secondary)'>empty</i>"
        rows.append(f"""
        <tr>
            <td><strong>{c['username']}</strong></td>
            <td><code>{secret}</code></td>
            <td><span style="color: var(--accent-cyan); font-weight:600;">{c['context']}</span></td>
            <td><span style="color: var(--text-secondary); font-size:13px;">{c['source']}</span></td>
        </tr>
        """)
    
    return f"""
    <div style="background-color: var(--panel-bg); border: 1px solid var(--border-color); border-radius: 12px; overflow: hidden;">
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Password / Token</th>
                    <th>Context</th>
                    <th>Source File</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>
    """


def _render_services_table(services: list[dict]) -> str:
    if not services:
        return "<p style='color: var(--text-secondary);'>No service banners discovered.</p>"

    rows = []
    for s in services:
        vuln_count = s.get('cve_count', 0)
        vuln_disp = f"<span style='color: var(--sev-critical); font-weight: bold;'>{vuln_count} CVEs</span>" if vuln_count > 0 else "<span style='color: #10b981;'>None</span>"
        rows.append(f"""
        <tr>
            <td><strong>{s['host']}</strong></td>
            <td><code>{s['port']}/{s['protocol']}</code></td>
            <td>{s['service_name']}</td>
            <td><code>{s['version']}</code></td>
            <td>{vuln_disp}</td>
        </tr>
        """)

    return f"""
    <div style="background-color: var(--panel-bg); border: 1px solid var(--border-color); border-radius: 12px; overflow: hidden;">
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port/Proto</th>
                    <th>Service</th>
                    <th>Version String</th>
                    <th>Vulnerabilities</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>
    """


def _render_privesc_table(paths: list[dict]) -> str:
    if not paths:
        return "<p style='color: var(--text-secondary);'>No privilege escalation pathways identified.</p>"

    rows = []
    for p in paths:
        conf_pct = f"{int(p['confidence'] * 100)}%"
        rows.append(f"""
        <tr>
            <td><strong>{p['technique']}</strong></td>
            <td><code>{p['command']}</code></td>
            <td><span style="font-weight: 600;">{conf_pct}</span></td>
            <td><span class="severity-badge" style="background-color: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid #10b981; display: inline-block;">{p['risk']}</span></td>
        </tr>
        """)

    return f"""
    <div style="background-color: var(--panel-bg); border: 1px solid var(--border-color); border-radius: 12px; overflow: hidden;">
        <table>
            <thead>
                <tr>
                    <th>Technique</th>
                    <th>Verification Command</th>
                    <th>Confidence</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>
    """


def _get_score_color(score: int) -> str:
    if score >= 75: return "var(--sev-critical)"
    if score >= 40: return "var(--sev-high)"
    if score >= 15: return "var(--sev-medium)"
    return "#10b981"


def _get_score_label(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 40: return "HIGH"
    if score >= 15: return "MEDIUM"
    return "LOW"
