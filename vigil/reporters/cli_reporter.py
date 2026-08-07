"""
CLI report formatter using the Rich library.
"""

from __future__ import annotations

import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vigil.models import ScanResult, Severity

console = Console()


def report_to_terminal(result: ScanResult, verbose: bool = False) -> None:
    """Print a structured analysis summary directly to the terminal."""

    # 1. Header panel
    console.print()
    header_table = Table.grid(expand=True)
    header_table.add_column(justify="left", ratio=3)
    header_table.add_column(justify="right", ratio=1)
    
    header_table.add_row(
        "[bold cyan]🔍 Vigil — AI Threat Hunting & Log Forensics Engine[/bold cyan]",
        f"[dim]v0.1.0[/dim]"
    )
    
    console.print(Panel(header_table, border_style="cyan"))

    # 2. Executive Scan Metadata Table
    meta_table = Table(title="Scan Summary", title_justify="left", show_header=False, box=None)
    meta_table.add_column(style="bold yellow")
    meta_table.add_column()

    start_date = datetime.fromtimestamp(result.scan_start).strftime("%Y-%m-%d %H:%M:%S")
    meta_table.add_row("Scan Started:", start_date)
    meta_table.add_row("Duration:", f"{result.scan_duration:.2f} seconds")
    meta_table.add_row("Files Processed:", f"{len(result.files_analyzed)} ({', '.join(result.files_analyzed) or 'None'})")
    meta_table.add_row("Total Lines:", f"{result.log_entries_processed:,}")
    meta_table.add_row("AI Provider:", f"{result.ai_provider or 'None (Rules Only)'}")
    meta_table.add_row("Threat Score:", f"[{_get_score_color(result.threat_score)}]{result.threat_score}/100[/{_get_score_color(result.threat_score)}]")

    console.print(meta_table)
    console.print()

    # 3. Aggregated counts panel
    counts_table = Table(show_header=True, header_style="bold magenta", box=None)
    counts_table.add_column("Findings", justify="center")
    counts_table.add_column("Credentials", justify="center")
    counts_table.add_column("Services", justify="center")
    counts_table.add_column("PrivEsc Paths", justify="center")

    counts_table.add_row(
        f"[bold red]{len(result.findings)}[/bold red]",
        f"[bold yellow]{len(result.credentials)}[/bold yellow]",
        f"[bold blue]{len(result.services)}[/bold blue]",
        f"[bold green]{len(result.privesc_paths)}[/bold green]"
    )
    console.print(Panel(counts_table, title="Artifact Counter", title_align="left", border_style="magenta"))
    console.print()

    # 4. Detailed findings by severity
    if result.findings:
        console.print("[bold white]🚨 Security Findings[/bold white]", style="underline")
        for finding in result.findings:
            severity_str = f"[{finding.severity.color}]{finding.severity.icon} {finding.severity.value}[/{finding.severity.color}]"
            
            desc = finding.description
            if finding.attack_technique:
                desc = f"[dim]ATT&CK: {finding.attack_technique} ({finding.attack_technique_name})[/dim]\n\n{desc}"
            
            if finding.remediation:
                desc = f"{desc}\n\n[bold green]Remediation:[/bold green] {finding.remediation}"

            if finding.evidence:
                evidence_list = []
                for ev in finding.evidence[:3]:
                    evidence_list.append(f"  [dim]L{ev.line_number}:[/dim] {ev.raw_line}")
                if len(finding.evidence) > 3:
                    evidence_list.append(f"  [dim]... and {len(finding.evidence) - 3} more lines[/dim]")
                desc = f"{desc}\n\n[bold white]Evidence:[/bold white]\n" + "\n".join(evidence_list)

            if finding.references:
                ref_list = [f"  • {ref}" for ref in finding.references[:4]]
                desc = f"{desc}\n\n[bold cyan]Exploits & References:[/bold cyan]\n" + "\n".join(ref_list)

            console.print(Panel(desc, title=f"{severity_str} — {finding.title}", border_style=finding.severity.color))
            console.print()
    else:
        console.print("[green]✔ No suspicious security findings detected.[/green]")
        console.print()

    # 5. Service Banners & Correlated CVE Details Table
    if result.services:
        services_table = Table(title="🎯 Discovered Service Banners & CVE Matches", title_justify="left", show_header=True)
        services_table.add_column("Host", style="bold cyan")
        services_table.add_column("Port/Proto")
        services_table.add_column("Service")
        services_table.add_column("Version")
        services_table.add_column("CVE Matches")
        services_table.add_column("Top Exploit Link", style="blue")

        for srv in result.services:
            cve_disp = f"[bold red]{len(srv.cve_matches)} vulns[/bold red]" if srv.cve_matches else "[green]None[/green]"
            top_link = "[dim]N/A[/dim]"
            if srv.cve_matches:
                first_cve = srv.cve_matches[0]
                exploits = first_cve.get("exploits", [])
                if exploits:
                    first_exp = exploits[0]
                    top_link = first_exp.get("url", "") if isinstance(first_exp, dict) else str(first_exp)

            services_table.add_row(
                srv.host,
                f"{srv.port}/{srv.protocol}",
                srv.service_name,
                f"{srv.version}",
                cve_disp,
                top_link,
            )

        console.print(services_table)
        console.print()

    # 6. Extracted credentials
    if result.credentials:
        creds_table = Table(title="🔑 Extracted Credentials", title_justify="left", show_header=True)
        creds_table.add_column("Username", style="bold yellow")
        creds_table.add_column("Password / Secret")
        creds_table.add_column("Context")
        creds_table.add_column("Source File")

        for cred in result.credentials:
            secret_disp = cred.secret if cred.secret else "[dim]<empty>[/dim]"
            creds_table.add_row(cred.username, secret_disp, cred.context, cred.source)

        console.print(creds_table)
        console.print()

    # 7. Timeline events
    if result.timeline.events:
        console.print("[bold white]⏱ Reconstructed Timeline[/bold white]", style="underline")
        timeline_table = Table(show_header=True, box=None)
        timeline_table.add_column("Timestamp", style="dim", width=20)
        timeline_table.add_column("Phase", style="bold yellow", width=15)
        timeline_table.add_column("Description")

        for ev in result.timeline.events:
            dt_str = datetime.fromtimestamp(ev.timestamp).strftime("%Y-%m-%d %H:%M:%S")
            timeline_table.add_row(dt_str, ev.phase.value, ev.description)

        console.print(timeline_table)
        console.print()

    # 8. PrivEsc Paths (linPEAS/winPEAS logs)
    if result.privesc_paths:
        peass_table = Table(title="📈 Privilege Escalation Pathways", title_justify="left", show_header=True)
        peass_table.add_column("Technique", style="bold green")
        peass_table.add_column("Command Template")
        peass_table.add_column("Confidence")
        peass_table.add_column("Risk")

        for path in result.privesc_paths:
            conf_str = f"{int(path.confidence * 100)}%"
            peass_table.add_row(path.technique, path.command, conf_str, path.risk)

        console.print(peass_table)
        console.print()


def _get_score_color(score: int) -> str:
    if score >= 75:
        return "red"
    if score >= 40:
        return "orange"
    if score >= 15:
        return "yellow"
    return "green"
