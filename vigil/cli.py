"""
Vigil Security Engine — Command Line Interface (CLI) v0.4.0.

Commands:
    vigil analyze <target> [--format cli|json|html|markdown|sarif] [--output file] [--offline]
    vigil compass <target> [--phase recon|initial_access|privesc] [--note "guidance"] [--offline]
    vigil diff <target1> <target2> [--offline]
    vigil graph <target> [--offline]
    vigil session save|load|list
    vigil mitre <query> [--online]
    vigil config show | set-key
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

# Force UTF-8 output streams on Windows PowerShell to prevent cp1252 charmap encoding errors
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vigil.config import VigilConfig

console = Console()


@click.group()
@click.version_option(version="0.4.0", prog_name="vigil")
def main() -> None:
    """[COMPASS] Vigil Security Engine — AI-Powered Threat Hunting & Red Team Tactical Compass."""
    pass


@main.command(name="analyze")
@click.argument("target", type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path))
@click.option("--format", "-f", type=click.Choice(["cli", "json", "html", "markdown", "sarif"]), default=None, help="Output format.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None, help="Save report to file.")
@click.option("--mode", "-m", type=click.Choice(["default", "htb", "incident"]), default=None, help="Analysis mode.")
@click.option("--offline", is_flag=True, help="Disable external API queries.")
@click.option("--verbose", "-v", is_flag=True, help="Show verbose debug logs.")
def analyze(
    target: Path,
    format: str | None,
    output: Path | None,
    mode: str | None,
    offline: bool,
    verbose: bool,
) -> None:
    """Analyze log files, scan outputs, web source code, or directories for security threats."""
    config = VigilConfig.load()

    if mode:
        config.default_mode = mode
    if format:
        config.default_format = format
    if offline:
        config.offline_mode = True
    if verbose:
        config.verbose = True

    from vigil.engine.analyzer import ThreatAnalyzer

    files_to_scan = [target] if target.is_file() else [p for p in target.glob("**/*") if p.is_file() and not p.name.startswith(".")]

    if not files_to_scan:
        console.print("[yellow]Warning: No valid files found to analyze.[/yellow]")
        sys.exit(0)

    console.print(f"[bold cyan]Vigil Security Engine v0.4.0[/bold cyan]")
    console.print(f"Target: [bold white]{target}[/bold white] ({len(files_to_scan)} files)\n")

    analyzer = ThreatAnalyzer(config)

    with console.status("[bold cyan][1/3] Parsing log entries & scanning heuristics...[/bold cyan]"):
        scan_result = analyzer.run_scan(files_to_scan, mode=config.default_mode)

    out_format = config.default_format

    if out_format == "json":
        report_text = json.dumps(scan_result.to_dict(), indent=2)
        if output:
            output.write_text(report_text, encoding="utf-8")
            console.print(f"[bold green]✔ JSON report saved to {output}[/bold green]")
        else:
            console.print(report_text)
    elif out_format == "html":
        from vigil.reporters.html_reporter import HTMLReporter
        reporter = HTMLReporter()
        report_text = reporter.generate(scan_result)
        out_path = output or Path("vigil_report.html")
        out_path.write_text(report_text, encoding="utf-8")
        console.print(f"[bold green]✔ Executive HTML dashboard saved to {out_path}[/bold green]")
    elif out_format == "markdown":
        from vigil.reporters.markdown_reporter import MarkdownReporter
        reporter = MarkdownReporter()
        report_text = reporter.generate(scan_result)
        if output:
            output.write_text(report_text, encoding="utf-8")
            console.print(f"[bold green]✔ Markdown report saved to {output}[/bold green]")
        else:
            console.print(report_text)
    elif out_format == "sarif":
        from vigil.reporters.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        report_text = reporter.generate(scan_result)
        if output:
            output.write_text(report_text, encoding="utf-8")
            console.print(f"[bold green]✔ SARIF v2.1.0 report saved to {output}[/bold green]")
        else:
            console.print(report_text)
    else:
        from vigil.reporters.cli_reporter import CLIReporter
        reporter = CLIReporter(color=config.color_output)
        reporter.render(scan_result)

    sys.exit(0)


@main.command(name="compass")
@click.argument("target", type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path))
@click.option("--phase", "-p", type=click.Choice(["reconnaissance", "initial_access", "privilege_escalation"]), default="reconnaissance", help="Red Team attack phase.")
@click.option("--note", "-n", type=str, default="", help="Human Commander override note for the AI agent handoff.")
@click.option("--force", is_flag=True, help="Bypass phase locks and re-run agent.")
@click.option("--offline", is_flag=True, help="Use local vulnerability databases only (ultra-fast mode).")
def compass(target: Path, phase: str, note: str, force: bool, offline: bool) -> None:
    """Red Team Compass — Multi-Agent Orchestrator & Inter-Agent Handoff Advisor."""
    config = VigilConfig.load()
    if offline:
        config.offline_mode = True

    from vigil.engine.analyzer import ThreatAnalyzer
    from vigil.engine.compass import CompassEngine
    from vigil.engine.orchestrator import RedTeamOrchestrator

    files_to_scan = [target] if target.is_file() else [p for p in target.glob("**/*") if p.is_file() and not p.name.startswith(".")]

    console.print(f"[bold cyan]Running Vigil Red Team Multi-Agent Compass on {len(files_to_scan)} files...[/bold cyan]\n")

    analyzer = ThreatAnalyzer(config)

    with console.status("[bold cyan]Step 1/3: Parsing target scan logs & updating Blackboard Memory...[/bold cyan]"):
        scan_result = analyzer.run_scan(files_to_scan)

    session_id = target.name.replace(".", "_")
    orchestrator = RedTeamOrchestrator(ai_brain=analyzer.ai_brain, session_id=session_id)

    prev_handoff = orchestrator.memory.latest_handoff()
    if prev_handoff:
        console.print(Panel(
            f"[bold yellow]Previous Phase Completed:[/bold yellow] {prev_handoff.phase_completed.upper()}\n"
            f"[bold yellow]Source Agent:[/bold yellow] {prev_handoff.source_agent}\n"
            f"[bold yellow]Key Findings:[/bold yellow] {', '.join(prev_handoff.key_findings[:3])}\n"
            f"[bold yellow]Recommended Focus:[/bold yellow] {prev_handoff.recommended_focus}\n"
            f"[bold green]Human Override Note:[/bold green] {prev_handoff.human_notes or 'None'}",
            title="🧠 SHARED BLACKBOARD HANDOFF MEMORANDUM",
            border_style="cyan",
        ))

    provider_name = config.provider.upper() if analyzer.ai_brain and analyzer.ai_brain.provider else "HEURISTIC"
    with console.status(f"[bold magenta]Step 2/3: Executing Agent Phase ({phase.upper()}) via {provider_name}...[/bold magenta]"):
        orch_res = orchestrator.execute_phase(scan_result, phase=phase, force=force, human_note=note)

    if orch_res.get("status") == "blocked":
        console.print(Panel(
            f"[bold red]{orch_res.get('message')}[/bold red]",
            title="🔒 PHASE LOCK GUARDRAIL ALERT",
            border_style="red",
        ))
        sys.exit(0)

    compass_engine = CompassEngine(ai_brain=analyzer.ai_brain)
    compass_report = compass_engine.generate_report(scan_result)

    console.print(Panel(
        f"[bold white]{compass_report.summary_narrative}[/bold white]\n\n"
        f"[bold yellow]Active Red Team Phase:[/bold yellow] {phase.upper()}\n"
        f"[bold yellow]Overall Threat Level:[/bold yellow] {compass_report.threat_level}",
        title="COMPASS TACTICAL DIRECTIVE",
        border_style="magenta",
    ))

    if compass_report.recommendations:
        table = Table(title="Ranked Tactical Next Steps", show_header=True)
        table.add_column("#", style="dim", justify="right")
        table.add_column("Action Title", style="bold yellow")
        table.add_column("Kill Chain Phase", style="cyan")
        table.add_column("Suggested Command / Tool", style="green")

        for rec in compass_report.recommendations:
            table.add_row(
                str(rec.priority),
                rec.title,
                rec.phase,
                rec.suggested_command or rec.tool,
            )

        console.print(table)


@main.command(name="diff")
@click.argument("target1", type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path))
@click.argument("target2", type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path))
@click.option("--offline", is_flag=True, help="Disable external API queries.")
def diff(target1: Path, target2: Path, offline: bool) -> None:
    """Compare two scan outputs to highlight open/closed ports, version shifts, and new vulnerabilities."""
    config = VigilConfig.load()
    if offline:
        config.offline_mode = True

    from vigil.engine.analyzer import ThreatAnalyzer
    from vigil.engine.diff_engine import DiffEngine

    analyzer = ThreatAnalyzer(config)

    files1 = [target1] if target1.is_file() else [p for p in target1.glob("**/*") if p.is_file()]
    files2 = [target2] if target2.is_file() else [p for p in target2.glob("**/*") if p.is_file()]

    res1 = analyzer.run_scan(files1)
    res2 = analyzer.run_scan(files2)

    diff_engine = DiffEngine()
    scan_diff = diff_engine.compare_scans(res1, res2)

    console.print(f"[bold cyan]🔍 Comparing Scans: {target1.name} ➔ {target2.name}[/bold cyan]\n")

    if scan_diff.is_empty:
        console.print("[green]✔ No structural changes or new vulnerabilities detected between scans.[/green]")
        return

    table = Table(title="🔄 Delta Scan Comparison Results", show_header=True)
    table.add_column("Type", style="bold")
    table.add_column("Host:Port", style="cyan")
    table.add_column("Details", style="white")

    for s in scan_diff.added_services:
        table.add_row("[bold green]➕ ADDED[/bold green]", f"{s.host}:{s.port}", f"Newly opened service: {s.new_version}")

    for s in scan_diff.removed_services:
        table.add_row("[bold red]➖ REMOVED[/bold red]", f"{s.host}:{s.port}", f"Closed/Patched service: {s.old_version}")

    for s in scan_diff.changed_services:
        table.add_row("[bold yellow]✏️ MODIFIED[/bold yellow]", f"{s.host}:{s.port}", f"Version changed: {s.old_version} ➔ {s.new_version}")

    for f in scan_diff.new_findings:
        table.add_row("[bold red]🔥 NEW VULN[/bold red]", "Target", f"{f.title} ({f.severity})")

    for f in scan_diff.resolved_findings:
        table.add_row("[bold green]✔ RESOLVED[/bold green]", "Target", f"{f.title} ({f.severity})")

    console.print(table)


@main.command(name="graph")
@click.argument("target", type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path))
@click.option("--offline", is_flag=True, help="Disable external API queries.")
def graph(target: Path, offline: bool) -> None:
    """Render interactive terminal tree diagram of target topology and attack surface."""
    config = VigilConfig.load()
    if offline:
        config.offline_mode = True

    from vigil.engine.analyzer import ThreatAnalyzer
    from vigil.reporters.graph_reporter import GraphReporter

    files = [target] if target.is_file() else [p for p in target.glob("**/*") if p.is_file()]
    analyzer = ThreatAnalyzer(config)
    scan_result = analyzer.run_scan(files)

    reporter = GraphReporter()
    tree = reporter.generate_terminal_tree(scan_result)
    console.print(tree)


@main.group(name="session")
def session_group() -> None:
    """Manage campaign sessions and engagement snapshots."""
    pass


@session_group.command(name="save")
@click.argument("name")
def session_save(name: str) -> None:
    """Save current target session state to disk."""
    from vigil.engine.blackboard import BlackboardMemory
    from vigil.engine.session_manager import SessionManager

    sm = SessionManager()
    mem = BlackboardMemory(session_id=name)
    path = sm.save_session(name, mem)
    console.print(f"[bold green]✔ Successfully saved campaign session '{name}' to {path}[/bold green]")


@session_group.command(name="list")
def session_list() -> None:
    """List all saved campaign sessions."""
    from vigil.engine.session_manager import SessionManager

    sm = SessionManager()
    sessions = sm.list_sessions()

    if not sessions:
        console.print("[yellow]No saved campaign sessions found.[/yellow]")
        return

    table = Table(title="💾 Saved Campaign Sessions", show_header=True)
    table.add_column("Session Name", style="bold cyan")
    table.add_column("Targets", style="yellow")
    table.add_column("Completed Phases", style="magenta")

    for s in sessions:
        table.add_row(s.name, str(s.target_count), ", ".join(s.completed_phases) or "None")

    console.print(table)


@main.command(name="mitre")
@click.argument("query")
@click.option("--online", is_flag=True, help="Fetch live results directly from attack.mitre.org.")
def mitre_lookup(query: str, online: bool) -> None:
    """Lookup MITRE ATT&CK techniques by ID (e.g. T1110) or search keyword."""
    from vigil.engine.mitre_attack import get_technique, search_techniques

    if online:
        console.print(f"[cyan]Querying attack.mitre.org live for '{query}'...[/cyan]")

    if query.upper().startswith("T"):
        tech = get_technique(query, online=online)
        results = [tech] if tech else []
    else:
        results = search_techniques(query, online=online)

    if not results:
        console.print(f"[yellow]No MITRE ATT&CK techniques found for '{query}'.[/yellow]")
        return

    table = Table(title=f"MITRE ATT&CK Results for '{query}'", show_header=True)
    table.add_column("ID", style="bold red")
    table.add_column("Name", style="bold white")
    table.add_column("Tactic", style="magenta")
    table.add_column("Description", style="dim")

    for t in results:
        desc = t.get("description", "")
        if len(desc) > 80:
            desc = desc[:77] + "..."
        table.add_row(t.get("id", ""), t.get("name", ""), t.get("tactic", ""), desc)

    console.print(table)


@main.group(name="config")
def config_group() -> None:
    """Manage Vigil configuration and API keys."""
    pass


@config_group.command(name="show")
def config_show() -> None:
    """Display current configuration and active AI provider settings."""
    cfg = VigilConfig.load()
    console.print(Panel(
        f"[bold yellow]AI Provider:[/bold yellow] {cfg.provider}\n"
        f"[bold yellow]Gemini Key Configured:[/bold yellow] {'Yes' if cfg.gemini_key else 'No'}\n"
        f"[bold yellow]OpenAI Key Configured:[/bold yellow] {'Yes' if cfg.openai_key else 'No'}\n"
        f"[bold yellow]NVD Key Configured:[/bold yellow] {'Yes' if cfg.nvd_api_key else 'No'}\n"
        f"[bold yellow]Offline Mode:[/bold yellow] {cfg.offline_mode}\n"
        f"[bold yellow]Default Format:[/bold yellow] {cfg.default_format}\n"
        f"[bold yellow]Active Model:[/bold yellow] {cfg.active_model}",
        title="Vigil Configuration",
        border_style="cyan",
    ))


@config_group.command(name="set-key")
@click.argument("provider_name", type=click.Choice(["gemini", "openai", "nvd", "github"]))
@click.argument("api_key")
def config_set_key(provider_name: str, api_key: str) -> None:
    """Securely set an API key for a provider."""
    cfg = VigilConfig.load()
    cfg.save_key(provider_name, api_key)
    console.print(f"[bold green]✔ Successfully saved API key for '{provider_name}'.[/bold green]")


if __name__ == "__main__":
    main()
