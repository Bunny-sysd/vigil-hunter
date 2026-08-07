"""
Target Topology & Attack Tree Visualizer.

Renders interactive terminal tree diagrams (using Rich Tree) and exportable HTML topology maps.
"""

from __future__ import annotations

from rich.tree import Tree
from vigil.models import ScanResult


class GraphReporter:
    """
    Generates Rich terminal tree representations of scan targets and attack vectors.
    """

    def generate_terminal_tree(self, scan_result: ScanResult) -> Tree:
        root = Tree("[bold cyan]🌐 TARGET TOPOLOGY & ATTACK SURFACE GRAPH[/bold cyan]")

        # Group services by host IP
        hosts: dict[str, list] = {}
        for s in scan_result.services:
            host_ip = s.host or "127.0.0.1"
            if host_ip not in hosts:
                hosts[host_ip] = []
            hosts[host_ip].append(s)

        for host_ip, services in hosts.items():
            host_node = root.add(f"[bold yellow]🖥️ Host: {host_ip}[/bold yellow]")

            for srv in services:
                srv_title = f"[cyan]Port {srv.port}/{srv.protocol}[/cyan] — [white]{srv.service_name} {srv.version}[/white]"
                srv_node = host_node.add(srv_title)

                # Attach CVE findings if present
                for cve in srv.cve_matches:
                    cve_id = cve.get("cve_id") or cve.get("id", "CVE")
                    cvss = cve.get("cvss", 0.0)
                    srv_node.add(f"[bold red]🔥 {cve_id}[/bold red] [dim](CVSS {cvss})[/dim]")

        # Findings without direct service mapping
        if scan_result.findings:
            findings_node = root.add("[bold red]🚨 Security Findings[/bold red]")
            for f in scan_result.findings:
                findings_node.add(f"[bold white]{f.title}[/bold white] [magenta]({f.severity.value})[/magenta]")

        return root
