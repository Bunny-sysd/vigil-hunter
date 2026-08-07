"""
Ingestor for Nmap XML output files (-oX).
"""

from __future__ import annotations

import logging
from pathlib import Path
import xml.etree.ElementTree as ET

from vigil.ingestors.base import BaseIngestor
from vigil.models import LogEntry, LogType

logger = logging.getLogger("vigil.ingestors.nmap_xml")


class NmapXmlIngestor(BaseIngestor):
    """
    Ingestor for Nmap XML scan results.

    Extracts open ports, services, product names, versions, and hosts.
    Generates LogEntry objects representing the discovery state.
    """

    def can_ingest(self, filepath: Path) -> bool:
        if not filepath.is_file():
            return False
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                head = [f.readline() for _ in range(5)]
            return self.detect_format(head)
        except Exception:
            return False

    def detect_format(self, sample_lines: list[str]) -> bool:
        combined = "".join(sample_lines)
        return "<nmaprun" in combined or "<host" in combined and "<ports" in combined

    def ingest(self, filepath: Path) -> list[LogEntry]:
        entries: list[LogEntry] = []
        source_name = filepath.name

        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML {source_name}: {e}")
            return []

        # Find scan start time
        scan_time_str = root.attrib.get("start")
        scan_time = float(scan_time_str) if scan_time_str and scan_time_str.isdigit() else None

        for host_node in root.findall("host"):
            status_node = host_node.find("status")
            if status_node is not None and status_node.attrib.get("state") != "up":
                continue  # Skip down hosts

            # Get host address
            host_ip = ""
            addr_nodes = host_node.findall("address")
            for addr in addr_nodes:
                if addr.attrib.get("addrtype") == "ipv4":
                    host_ip = addr.attrib.get("addr")
                    break
            if not host_ip and addr_nodes:
                host_ip = addr_nodes[0].attrib.get("addr", "")

            # Get hostnames
            hostnames = []
            hostnames_node = host_node.find("hostnames")
            if hostnames_node is not None:
                for hn in hostnames_node.findall("hostname"):
                    name = hn.attrib.get("name")
                    if name:
                        hostnames.append(name)

            hostname = hostnames[0] if hostnames else host_ip

            # Parse ports
            ports_node = host_node.find("ports")
            if ports_node is None:
                continue

            for port_node in ports_node.findall("port"):
                state_node = port_node.find("state")
                if state_node is None or state_node.attrib.get("state") != "open":
                    continue

                port = int(port_node.attrib.get("portid", 0))
                protocol = port_node.attrib.get("protocol", "tcp")

                service_node = port_node.find("service")
                service_name = ""
                product = ""
                version = ""
                cpe_str = ""

                if service_node is not None:
                    service_name = service_node.attrib.get("name", "")
                    product = service_node.attrib.get("product", "")
                    version = service_node.attrib.get("version", "")
                    
                    # Extract first CPE if present
                    cpe_nodes = service_node.findall("cpe")
                    if cpe_nodes:
                        cpe_str = cpe_nodes[0].text or ""

                # Build discovery action
                action = "service_discovered"
                raw_line = f"Host: {host_ip} ({hostname}) | Port: {port}/{protocol} | Service: {service_name} | Product: {product} | Version: {version}"

                metadata = {
                    "port": port,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "cpe": cpe_str,
                    "hostname": hostname,
                }

                entry = LogEntry(
                    timestamp=scan_time,
                    source_ip=host_ip,
                    action=action,
                    raw_line=raw_line,
                    line_number=0,
                    source_file=source_name,
                    log_type=LogType.NMAP_XML,
                    metadata=metadata,
                )
                entries.append(entry)

        return entries
