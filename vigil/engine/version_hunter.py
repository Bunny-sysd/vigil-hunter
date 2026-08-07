"""
Service version discovery engine.
"""

from __future__ import annotations

from vigil.models import LogEntry, LogType, ServiceVersion


class VersionHunter:
    """
    Scans parsed LogEntries to find service versions discovered in the logs.
    """

    def extract_versions(self, entries: list[LogEntry]) -> list[ServiceVersion]:
        versions: list[ServiceVersion] = []
        seen = set()

        for entry in entries:
            # Service discoveries mapped from Nmap XML/Text or Service Discovery actions
            if entry.log_type == LogType.NMAP_XML or entry.action == "service_discovered" or "port" in entry.metadata:
                port = entry.metadata.get("port", 0)
                protocol = entry.metadata.get("protocol", "tcp")
                service = entry.metadata.get("service", "")
                version = entry.metadata.get("version", "")
                product = entry.metadata.get("product", "")
                cpe = entry.metadata.get("cpe", "")
                host = entry.source_ip or ""

                service_display = product if product else service

                if service_display or version:
                    key = (host, port, protocol, service_display, version)
                    if key not in seen:
                        versions.append(
                            ServiceVersion(
                                service_name=service_display,
                                version=version,
                                host=host,
                                port=port,
                                protocol=protocol,
                                cpe=cpe,
                            )
                        )
                        seen.add(key)

            # Web logs Server headers
            elif entry.log_type == LogType.WEB_ACCESS:
                server_hdr = entry.metadata.get("server", "")
                if server_hdr and "/" in server_hdr:
                    parts = server_hdr.split("/", 1)
                    name = parts[0]
                    ver = parts[1].split()[0]
                    key = (entry.source_ip or "", 80, "tcp", name, ver)
                    if key not in seen:
                        versions.append(
                            ServiceVersion(
                                service_name=name,
                                version=ver,
                                host=entry.source_ip or "",
                                port=80,
                                protocol="tcp",
                            )
                        )
                        seen.add(key)

        return versions
