from __future__ import annotations

import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class NetworkParser:
    def __init__(self, evidence_dir: Path):
        self.evidence_dir = Path(evidence_dir)
        self.findings: list[dict] = []

    def parse_all(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "parser": "network",
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": {
                "pcap_files": [],
                "conversations": [],
                "dns_queries": [],
                "http_hosts": [],
            },
            "findings": [],
        }
        for pcap in list(self.evidence_dir.rglob("*.pcap")) + list(self.evidence_dir.rglob("*.pcapng")):
            info = self._parse_pcap(pcap)
            result["artifacts"]["pcap_files"].append(info)
            result["artifacts"]["conversations"].extend(info.get("conversations", []))
            result["artifacts"]["dns_queries"].extend(info.get("dns", []))
            result["artifacts"]["http_hosts"].extend(info.get("http", []))
        result["findings"] = self.findings
        return result

    def _parse_pcap(self, path: Path) -> dict:
        result = {
            "path": str(path),
            "size": path.stat().st_size,
            "conversations": [],
            "dns": [],
            "http": [],
        }
        try:
            import dpkt
        except ImportError:
            result["parse_error"] = "dpkt not installed"
            return result
        try:
            with open(path, "rb") as handle:
                reader = dpkt.pcap.Reader(handle)
                ip_count = 0
                for _ts, buf in reader:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        ip = eth.data
                        if not isinstance(ip, dpkt.ip.IP):
                            continue
                        ip_count += 1
                        src = socket.inet_ntoa(ip.src)
                        dst = socket.inet_ntoa(ip.dst)
                        transport = ip.data
                        if isinstance(transport, dpkt.udp.UDP) and (transport.dport == 53 or transport.sport == 53):
                            try:
                                dns = dpkt.dns.DNS(transport.data)
                                for question in dns.qd:
                                    name = question.name
                                    if isinstance(name, bytes):
                                        name = name.decode(errors="ignore")
                                    result["dns"].append({"query": name, "src": src, "dst": dst})
                            except Exception:
                                pass
                        if isinstance(transport, dpkt.tcp.TCP) and (transport.dport in (80, 8080) or transport.sport in (80, 8080)):
                            result["http"].append({"src": f"{src}:{transport.sport}", "dst": f"{dst}:{transport.dport}"})
                    except Exception:
                        continue
            result["conversations"].append({"ip_packets": ip_count})
        except Exception as exc:
            result["parse_error"] = str(exc)
        return result
