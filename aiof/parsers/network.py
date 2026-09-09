import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List


class NetworkParser:
    """Parser for network artifacts (pcap)."""

    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir
        self.findings: List[dict] = []

    def parse_all(self) -> dict:
        """Parse all network artifacts."""
        result = {
            "parser": "network",
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "pcap_files": [],
            "conversations": [],
            "dns_queries": [],
            "http_hosts": [],
            "findings": []
        }

        for pcap in self.evidence_dir.glob("*.pcap"):
            pcap_info = self._parse_pcap(pcap)
            result["pcap_files"].append(pcap_info)
            result["conversations"].extend(pcap_info.get("conversations", []))
            result["dns_queries"].extend(pcap_info.get("dns", []))
            result["http_hosts"].extend(pcap_info.get("http", []))

        self.findings = result["findings"]
        return result

    def _parse_pcap(self, path: Path) -> dict:
        """Parse a pcap file (basic analysis)."""
        result = {
            "path": str(path),
            "size": path.stat().st_size,
            "conversations": [],
            "dns": [],
            "http": []
        }

        try:
            import dpkt
            import struct

            with open(path, "rb") as f:
                pcap = dpkt.pcap.Reader(f)
                ip_count = 0
                for ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue
                        ip = eth.data

                        # Count IP packets
                        ip_count += 1

                        # Extract DNS
                        if hasattr(ip, "data") and isinstance(ip.data, dpkt.dns.DNS):
                            dns = ip.data
                            for q in dns.qd:
                                if hasattr(q, "name") and q.name:
                                    result["dns"].append({"query": q.name.decode() if isinstance(q.name, bytes) else str(q.name)})

                        # Extract TCP (basic)
                        if hasattr(ip, "data") and isinstance(ip.data, dpkt.tcp.TCP):
                            tcp = ip.data
                            if tcp.dport == 80 or tcp.sport == 80:
                                result["http"].append({"src": f"{self._ip2str(ip.sip)}:{tcp.sport}", "dst": f"{self._ip2str(ip.dip)}:{tcp.dport}"})

                    except Exception:
                        continue

            result["conversations"].append({"ip_packets": ip_count})

        except ImportError:
            result["parse_error"] = "dpkt not installed"
        except Exception as e:
            result["parse_error"] = str(e)

        return result

    def _ip2str(self, ip: int) -> str:
        """Convert integer IP to string."""
        return ".".join(str((ip >> (8 * j)) & 0xff) for j in (3, 2, 1, 0))
