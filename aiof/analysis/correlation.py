from __future__ import annotations

from typing import Any, Dict, List


def correlate_cross_source(parsed: dict[str, Any]) -> List[Dict[str, Any]]:
    """Correlates indicators across multiple forensic artifact sources (e.g., memory, windows, linux)."""
    correlations: List[Dict[str, Any]] = []
    modules = parsed.get("modules", parsed)

    ips_seen: Dict[str, List[str]] = {}
    hashes_seen: Dict[str, List[str]] = {}

    for mod_name, mod_data in modules.items():
        if not isinstance(mod_data, dict):
            continue
        artifacts = mod_data.get("artifacts", {})
        for art_name, payload in artifacts.items():
            items = payload if isinstance(payload, list) else [payload]
            for item in items:
                if isinstance(item, dict):
                    # Check IPs
                    for ip_key in ["remote_ip", "ip", "src_ip"]:
                        ip = item.get(ip_key)
                        if ip:
                            ips_seen.setdefault(str(ip), []).append(f"{mod_name}/{art_name}")
                    # Check hashes
                    for h_key in ["hash_sha256", "hash", "sha256"]:
                        h = item.get(h_key)
                        if h:
                            hashes_seen.setdefault(str(h), []).append(f"{mod_name}/{art_name}")

    for ip, sources in ips_seen.items():
        if len(set(sources)) > 1:
            correlations.append({
                "type": "Cross-Source IP Correlation",
                "indicator": ip,
                "sources": list(set(sources)),
                "severity": "High",
                "description": f"IP address {ip} observed across multiple artifact sources: {sources}"
            })

    for h, sources in hashes_seen.items():
        if len(set(sources)) > 1:
            correlations.append({
                "type": "Cross-Source Hash Correlation",
                "indicator": h,
                "sources": list(set(sources)),
                "severity": "High",
                "description": f"File hash {h} observed across multiple artifact sources: {sources}"
            })

    return correlations
