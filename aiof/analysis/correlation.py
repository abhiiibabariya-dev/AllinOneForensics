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


def generate_triage_summary(parsed: dict[str, Any]) -> Dict[str, Any]:
    """Generates an automated heuristic triage summary with weighted risk scoring."""
    findings = parsed.get("findings", [])
    if isinstance(findings, dict):
        findings = findings.get("findings", [])

    severity_weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}
    total_score = 0
    breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    for f in findings:
        sev = f.get("severity", "Low")
        if sev not in breakdown:
            sev = "Low"
        breakdown[sev] += 1
        total_score += severity_weights.get(sev, 1)

    risk_level = "Low"
    if total_score >= 30 or breakdown["Critical"] > 0:
        risk_level = "Critical"
    elif total_score >= 15 or breakdown["High"] > 0:
        risk_level = "High"
    elif total_score >= 5 or breakdown["Medium"] > 0:
        risk_level = "Medium"

    correlations = correlate_cross_source(parsed)

    return {
        "risk_level": risk_level,
        "risk_score": total_score,
        "severity_breakdown": breakdown,
        "total_findings": len(findings),
        "cross_source_correlations": len(correlations),
        "correlations": correlations,
        "recommendation": f"Triage completed with risk level '{risk_level}' (Score: {total_score}). Review {breakdown['Critical']} critical and {breakdown['High']} high severity findings."
    }
