from __future__ import annotations

from typing import Any

_TECHNIQUE_MAP: dict[str, list[str]] = {
    # Execution
    "powershell": ["T1059.001"],
    "cmd.exe": ["T1059.003"],
    "wscript": ["T1059.005"],
    "cscript": ["T1059.005"],
    "mshta": ["T1218.005"],
    "rundll32": ["T1218.011"],
    "regsvr32": ["T1218.010"],
    "certutil": ["T1140"],
    "bash history": ["T1059.004"],
    "crontab": ["T1053.003"],
    "launchagent": ["T1543.001"],
    "systemd": ["T1543.002"],
    # Persistence
    "run key": ["T1547.001"],
    "startup folder": ["T1547.001"],
    "scheduled task": ["T1053.005"],
    "clusterrolebinding": ["T1078.001"],
    # Privilege Escalation
    "privileged container": ["T1611"],
    "pid_mode": ["T1611"],
    "host volume": ["T1611"],
    # Defense Evasion
    "eventlog": ["T1070.001"],
    "prefetch": ["T1070.004"],
    "amcache": ["T1059"],
    # Credential Access
    "lsass": ["T1003.001"],
    "sam": ["T1003.002"],
    "dpapi": ["T1555"],
    "mimikatz": ["T1003.001"],
    # Discovery
    "whoami": ["T1033"],
    "ipconfig": ["T1016"],
    "netstat": ["T1049"],
    # Lateral Movement
    "rdp": ["T1021.001"],
    "psexec": ["T1021.002"],
    "wmi": ["T1047"],
    # Collection
    "clipboard": ["T1115"],
    # Exfiltration
    "dns tunnel": ["T1048.003"],
    "beaconing": ["T1071.001"],
    # Initial Access
    "phishing": ["T1566"],
    "spf fail": ["T1566.001"],
    "dkim fail": ["T1566.001"],
    "suspicious attachment": ["T1566.001"],
    "unauthenticated": ["T1190"],
    # Impact
    "ransomware": ["T1486"],
    "encrypt": ["T1486"],
}


def tag_finding(finding: dict[str, Any]) -> dict[str, Any]:
    if "mitre" in finding:
        return finding
    desc = (finding.get("description", "") + " " + finding.get("detail", "")).lower()
    techniques: list[str] = []
    for keyword, techs in _TECHNIQUE_MAP.items():
        if keyword in desc:
            for t in techs:
                if t not in techniques:
                    techniques.append(t)
    if techniques:
        finding = {**finding, "mitre": techniques[0] if len(techniques) == 1 else techniques}
    return finding


def tag_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [tag_finding(f) for f in findings]


def generate_mitre_heatmap(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Generates a MITRE ATT&CK tactic/technique heatmap summary matrix from findings."""
    tagged = tag_findings(findings)
    tactics_summary: dict[str, int] = {
        "Initial Access": 0,
        "Execution": 0,
        "Persistence": 0,
        "Privilege Escalation": 0,
        "Defense Evasion": 0,
        "Credential Access": 0,
        "Discovery": 0,
        "Lateral Movement": 0,
        "Collection": 0,
        "Exfiltration": 0,
        "Impact": 0,
    }
    technique_counts: dict[str, int] = {}

    technique_to_tactic = {
        "T1566": "Initial Access", "T1190": "Initial Access", "T1078": "Initial Access",
        "T1059": "Execution", "T1218": "Execution", "T1140": "Execution", "T1053": "Execution", "T1543": "Execution",
        "T1547": "Persistence",
        "T1611": "Privilege Escalation",
        "T1070": "Defense Evasion", "T1070.001": "Defense Evasion", "T1070.004": "Defense Evasion",
        "T1003": "Credential Access", "T1555": "Credential Access",
        "T1033": "Discovery", "T1016": "Discovery", "T1049": "Discovery",
        "T1021": "Lateral Movement", "T1047": "Lateral Movement",
        "T1115": "Collection",
        "T1048": "Exfiltration", "T1071": "Exfiltration",
        "T1486": "Impact"
    }

    for f in tagged:
        mitre = f.get("mitre")
        if not mitre:
            continue
        techs = [mitre] if isinstance(mitre, str) else mitre
        for t in techs:
            technique_counts[t] = technique_counts.get(t, 0) + 1
            base_t = t.split(".")[0]
            tactic = technique_to_tactic.get(base_t, "Execution")
            tactics_summary[tactic] = tactics_summary.get(tactic, 0) + 1

    return {
        "total_mapped_findings": sum(technique_counts.values()),
        "tactics_heatmap": tactics_summary,
        "technique_counts": technique_counts,
    }
