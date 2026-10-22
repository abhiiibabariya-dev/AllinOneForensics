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
