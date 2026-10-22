from __future__ import annotations

import json
from pathlib import Path
from typing import Any

class MemoryParser:
    def __init__(self, evidence_dir: Path) -> None:
        self.evidence_dir = evidence_dir

    def parse_all(self) -> dict[str, Any]:
        artifacts: dict[str, Any] = {"processes": [], "network_sockets": [], "malfind_injections": []}
        findings: list[dict[str, Any]] = []

        if not self.evidence_dir.exists():
            return {"parser": "memory", "artifacts": artifacts, "findings": findings}

        for path in self.evidence_dir.rglob("*"):
            if not path.is_file():
                continue
            name_lower = path.name.lower()
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                data = json.loads(content)
            except Exception:
                continue

            rows = data if isinstance(data, list) else [data]
            for row in rows:
                if "ImageFileName" in row or "PID" in row:
                    pid = row.get("PID", row.get("ProcessId", 0))
                    ppid = row.get("PPID", row.get("ParentProcessId", 0))
                    name = row.get("ImageFileName", row.get("Name", "unknown"))
                    artifacts["processes"].append({"pid": pid, "ppid": ppid, "name": name})

                if "Offset" in row and "Protection" in row and ("malfind" in name_lower or "inject" in name_lower):
                    findings.append({
                        "severity": "Critical",
                        "category": "Memory Forensics",
                        "description": f"Potential process injection detected in PID {row.get(\"PID\", \"unknown\")}",
                        "detail": f"Malfind match at offset {row.get(\"Offset\")} with protection {row.get(\"Protection\")}",
                        "mitre": "T1055"
                    })
                    artifacts["malfind_injections"].append(row)

                if "LocalAddr" in row or "ForeignAddr" in row:
                    artifacts["network_sockets"].append(row)

        return {"parser": "memory", "artifacts": artifacts, "findings": findings}
