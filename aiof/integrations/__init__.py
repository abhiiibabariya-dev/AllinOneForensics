from __future__ import annotations

import json
from pathlib import Path
from typing import Any

class IntegrationsManager:
    @staticmethod
    def parse_mobsf_report(report_path: Path) -> dict[str, Any]:
        findings = []
        artifacts = {}
        try:
            data = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
            artifacts["mobsf_summary"] = {
                "app_name": data.get("app_name", "unknown"),
                "package_name": data.get("package_name", "unknown"),
                "security_score": data.get("security_score", 0),
            }
            sca = data.get("security_issues", {})
            for issue_id, details in sca.items():
                severity = details.get("severity", "Medium")
                if severity.lower() == "high":
                    sev = "High"
                elif severity.lower() == "critical":
                    sev = "Critical"
                else:
                    sev = "Medium"
                findings.append({
                    "severity": sev,
                    "category": "MobSF/Mobile",
                    "description": details.get("description", issue_id),
                    "detail": f"File: {details.get(\"file\", \"\")} | Ref: {details.get(\"cvss\", \"\")}",
                    "mitre": "T1418"
                })
        except Exception as exc:
            findings.append({"severity": "Low", "category": "MobSF", "description": "Failed to parse MobSF report", "detail": str(exc)})
        return {"parser": "mobsf", "artifacts": artifacts, "findings": findings}

    @staticmethod
    def export_to_iris(case_blob: dict[str, Any]) -> dict[str, Any]:
        iris_payload = {
            "title": case_blob.get("case_name", "AllinOneForensics Investigation"),
            "description": "Exported from AllinOneForensics workbench by Abhishek Babariya",
            "evidences": [],
            "notes": [],
            "indicators": []
        }
        for finding in case_blob.get("findings", []):
            iris_payload["notes"].append({
                "title": finding.get("description", ""),
                "content": f"Severity: {finding.get(\"severity\")} | Category: {finding.get(\"category\")} | Detail: {finding.get(\"detail\")}",
                "tags": [finding.get("category", "DFIR")]
            })
        for match in case_blob.get("ioc_matches", {}).get("matches", []):
            iris_payload["indicators"].append({
                "description": f"IOC match type {match.get(\"type\")}: {match.get(\"value\")}",
                "value": match.get("value"),
                "type": match.get("type")
            })
        return iris_payload
