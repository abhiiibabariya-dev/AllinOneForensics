from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CloudParser:
    def __init__(self, evidence_dir: Path):
        self.evidence_dir = Path(evidence_dir)
        self.findings: list[dict] = []

    def parse_all(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "parser": "cloud",
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": {
                "cloudtrail": [],
                "azure_activity": [],
                "gcp_audit": [],
            },
            "findings": [],
        }
        for path in self.evidence_dir.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl"}:
                continue
            name = path.name.lower()
            try:
                if "cloudtrail" in name or "aws" in name:
                    result["artifacts"]["cloudtrail"].extend(self._parse_cloudtrail(path))
                elif "azure" in name:
                    result["artifacts"]["azure_activity"].extend(self._parse_azure(path))
                elif "gcp" in name:
                    result["artifacts"]["gcp_audit"].extend(self._parse_gcp(path))
            except Exception as exc:
                self.findings.append(
                    {
                        "severity": "Low",
                        "category": "Cloud",
                        "description": f"Failed to parse {path.name}",
                        "detail": str(exc),
                    }
                )
        self.findings.extend(self._analyze(result["artifacts"]))
        result["findings"] = self.findings
        return result

    def _load_json_records(self, path: Path) -> list[dict]:
        text = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not text:
            return []
        if text.startswith("["):
            data = json.loads(text)
            return data if isinstance(data, list) else [data]
        if text.startswith("{"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return self._load_jsonl(text)
            if isinstance(data, dict) and "Records" in data:
                return list(data.get("Records") or [])
            if isinstance(data, dict) and "value" in data:
                return list(data.get("value") or [])
            return [data]
        return self._load_jsonl(text)

    def _load_jsonl(self, text: str) -> list[dict]:
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

    def _parse_cloudtrail(self, path: Path) -> list[dict]:
        events = []
        for event in self._load_json_records(path):
            identity = event.get("userIdentity") or {}
            additional = event.get("additionalEventData") or {}
            events.append(
                {
                    "event_time": event.get("eventTime", ""),
                    "event_name": event.get("eventName", ""),
                    "user_identity": identity.get("userName") or identity.get("arn", ""),
                    "source_ip": event.get("sourceIPAddress", ""),
                    "event_source": event.get("eventSource", ""),
                    "mfa_used": additional.get("MFAUsed") or additional.get("mfa_used", ""),
                }
            )
        return events[:500]

    def _parse_azure(self, path: Path) -> list[dict]:
        events = []
        for record in self._load_json_records(path):
            operation = record.get("operationName")
            if isinstance(operation, dict):
                operation = operation.get("value", "")
            events.append(
                {
                    "event_time": record.get("eventTimestamp") or record.get("time", ""),
                    "operation_name": operation or "",
                    "caller_ip": record.get("callerIpAddress", ""),
                    "identity": record.get("identity", {}),
                }
            )
        return events[:500]

    def _parse_gcp(self, path: Path) -> list[dict]:
        events = []
        for event in self._load_json_records(path):
            payload = event.get("protoPayload") or {}
            auth = payload.get("authenticationInfo") or event.get("authenticationInfo") or {}
            events.append(
                {
                    "timestamp": event.get("timestamp", ""),
                    "method_name": payload.get("methodName", ""),
                    "principal": auth.get("principalEmail", ""),
                    "resource_name": (event.get("resource") or {}).get("name", ""),
                }
            )
        return events[:500]

    def _analyze(self, artifacts: dict) -> list[dict]:
        findings = []
        privileged = {"ConsoleLogin", "CreateAccessKey", "CreateUser", "AttachUserPolicy", "PutBucketPolicy"}
        for event in artifacts.get("cloudtrail", []):
            if event.get("event_name") in privileged:
                findings.append(
                    {
                        "severity": "High",
                        "category": "Cloud",
                        "description": f"Privileged CloudTrail action: {event.get('event_name')}",
                        "detail": f"{event.get('user_identity')} from {event.get('source_ip')}",
                    }
                )
            if event.get("event_name") == "ConsoleLogin" and str(event.get("mfa_used")).upper() not in {"YES", "TRUE"}:
                findings.append(
                    {
                        "severity": "High",
                        "category": "Cloud",
                        "description": "Console login without MFA",
                        "detail": f"{event.get('user_identity')} from {event.get('source_ip')}",
                    }
                )
        return findings[:50]
