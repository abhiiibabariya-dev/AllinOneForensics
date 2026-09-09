import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, List


class CloudParser:
    """Parser for cloud audit logs."""

    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir
        self.findings: List[dict] = []

    def parse_all(self) -> dict:
        """Parse all cloud audit logs."""
        result = {
            "parser": "cloud",
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "cloudtrail": [],
            "azure_activity": [],
            "gcp_audit": [],
            "findings": []
        }

        # Parse CloudTrail
        for trail in self.evidence_dir.glob("*cloudtrail*"):
            if trail.suffix in (".json", ".jsonl"):
                result["cloudtrail"].extend(self._parse_cloudtrail(trail))

        # Parse Azure Activity
        for azure in self.evidence_dir.glob("*azure*"):
            if azure.suffix == ".json":
                result["azure_activity"].extend(self._parse_azure(azure))

        # Parse GCP Audit
        for gcp in self.evidence_dir.glob("*gcp*"):
            if gcp.suffix in (".json", ".jsonl"):
                result["gcp_audit"].extend(self._parse_gcp(gcp))

        self.findings = self._analyze_findings(result)
        result["findings"] = self.findings
        return result

    def _parse_cloudtrail(self, path: Path) -> List[dict]:
        """Parse CloudTrail log."""
        events = []
        with open(path, "r") as f:
            content = f.read()
            if content.strip().startswith("["):
                data = json.loads(content)
            else:
                data = []
                for line in content.strip().split("\n"):
                    try:
                        data.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            for event in data.get("Records", []):
                events.append({
                    "event_time": event.get("eventTime", ""),
                    "event_name": event.get("eventName", ""),
                    "user_identity": event.get("userIdentity", {}).get("userName", ""),
                    "source_ip": event.get("sourceIPAddress", ""),
                    "event_source": event.get("eventSource", "")
                })

        return events[:500]  # Limit for report

    def _parse_azure(self, path: Path) -> List[dict]:
        """Parse Azure Activity log."""
        events = []
        with open(path, "r") as f:
            data = json.loads(f.read())
            for record in data.get("value", []):
                events.append({
                    "event_time": record.get("eventTimestamp", ""),
                    "operation_name": record.get("operationName", {}).get("value", ""),
                    "category": record.get("category", ""),
                    "caller_ip": record.get("callerIpAddress", ""),
                    "identity": record.get("identity", {})
                })

        return events[:500]

    def _parse_gcp(self, path: Path) -> List[dict]:
        """Parse GCP Audit log."""
        events = []
        with open(path, "r") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    events.append({
                        "timestamp": event.get("timestamp", ""),
                        "method_name": event.get("protoPayload", {}).get("methodName", ""),
                        "authentication_info": event.get("authenticationInfo", {}).get("principalEmail", ""),
                        "resource_name": event.get("resource", {}).get("name", "")
                    })
                except json.JSONDecodeError:
                    continue

        return events[:500]

    def _analyze_findings(self, result: dict) -> List[dict]:
        """Analyze findings from cloud logs."""
        findings = []

        # Check for privileged actions
        privileged_events = ["ConsoleLogin", "CreateAccessKey", "CreateUser", "AttachPolicy"]
        for event in result.get("cloudtrail", []):
            if event.get("event_name") in privileged_events:
                findings.append({
                    "severity": "High",
                    "finding": "Privileged action detected",
                    "event": event.get("event_name"),
                    "user": event.get("user_identity"),
                    "source_ip": event.get("source_ip")
                })

        # Check for MFA-less login
        for event in result.get("cloudtrail", []):
            if event.get("event_name") == "ConsoleLogin":
                mfa = event.get("additional_event_attributes", {}).get("mfa_used")
                if mfa != "TRUE":
                    findings.append({
                        "severity": "High",
                        "finding": "Console login without MFA",
                        "user": event.get("user_identity"),
                        "source_ip": event.get("source_ip")
                    })

        return findings[:50]  # Limit findings
