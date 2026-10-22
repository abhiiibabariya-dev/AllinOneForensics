from __future__ import annotations

import email
import email.policy
import re
from pathlib import Path
from typing import Any


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_AUTH_RE = re.compile(r"(dkim|spf|dmarc)=(pass|fail|none|softfail|neutral|permerror|temperror)", re.IGNORECASE)


class EmailParser:
    def __init__(self, evidence_dir: Path) -> None:
        self.evidence_dir = evidence_dir

    def parse_all(self) -> dict[str, Any]:
        artifacts: dict[str, Any] = {"emails": []}
        findings: list[dict[str, Any]] = []

        if not self.evidence_dir.exists():
            return {"parser": "email", "artifacts": artifacts, "findings": findings}

        for path in self.evidence_dir.rglob("*"):
            if not path.is_file():
                continue
            suf = path.suffix.lower()
            if suf not in {".eml", ".msg", ".txt"} and "mail" not in path.name.lower():
                continue
            try:
                raw = path.read_bytes()
                msg = email.message_from_bytes(raw, policy=email.policy.default)
            except Exception:
                continue

            subject = str(msg.get("subject", ""))
            from_addr = str(msg.get("from", ""))
            to_addr = str(msg.get("to", ""))
            date = str(msg.get("date", ""))
            message_id = str(msg.get("message-id", ""))
            received_headers = msg.get_all("received") or []
            auth_results = str(msg.get("authentication-results", ""))
            dkim_sig = str(msg.get("dkim-signature", ""))

            relay_ips: list[str] = []
            for hdr in received_headers:
                relay_ips.extend(_IP_RE.findall(str(hdr)))

            auth_checks: dict[str, str] = {}
            for m in _AUTH_RE.finditer(auth_results):
                auth_checks[m.group(1).lower()] = m.group(2).lower()

            body_text = ""
            try:
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body_text = part.get_content()
                            break
                else:
                    body_text = msg.get_content()
            except Exception:
                pass

            urls = re.findall(r"https?://[^\s\"<>]+", body_text)
            attachments = [
                part.get_filename() for part in msg.walk()
                if part.get_content_disposition() == "attachment" and part.get_filename()
            ]

            entry = {
                "source": path.name,
                "message_id": message_id,
                "from": from_addr,
                "to": to_addr,
                "subject": subject,
                "date": date,
                "relay_ips": list(dict.fromkeys(relay_ips)),
                "auth": auth_checks,
                "urls": urls[:50],
                "attachments": attachments,
            }
            artifacts["emails"].append(entry)

            if auth_checks.get("spf") in {"fail", "softfail"} or auth_checks.get("dkim") == "fail":
                findings.append({
                    "severity": "High",
                    "category": "Email",
                    "description": "Email authentication failure (SPF/DKIM) — possible spoofing",
                    "detail": f"From: {from_addr} | Auth: {auth_checks} | File: {path.name}",
                    "mitre": "T1566.001",
                })

            if not dkim_sig and not auth_checks:
                findings.append({
                    "severity": "Medium",
                    "category": "Email",
                    "description": "Email lacks authentication headers (no DKIM/SPF)",
                    "detail": f"Subject: {subject} | From: {from_addr}",
                    "mitre": "T1566",
                })

            suspicious_ext = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr", ".lnk", ".iso"}
            for att in attachments:
                if any(att.lower().endswith(e) for e in suspicious_ext):
                    findings.append({
                        "severity": "Critical",
                        "category": "Email",
                        "description": f"Suspicious attachment in email: {att}",
                        "detail": f"Subject: {subject} | From: {from_addr}",
                        "mitre": "T1566.001",
                    })

        return {"parser": "email", "artifacts": artifacts, "findings": findings}
