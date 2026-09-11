from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class LinuxParser:
    def __init__(self, evidence_dir: Path):
        self.evidence_dir = Path(evidence_dir)
        self.findings: list[dict] = []

    def parse_all(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "parser": "linux",
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": {},
            "findings": [],
        }
        for log_path in list(self.evidence_dir.rglob("*.log")) + list(self.evidence_dir.rglob("auth.log")):
            if log_path.is_file():
                result["artifacts"][log_path.name] = self._parse_log(log_path)

        for hist in self.evidence_dir.rglob(".bash_history"):
            result["artifacts"][str(hist.relative_to(self.evidence_dir))] = self._parse_bash_history(hist)

        cron_dir = self.evidence_dir / "etc" / "cron.d"
        if cron_dir.exists():
            result["artifacts"]["cron"] = self._parse_cron(cron_dir)

        passwd = self.evidence_dir / "etc" / "passwd"
        if passwd.exists():
            result["artifacts"]["passwd"] = self._parse_passwd(passwd)

        result["findings"] = self.findings
        return result

    def _parse_log(self, path: Path) -> dict:
        entries = []
        keywords = ("Failed password", "Accepted password", "sudo:", "session opened", "Invalid user")
        with open(path, "r", errors="ignore") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                entries.append({"line": stripped[:300]})
                for keyword in keywords:
                    if keyword.lower() in stripped.lower():
                        self.findings.append(
                            {
                                "severity": "Medium" if "Failed" in keyword or "Invalid" in keyword else "Low",
                                "category": "Linux",
                                "description": keyword,
                                "detail": stripped[:300],
                            }
                        )
                        break
        return {"type": "log", "path": str(path), "entries": entries[:200]}

    def _parse_bash_history(self, path: Path) -> dict:
        commands = []
        suspicious = ("curl ", "wget ", "nc ", "ncat ", "python -c", "base64 ", "chmod +x")
        with open(path, "r", errors="ignore") as handle:
            for line in handle:
                cmd = line.strip()
                if not cmd or cmd.startswith("#"):
                    continue
                commands.append({"command": cmd})
                if any(token in cmd for token in suspicious):
                    self.findings.append(
                        {
                            "severity": "Medium",
                            "category": "Linux",
                            "description": "Suspicious shell history command",
                            "detail": cmd[:300],
                        }
                    )
        return {"type": "bash_history", "path": str(path), "commands": commands[:200]}

    def _parse_cron(self, cron_dir: Path) -> dict:
        jobs = []
        for job_file in cron_dir.glob("*"):
            if not job_file.is_file():
                continue
            with open(job_file, "r", errors="ignore") as handle:
                for line in handle:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        jobs.append({"file": job_file.name, "job": line[:200]})
        return {"type": "cron", "jobs": jobs}

    def _parse_passwd(self, path: Path) -> dict:
        users = []
        with open(path, "r", errors="ignore") as handle:
            for line in handle:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    users.append({"user": parts[0], "uid": parts[2], "shell": parts[6]})
                    if parts[2] == "0" and parts[0] != "root":
                        self.findings.append(
                            {
                                "severity": "High",
                                "category": "Linux",
                                "description": "Non-root UID 0 account",
                                "detail": parts[0],
                            }
                        )
        return {"type": "passwd", "users": users}
