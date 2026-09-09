import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List


class LinuxParser:
    """Parser for Linux artifacts."""

    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir
        self.findings: List[dict] = []

    def parse_all(self) -> dict:
        """Parse all Linux artifacts."""
        result = {
            "parser": "linux",
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": {},
            "findings": []
        }

        # Parse system logs
        for log_path in self.evidence_dir.glob("*.log"):
            result["artifacts"][log_path.name] = self._parse_log(log_path)

        # Parse bash history
        bash_hist = self.evidence_dir / ".bash_history"
        if bash_hist.exists():
            result["artifacts"][".bash_history"] = self._parse_bash_history(bash_hist)

        # Parse cron files
        cron_dir = self.evidence_dir / "etc" / "cron.d"
        if cron_dir.exists():
            result["artifacts"]["cron"] = self._parse_cron(cron_dir)

        self.findings = result["findings"]
        return result

    def _parse_log(self, path: Path) -> dict:
        """Parse a log file."""
        entries = []
        with open(path, "r", errors="ignore") as f:
            for line in f:
                entries.append({"line": line.strip()[:200]})
        return {"type": "log", "path": str(path), "entries": entries[:100]}

    def _parse_bash_history(self, path: Path) -> dict:
        """Parse bash history file."""
        commands = []
        with open(path, "r", errors="ignore") as f:
            for line in f:
                cmd = line.strip()
                if cmd and not cmd.startswith("#"):
                    commands.append({"command": cmd})
        return {"type": "bash_history", "path": str(path), "commands": commands[:100]}

    def _parse_cron(self, cron_dir: Path) -> dict:
        """Parse cron configuration files."""
        cron_jobs = []
        for job_file in cron_dir.glob("*"):
            if job_file.is_file():
                with open(job_file, "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            cron_jobs.append({"file": job_file.name, "job": line[:100]})
        return {"type": "cron", "jobs": cron_jobs}
