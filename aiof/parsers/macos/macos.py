import json
import sqlite3
import plistlib
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any


class macOSParser:
    """Parser for macOS artifacts.

    Reads evidence files offline. Never modifies evidence.
    All sections are wrapped in try/except so a single artifact failure
    never crashes the run.
    """

    def __init__(self, evidence_dir: Path):
        self.evidence_dir = Path(evidence_dir)
        self.findings: List[dict] = []

    def parse_all(self) -> Dict[str, Any]:
        """Parse every macOS artifact found under *evidence_dir*."""
        result: Dict[str, Any] = {
            "parser": "macos",
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": {},
            "findings": [],
        }

        self._parse_unified_logs(result)
        self._parse_launch_plists(result, "LaunchDaemons", "/Library/LaunchDaemons")
        self._parse_launch_plists(result, "LaunchAgents", "/Library/LaunchAgents")
        self._parse_launch_plists(result, "UserLaunchAgents", "~/Library/LaunchAgents")
        self._parse_quarantine_events(result)
        self._parse_safari_history(result)
        self._parse_chrome_history(result)

        result["findings"] = self.findings
        return result

    # ------------------------------------------------------------------
    # Unified log (plain-text export, best-effort)
    # ------------------------------------------------------------------

    def _parse_unified_logs(self, result: dict) -> None:
        """Handle logexport .log / .txt dumps produced by 'log collect'."""
        try:
            collected: List[dict] = []
            for log_path in self.evidence_dir.glob("*.log"):
                collected.extend(self._read_log_lines(log_path))
            for txt_path in self.evidence_dir.glob("*.txt"):
                collected.extend(self._read_log_lines(txt_path))
            if collected:
                result["artifacts"]["unified_log"] = collected[:500]
        except Exception as exc:  # pragma: no cover – defensive
            self._add_finding("High", "Unified Log Parse Error", str(exc))

    @staticmethod
    def _read_log_lines(path: Path) -> List[dict]:
        entries: List[dict] = []
        try:
            with open(path, "r", errors="ignore") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped:
                        entries.append({"line": stripped[:300]})
        except Exception:
            pass
        return entries[:200]

    # ------------------------------------------------------------------
    # LaunchAgents / LaunchDaemons plist parsing
    # ------------------------------------------------------------------

    # Well-known Apple bundle-identifier prefixes.
    _KNOWN_PREFIXES = (
        "com.apple.",
        "com.microsoft.",
        "com.google.",
        "com.github.",
        "com.docker.",
        "org.virtualbox.",
        "us.zoom.",
        "io.",
    )

    def _parse_launch_plists(self, result: dict, label: str, rel_dir: str) -> None:
        """Parse plist files from a LaunchAgents or LaunchDaemons directory."""
        try:
            plist_dir = self.evidence_dir / rel_dir.lstrip("/")
            if not plist_dir.exists():
                return
            entries: List[dict] = []
            for plist_path in sorted(plist_dir.glob("*.plist")):
                entry = self._parse_single_plist(plist_path)
                entries.append(entry)
                self._evaluate_persistence(entry, label)
            if entries:
                result["artifacts"][label] = entries
        except Exception as exc:
            self._add_finding("High", f"{label} Parse Error", str(exc))

    def _parse_single_plist(self, path: Path) -> Dict[str, Any]:
        """Return a serialisable dict for one plist file."""
        try:
            with open(path, "rb") as fh:
                data = plistlib.load(fh)
            return {
                "file": path.name,
                "Label": data.get("Label", ""),
                "ProgramArguments": [
                    str(a) for a in (data.get("ProgramArguments") or [])
                ],
                "RunAtLoad": data.get("RunAtLoad", False),
                "KeepAlive": data.get("KeepAlive", False),
                "StartInterval": data.get("StartInterval"),
                "WorkingDirectory": data.get("WorkingDirectory", ""),
            }
        except Exception as exc:
            return {"file": path.name, "error": str(exc)}

    def _evaluate_persistence(self, entry: dict, label: str) -> None:
        """Flag suspicious LaunchAgent / LaunchDaemon entries."""
        program_args = entry.get("ProgramArguments", [])
        executable = program_args[0] if program_args else ""
        bundle_id = entry.get("Label", "")

        # Unknown vendor – potential persistence risk
        if bundle_id and not any(
            bundle_id.startswith(p) for p in self._KNOWN_PREFIXES
        ):
            self._add_finding(
                "Medium",
                "Unknown LaunchAgent/Daemon (persistence risk)",
                f"Label '{bundle_id}' does not match a known vendor prefix. "
                f"Verify legitimacy. Executable: {executable}",
            )

        # KeepAlive creates automatic restart – persistence mechanism
        if entry.get("KeepAlive"):
            self._add_finding(
                "Medium",
                "KeepAlive persistence enabled",
                f"'{bundle_id}' uses KeepAlive – the OS will restart it if it terminates.",
            )

        # Suspicious paths (outside /usr/bin, /usr/sbin, /System, /Applications)
        safe_prefixes = ("/usr/bin", "/usr/sbin", "/System", "/Applications", "/bin", "/sbin")
        if executable and not any(executable.startswith(p) for p in safe_prefixes):
            self._add_finding(
                "Medium",
                "Executable outside standard directories",
                f"'{bundle_id}' runs '{executable}'. Confirm it is expected.",
            )

    # ------------------------------------------------------------------
    # Quarantine Events (com.apple.LaunchServices.QuarantineEventsV2)
    # ------------------------------------------------------------------

    def _parse_quarantine_events(self, result: dict) -> None:
        """Parse the Launch Services Quarantine SQLite database."""
        db_path = self.evidence_dir / "com.apple.LaunchServices.QuarantineEventsV2"
        if not db_path.exists():
            return
        events: List[dict] = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Schema: LSQuarantineEvent with columns: key, date, bundle-id, type, sender-bundle-id, sender-address, data-url, origin-url
            cursor.execute(
                "SELECT key, date, \"bundle-id\", type, \"sender-bundle-id\", "
                "\"sender-address\", \"data-url\", \"origin-url\" "
                "FROM LSQuarantineEvent ORDER BY date DESC LIMIT 200"
            )
            for row in cursor:
                events.append({
                    "key": row[0],
                    "date": row[1],
                    "bundle_id": row[2],
                    "type": row[3],
                    "sender_bundle_id": row[4],
                    "sender_address": row[5],
                    "data_url": row[6],
                    "origin_url": row[7],
                })
            conn.close()
        except Exception as exc:
            self._add_finding("Medium", "Quarantine DB Parse Error", str(exc))
            # Fall back to table listing attempt
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                tables = [
                    r[0] for r in
                    conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                ]
                events.append({"_note": "Could not read rows", "tables": tables})
                conn.close()
            except Exception:
                pass
        if events:
            result["artifacts"]["quarantine_events"] = events
            # Flag unsigned downloads
            for evt in events:
                if evt.get("sender_bundle_id") == "-1":
                    self._add_finding(
                        "Low",
                        "Unsigned app quarantine event",
                        f"Bundle '{evt.get('bundle_id')}' downloaded from '{evt.get('origin_url', 'unknown')}' has no valid signature.",
                    )

    # ------------------------------------------------------------------
    # Safari History
    # ------------------------------------------------------------------

    def _parse_safari_history(self, result: dict) -> None:
        """Parse Safari History.db (WebKit-based, present since Safari 5.1)."""
        candidates = list(self.evidence_dir.rglob("History.db"))
        if not candidates:
            return
        for db_path in candidates:
            history: List[dict] = []
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT zURL, zTITLE, zVISITTIME, zHISTORYITEM FROM "
                    "ZHISTORYITEM ORDER BY zVISITTIME DESC LIMIT 100"
                )
                for row in cursor:
                    history.append({
                        "url": row[0],
                        "title": row[1],
                        "visit_time": row[2],
                        "history_item_id": row[3],
                    })
                conn.close()
            except Exception as exc:
                self._add_finding("Medium", "Safari History Parse Error", str(exc))
            if history:
                result["artifacts"]["safari_history"] = history

    # ------------------------------------------------------------------
    # Chrome History (Chromium-based browsers on macOS)
    # ------------------------------------------------------------------

    def _parse_chrome_history(self, result: dict) -> None:
        """Parse Chrome / Chromium History SQLite."""
        candidates = list(self.evidence_dir.rglob("History"))
        if not candidates:
            return
        for db_path in candidates:
            history: List[dict] = []
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT url, title, visit_count, last_visit_time "
                    "FROM urls ORDER BY last_visit_time DESC LIMIT 100"
                )
                for row in cursor:
                    history.append({
                        "url": row[0],
                        "title": row[1],
                        "visit_count": row[2],
                        "last_visit_time": row[3],
                    })
                conn.close()
            except Exception as exc:
                self._add_finding("Medium", "Chrome History Parse Error", str(exc))
            if history:
                result["artifacts"]["chrome_history"] = history

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _add_finding(
        self, severity: str, description: str, detail: str = ""
    ) -> None:
        self.findings.append({
            "severity": severity,
            "category": "macOS",
            "description": description,
            "detail": detail,
        })
