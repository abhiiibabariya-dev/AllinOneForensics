import json
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any

try:
    import sqlite3
except ImportError:  # pragma: no cover – sqlite3 is in the stdlib
    sqlite3 = None  # type: ignore[assignment]


class AndroidParser:
    """Parser for Android forensic artifacts.

    Operates read-only on evidence copies. Never attempts device unlock,
    exploitation, or any unauthorized access. Errors are recorded in the
    result dict instead of being raised.
    """

    def __init__(self, evidence_dir: Path):
        self.evidence_dir = Path(evidence_dir)
        self.findings: List[dict] = []

    def parse_all(self) -> Dict[str, Any]:
        """Parse every Android artifact found under *evidence_dir*."""
        result: Dict[str, Any] = {
            "parser": "android",
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": {},
            "findings": [],
        }

        self._parse_bugreport_zips(result)
        self._parse_packages_xml(result)
        self._parse_logcat(result)
        self._parse_sms_database(result)
        self._parse_chrome_database(result)

        result["findings"] = self.findings
        return result

    # ------------------------------------------------------------------
    # bugreport.zip / adb backup .ab  (zipfile stdlib)
    # ------------------------------------------------------------------

    def _parse_bugreport_zips(self, result: dict) -> None:
        """Ingest bugreport zips found in the evidence directory."""
        for zip_path in sorted(self.evidence_dir.glob("*.zip")):
            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    manifest = zf.namelist()
                    # Look for the main bugreport txt or proto inside
                    report_name = None
                    for name in manifest:
                        if name.startswith("bugreport") and (
                            name.endswith(".txt") or name.endswith(".pb")
                        ):
                            report_name = name
                            break

                    extracted_files: List[str] = []
                    if report_name:
                        zf.extract(report_name, path=self.evidence_dir / "_extracted")
                        extracted_files.append(report_name)

                    # Also list other interesting files
                    interesting_exts = {".log", ".txt", ".xml", ".db", ".proto"}
                    for name in manifest:
                        if any(name.endswith(ext) for ext in interesting_exts):
                            if name not in extracted_files:
                                extracted_files.append(name)

                    result["artifacts"][zip_path.name] = {
                        "type": "bugreport_zip",
                        "file_count": len(manifest),
                        "interesting_files": extracted_files[:50],
                    }

                    # Check file count as a heuristic for completeness
                    if len(manifest) < 5:
                        self._add_finding(
                            "Low",
                            "Small bugreport archive",
                            f"'{zip_path.name}' contains only {len(manifest)} files – may be incomplete.",
                        )
            except zipfile.BadZipFile:
                self._add_finding(
                    "Medium",
                    "Corrupt ZIP file",
                    f"'{zip_path.name}' is not a valid ZIP archive.",
                )
            except Exception as exc:
                self._add_finding(
                    "Medium",
                    "Bugreport ZIP parse error",
                    f"{zip_path.name}: {exc}",
                )

    # ------------------------------------------------------------------
    # packages.xml  (XML stdlib)
    # ------------------------------------------------------------------

    # Well-known Android platform package prefixes
    _PLATFORM_PREFIXES = (
        "com.android.",
        "com.google.android.",
        "com.samsung.",
        "org.android.",
        "com.sec.",
        "com.qualcomm.",
    )

    def _parse_packages_xml(self, result: dict) -> None:
        """Parse the packages.xml from /data/system on the device."""
        pkg_path = self.evidence_dir / "packages.xml"
        if not pkg_path.exists():
            return
        packages: List[dict] = []
        try:
            tree = ET.parse(pkg_path)
            root = tree.getroot()
            for pkg in root.findall(".//package"):
                name = pkg.get("name", "")
                code_path = pkg.get("codePath", "")
                installer = pkg.get("installer", "")
                first_install = pkg.get("firstInstallTime", "")
                last_update = pkg.get("lastUpdateTime", "")
                packages.append({
                    "name": name,
                    "code_path": code_path,
                    "installer": installer,
                    "first_install_time": first_install,
                    "last_update_time": last_update,
                })

                # Flag third-party apps installed from unknown sources
                if installer and installer not in (
                    "com.android.vending",  # Google Play
                    "com.sec.android.app.samsungapps",  # Samsung Galaxy Store
                    "com.amazon.venezia",  # Amazon Appstore
                ):
                    self._add_finding(
                        "Medium",
                        "Third-party installer detected",
                        f"Package '{name}' was installed by '{installer}'.",
                    )

                # Flag packages outside standard paths
                if code_path and not code_path.startswith(
                    ("/system", "/vendor", "/product", "/data/app")
                ):
                    self._add_finding(
                        "Low",
                        "Unusual package code path",
                        f"Package '{name}' resides at '{code_path}'.",
                    )
        except Exception as exc:
            self._add_finding(
                "Medium",
                "packages.xml parse error",
                str(exc),
            )
        if packages:
            result["artifacts"]["packages_xml"] = {
                "type": "packages",
                "count": len(packages),
                "packages": packages[:300],
            }

    # ------------------------------------------------------------------
    # logcat text parsing
    # ------------------------------------------------------------------

    # Patterns that indicate crash or security events
    _SECURITY_KEYWORDS = (
        "FATAL EXCEPTION",
        "ANR in",
        "am_crash",
        "am_anr",
        "SELinux",
        "avc:",
        "permission denied",
        "GrantPermissions",
        "RevokePermissions",
        "KeyguardManager",
        "SecurityException",
    )

    def _parse_logcat(self, result: dict) -> None:
        """Best-effort plain-text logcat parsing."""
        logcat_path = self.evidence_dir / "logcat.txt"
        if not logcat_path.exists():
            # Also try common alternate names
            for alt in ("logcat.log", "logcat_output.txt"):
                alt_path = self.evidence_dir / alt
                if alt_path.exists():
                    logcat_path = alt_path
                    break
            else:
                return

        entries: List[dict] = []
        crash_entries: List[dict] = []
        try:
            with open(logcat_path, "r", errors="ignore") as fh:
                for line in fh:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    entries.append({"line": stripped[:300]})
                    for kw in self._SECURITY_KEYWORDS:
                        if kw in stripped:
                            crash_entries.append({"line": stripped[:300], "matched_keyword": kw})
                            break
        except Exception as exc:
            self._add_finding("Medium", "Logcat parse error", str(exc))

        if entries:
            result["artifacts"]["logcat"] = entries[:500]

        if crash_entries:
            result["artifacts"]["logcat_security_events"] = crash_entries[:100]
            self._add_finding(
                "Medium",
                "Security/crash events in logcat",
                f"Found {len(crash_entries)} entries matching crash/security keywords.",
            )

    # ------------------------------------------------------------------
    # SMS / messaging SQLite (when unencrypted)
    # ------------------------------------------------------------------

    def _parse_sms_database(self, result: dict) -> None:
        """Attempt to read an unencrypted SMS/MMS SQLite database."""
        if sqlite3 is None:
            return
        sms_db = self.evidence_dir / "mmssms.db"
        if not sms_db.exists():
            return
        messages: List[dict] = []
        try:
            conn = sqlite3.connect(f"file:{sms_db}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT address, body, date, type, read "
                "FROM sms ORDER BY date DESC LIMIT 100"
            )
            for row in cursor:
                messages.append({
                    "address": row["address"],
                    "body": (row["body"] or "")[:500],
                    "date": row["date"],
                    "type": row["type"],
                    "read": row["read"],
                })
            conn.close()
        except Exception as exc:
            self._add_finding("Medium", "SMS database parse error", str(exc))

        if messages:
            result["artifacts"]["sms_messages"] = messages
            self._add_finding(
                "Low",
                "SMS/MMS database recovered (unencrypted)",
                f"{len(messages)} messages extracted from mmssms.db.",
            )

    # ------------------------------------------------------------------
    # Chrome for Android SQLite
    # ------------------------------------------------------------------

    def _parse_chrome_database(self, result: dict) -> None:
        """Attempt to read unencrypted Chrome history from an Android dump."""
        if sqlite3 is None:
            return
        # Common Chrome data paths inside extracted filesystem dumps
        chrome_history_candidates = list(
            self.evidence_dir.rglob("**/com.android.chrome/**/History")
        )
        if not chrome_history_candidates:
            return

        for db_path in chrome_history_candidates:
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
                self._add_finding("Medium", "Chrome History parse error", str(exc))

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
            "category": "Android",
            "description": description,
            "detail": detail,
        })
