import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any


class WindowsParser:
    """Parser for Windows artifacts."""

    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir
        self.findings: List[dict] = []

    def parse_all(self) -> dict:
        """Parse all Windows artifacts."""
        result = {
            "parser": "windows",
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": {},
            "findings": []
        }

        # Parse EVTX logs
        evtx_dir = self.evidence_dir / "evtx"
        if evtx_dir.exists():
            result["artifacts"]["evtx"] = self._parse_evtx_logs(evtx_dir)

        # Parse registry hives
        registry_dir = self.evidence_dir / "registry"
        if registry_dir.exists():
            result["artifacts"]["registry"] = self._parse_registry_hives(registry_dir)

        # Parse prefetch files
        prefetch_dir = self.evidence_dir / "prefetch"
        if prefetch_dir.exists():
            result["artifacts"]["prefetch"] = self._parse_prefetch(prefetch_dir)

        # Parse LNK files
        lnk_dir = self.evidence_dir / "lnk"
        if lnk_dir.exists():
            result["artifacts"]["lnk"] = self._parse_lnk_files(lnk_dir)

        # Parse browser data (Chromium/Firefox)
        browser_dir = self.evidence_dir / "browser"
        if browser_dir.exists():
            result["artifacts"]["browser"] = self._parse_browser_data(browser_dir)

        # Parse jump lists
        jump_dir = self.evidence_dir / "jump"
        if jump_dir.exists():
            result["artifacts"]["jump_lists"] = self._parse_jump_lists(jump_dir)

        self.findings = result["findings"]
        return result

    def _parse_evtx_logs(self, evtx_dir: Path) -> dict:
        """Parse EVTX event logs."""
        result = {"type": "evtx", "logs": {}, "errors": []}
        try:
            try:
                import Evtx.Evtx as evtx
                import Evtx.Views as e_views
            except ImportError:
                result["errors"].append("python-evtx not installed")
                return result

            for evtx_file in evtx_dir.glob("*.evtx"):
                try:
                    with evtx.Evtx(str(evtx_file)) as log:
                        entries = []
                        for record in log.records():
                            try:
                                xml_record = record.xml()
                                # Simple extraction: look for EventID and basic data
                                # In a real implementation, you would parse the XML properly.
                                # For now, we just note the presence of events and extract some common IDs.
                                if '<EventID>4624</EventID>' in xml_record:
                                    entries.append({"event_id": 4624, "type": "successful_logon"})
                                elif '<EventID>4625</EventID>' in xml_record:
                                    entries.append({"event_id": 4625, "type": "failed_logon"})
                                elif '<EventID>4688</EventID>' in xml_record:
                                    entries.append({"event_id": 4688, "type": "process_creation"})
                                elif '<EventID>7045</EventID>' in xml_record:
                                    entries.append({"event_id": 7045, "type": "service_installation"})
                                elif 'PowerShell' in xml_record:
                                    entries.append({"event_id": "powershell", "type": "powershell_activity"})
                            except Exception:
                                # Skip malformed records
                                continue
                        result["logs"][evtx_file.name] = {
                            "event_count": len(entries),
                            "samples": entries[:10]  # Limit samples
                        }
                except Exception as e:
                    result["errors"].append(f"Failed to parse {evtx_file.name}: {str(e)}")
        except Exception as e:
            result["errors"].append(f"EVTX parsing error: {str(e)}")
        return result

    def _parse_registry_hives(self, registry_dir: Path) -> dict:
        """Parse Windows registry hives."""
        result = {"type": "registry", "hives": {}, "errors": []}
        try:
            try:
                import Registry.Registry as reg
                import Registry.RegistryKey as regkey
            except ImportError:
                result["errors"].append("python-registry not installed")
                return result

            hive_files = {
                "SYSTEM": "SYSTEM",
                "SOFTWARE": "SOFTWARE",
                "NTUSER.DAT": "NTUSER.DAT",
                "USRCLASS.DAT": "USRCLASS.DAT",
                "SAM": "SAM"
            }

            for hive_name, hive_filename in hive_files.items():
                hive_path = registry_dir / hive_filename
                if hive_path.exists():
                    try:
                        registry = reg.Registry(str(hive_path))
                        # Parse specific keys
                        hive_data = {}
                        if hive_name in ["SOFTWARE", "NTUSER.DAT"]:
                            # Run keys
                            run_key_paths = [
                                r"Microsoft\Windows\CurrentVersion\Run",
                                r"Microsoft\Windows\CurrentVersion\RunOnce"
                            ]
                            for run_path in run_key_paths:
                                try:
                                    key = registry.open(run_path)
                                    run_values = []
                                    for v in key.values():
                                        run_values.append({
                                            "name": v.name(),
                                            "data": v.value()
                                        })
                                    if run_values:
                                        hive_data[f"run_{run_path.replace('\\', '_')}"] = run_values
                                except Exception:
                                    pass  # Key might not exist

                        if hive_name == "SYSTEM":
                            # USBSTOR
                            try:
                                usb_key = registry.open(r"Microsoft\Windows Portable Devices\Devices")
                                usb_devices = []
                                for subkey in usb_key.subkeys():
                                    usb_devices.append({"name": subkey.name()})
                                if usb_devices:
                                    hive_data["usb_devices"] = usb_devices
                            except Exception:
                                pass

                            # ShimCache (in SYSTEM hive)
                            try:
                                shimcache_key = registry.open(r"ControlSet001\Control\Session Manager\AppCompatCache")
                                shimcache_values = []
                                for v in shimcache_key.values():
                                    if v.name() == "AppCompatCache":
                                        # The value is binary, we note its presence
                                        shimcache_values.append({"present": True, "size": len(v.value())})
                                if shimcache_values:
                                    hive_data["shimcache"] = shimcache_values
                            except Exception:
                                pass

                        if hive_data:
                            result["hives"][hive_name] = hive_data
                    except Exception as e:
                        result["errors"].append(f"Failed to parse {hive_filename}: {str(e)}")
        except Exception as e:
            result["errors"].append(f"Registry parsing error: {str(e)}")
        return result

    def _parse_prefetch(self, prefetch_dir: Path) -> dict:
        """Parse prefetch file headers."""
        result = {"type": "prefetch", "files": {}, "errors": []}
        try:
            for pf_file in prefetch_dir.glob("*.pf"):
                try:
                    with open(pf_file, "rb") as f:
                        header = f.read(28)  # Prefetch header is 28 bytes
                        if len(header) >= 28:
                            # Magic number (MAM) - should be "MAM" (0x4D 0x41 0x4D)
                            magic = header[0:3]
                            if magic == b"MAM":
                                # Version (bytes 4-5)
                                version = int.from_bytes(header[4:6], byteorder='little')
                                # Number of files (bytes 8-11)
                                num_files = int.from_bytes(header[8:12], byteorder='little')
                                # Last run time (bytes 12-15) - FILETIME
                                last_run_raw = int.from_bytes(header[12:16], byteorder='little')
                                # Convert FILETIME to Unix timestamp (if needed, we just note raw)
                                result["files"][pf_file.name] = {
                                    "magic": magic.decode('ascii', errors='ignore'),
                                    "version": version,
                                    "number_of_files": num_files,
                                    "last_run_time_raw": last_run_raw
                                }
                            else:
                                result["files"][pf_file.name] = {
                                    "error": "Invalid prefetch magic",
                                    "magic": magic.hex()
                                }
                        else:
                            result["files"][pf_file.name] = {
                                "error": "File too small for prefetch header"
                            }
                except Exception as e:
                    result["errors"].append(f"Failed to parse {pf_file.name}: {str(e)}")
        except Exception as e:
            result["errors"].append(f"Prefetch parsing error: {str(e)}")
        return result

    def _parse_lnk_files(self, lnk_dir: Path) -> dict:
        """Parse LNK file metadata (best-effort)."""
        result = {"type": "lnk", "files": {}, "errors": []}
        try:
            for lnk_file in lnk_dir.glob("*.lnk"):
                try:
                    # Simple LNK parsing: read the file and extract some strings
                    with open(lnk_file, "rb") as f:
                        data = f.read()
                    # Look for common strings in LNK (target path, etc.)
                    # This is a very basic implementation.
                    # In a real parser, you would use the lnkparse library or similar.
                    # We'll just note the file size and look for ASCII strings.
                    strings = []
                    current = b""
                    for byte in data:
                        if 32 <= byte <= 126:  # Printable ASCII
                            current += bytes([byte])
                        else:
                            if len(current) >= 4:
                                strings.append(current.decode('ascii', errors='ignore'))
                            current = b""
                    if len(current) >= 4:
                        strings.append(current.decode('ascii', errors='ignore'))

                    result["files"][lnk_file.name] = {
                        "size": lnk_file.stat().st_size,
                        "string_count": len(strings),
                        "sample_strings": strings[:10]
                    }
                except Exception as e:
                    result["errors"].append(f"Failed to parse {lnk_file.name}: {str(e)}")
        except Exception as e:
            result["errors"].append(f"LNK parsing error: {str(e)}")
        return result

    def _parse_browser_data(self, browser_dir: Path) -> dict:
        """Parse browser SQLite databases (Chromium/Firefox)."""
        result = {"type": "browser", "chromium": {}, "firefox": {}, "errors": []}
        try:
            # Chromium-like browsers (Chrome, Edge, etc.)
            chromium_dir = browser_dir / "chromium"
            if chromium_dir.exists():
                for profile in chromium_dir.iterdir():
                    if profile.is_dir():
                        profile_data = {}
                        # History
                        history_db = profile / "History"
                        if history_db.exists():
                            try:
                                conn = sqlite3.connect(str(history_db))
                                cursor = conn.cursor()
                                cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10")
                                rows = cursor.fetchall()
                                profile_data["history"] = [
                                    {"url": row[0], "title": row[1], "last_visit_time": row[2]}
                                    for row in rows
                                ]
                                conn.close()
                            except Exception as e:
                                profile_data["history_error"] = str(e)
                        # Downloads
                        downloads_db = profile / "History"  # In Chromium, downloads are in History too
                        if downloads_db.exists():
                            try:
                                conn = sqlite3.connect(str(downloads_db))
                                cursor = conn.cursor()
                                cursor.execute("SELECT tab_url, target_path, start_time FROM downloads ORDER BY start_time DESC LIMIT 10")
                                rows = cursor.fetchall()
                                profile_data["downloads"] = [
                                    {"tab_url": row[0], "target_path": row[1], "start_time": row[2]}
                                    for row in rows
                                ]
                                conn.close()
                            except Exception as e:
                                profile_data["downloads_error"] = str(e)
                        if profile_data:
                            result["chromium"][profile.name] = profile_data

            # Firefox
            firefox_dir = browser_dir / "firefox"
            if firefox_dir.exists():
                for profile in firefox_dir.iterdir():
                    if profile.is_dir() and (profile / "places.sqlite").exists():
                        profile_data = {}
                        places_db = profile / "places.sqlite"
                        try:
                            conn = sqlite3.connect(str(places_db))
                            cursor = conn.cursor()
                            cursor.execute("""
                                SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date
                                FROM moz_places
                                JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
                                ORDER BY moz_historyvisits.visit_date DESC
                                LIMIT 10
                            """)
                            rows = cursor.fetchall()
                            profile_data["history"] = [
                                {"url": row[0], "title": row[1], "visit_date": row[2]}
                                for row in rows
                            ]
                            conn.close()
                        except Exception as e:
                            profile_data["history_error"] = str(e)
                        if profile_data:
                            result["firefox"][profile.name] = profile_data
        except Exception as e:
            result["errors"].append(f"Browser parsing error: {str(e)}")
        return result

    def _parse_jump_lists(self, jump_dir: Path) -> dict:
        """Parse Jump List artifacts (best-effort)."""
        result = {"type": "jump_lists", "files": {}, "errors": []}
        try:
            # Jump Lists are typically in AutomaticDestinations and CustomDestinations
            # We'll parse the .automaticDestinations-ms and .customDestinations-ms files
            for jump_file in jump_dir.glob("*"):
                if jump_file.is_file():
                    try:
                        # Basic file info
                        result["files"][jump_file.name] = {
                            "size": jump_file.stat().st_size,
                            "modified": jump_file.stat().st_mtime
                        }
                        # Attempt to read as binary and look for strings
                        with open(jump_file, "rb") as f:
                            data = f.read(1024)  # Read first 1KB
                        strings = []
                        current = b""
                        for byte in data:
                            if 32 <= byte <= 126:
                                current += bytes([byte])
                            else:
                                if len(current) >= 4:
                                    strings.append(current.decode('ascii', errors='ignore'))
                                current = b""
                        if len(current) >= 4:
                            strings.append(current.decode('ascii', errors='ignore'))
                        result["files"][jump_file.name]["string_sample"] = strings[:5]
                    except Exception as e:
                        result["errors"].append(f"Failed to parse {jump_file.name}: {str(e)}")
        except Exception as e:
            result["errors"].append(f"Jump list parsing error: {str(e)}")
        return result