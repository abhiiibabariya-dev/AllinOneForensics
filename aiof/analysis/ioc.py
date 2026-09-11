from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Iterator

DEFAULT_IOC_FILE = Path(__file__).resolve().parents[1] / "intel" / "iocs.json"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
IP_RE = re.compile(r"(?<![0-9A-Za-z])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Za-z])")
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-])")


def _iter_values(value: Any, location: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_values(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_values(child, f"{location}[{index}]")
    elif isinstance(value, str):
        yield location, value


def load_iocs(path: Path | None = None) -> dict[str, list[str]]:
    source = Path(path) if path else DEFAULT_IOC_FILE
    if not source.exists():
        return {"sha256": [], "ip": [], "domain": [], "url": []}
    data = json.loads(source.read_text(encoding="utf-8"))
    return {
        "sha256": [str(item) for item in data.get("sha256", [])],
        "ip": [str(item) for item in data.get("ip", [])],
        "domain": [str(item) for item in data.get("domain", [])],
        "url": [str(item) for item in data.get("url", [])],
    }


def _find_locations(text: str, pattern: re.Pattern[str], value: str) -> list[str]:
    return [match.group(0) for match in pattern.finditer(text)] if pattern else [value]


def match_iocs(parsed: dict[str, Any], ioc_path: Path | None = None) -> dict[str, Any]:
    iocs = load_iocs(ioc_path)
    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for location, text in _iter_values(parsed):
        text = text.strip()
        for ioc_type, values in iocs.items():
            for ioc in values:
                if ioc_type == "sha256" and text == ioc.lower():
                    key = (ioc_type, ioc.lower(), location)
                    if key not in seen:
                        matches.append({"type": ioc_type, "value": ioc.lower(), "location": location, "context": text[:300]})
                        seen.add(key)
                elif ioc_type == "ip":
                    for found in _find_locations(text, IP_RE, ioc):
                        try:
                            if str(ipaddress.ip_address(found)) != found:
                                continue
                        except ValueError:
                            continue
                        key = (ioc_type, found, location)
                        if key not in seen:
                            matches.append({"type": ioc_type, "value": found, "location": location, "context": text[:300]})
                            seen.add(key)
                elif ioc_type in {"domain", "url"}:
                    pattern = URL_RE if ioc_type == "url" else DOMAIN_RE
                    for found in _find_locations(text, pattern, ioc):
                        if ioc.lower() not in found.lower():
                            continue
                        key = (ioc_type, found, location)
                        if key not in seen:
                            matches.append({"type": ioc_type, "value": found, "location": location, "context": text[:300]})
                            seen.add(key)
    return {"iocs": iocs, "matches": matches, "match_count": len(matches)}
