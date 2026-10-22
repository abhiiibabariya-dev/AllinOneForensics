from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_stix_bundle(bundle_path: Path | str) -> dict[str, list[str]]:
    path = Path(bundle_path)
    if not path.exists():
        return {"sha256": [], "ip": [], "domain": [], "url": []}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"sha256": [], "ip": [], "domain": [], "url": []}

    indicators: dict[str, list[str]] = {
        "sha256": [],
        "ip": [],
        "domain": [],
        "url": [],
    }

    objects = data.get("objects", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        obj_type = obj.get("type", "")

        # STIX Indicator object
        if obj_type == "indicator":
            pattern = obj.get("pattern", "")
            # Simple pattern parsing heuristics for STIX patterns
            # e.g., [file:hashes.sha256 = '...'] or [ipv4-addr:value = '...'] or [domain-name:value = '...'] or [url:value = '...']
            pattern_lower = pattern.lower()
            if "sha256" in pattern_lower:
                import re
                matches = re.findall(r"'([0-9a-fA-F]{64})'", pattern)
                for m in matches:
                    if m.lower() not in indicators["sha256"]:
                        indicators["sha256"].append(m.lower())
            if "ipv4-addr" in pattern_lower or "ip" in pattern_lower:
                import re
                matches = re.findall(r"'((?:\d{1,3}\.){3}\d{1,3})'", pattern)
                for m in matches:
                    if m not in indicators["ip"]:
                        indicators["ip"].append(m)
            if "domain-name" in pattern_lower:
                import re
                matches = re.findall(r"'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,63})'", pattern)
                for m in matches:
                    if m.lower() not in indicators["domain"]:
                        indicators["domain"].append(m.lower())
            if "url" in pattern_lower:
                import re
                matches = re.findall(r"'(https?://[^']+)'", pattern)
                for m in matches:
                    if m not in indicators["url"]:
                        indicators["url"].append(m)

        elif obj_type in {"observed-data", "infrastructure"}:
            # Extract any embedded observables or values
            pass

    return indicators


def sync_stix_feed(bundle_path: Path | str, target_iocs_path: Path | str | None = None) -> int:
    from aiof.analysis.ioc import DEFAULT_IOC_FILE, load_iocs
    dest = Path(target_iocs_path) if target_iocs_path else DEFAULT_IOC_FILE
    current = load_iocs(dest)
    incoming = parse_stix_bundle(bundle_path)

    added = 0
    for itype, values in incoming.items():
        if itype not in current:
            current[itype] = []
        for val in values:
            if val not in current[itype]:
                current[itype].append(val)
                added += 1

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(current, indent=2), encoding="utf-8")
    return added
