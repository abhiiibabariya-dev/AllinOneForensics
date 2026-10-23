from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from aiof import __version__


def _iter_values(value: Any, location: str = "$") -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_values(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_values(child, f"{location}[{index}]")
    else:
        yield location, value


def _parse_timestamp(value: Any) -> tuple[datetime | None, str, str]:
    """Returns (dt, precision, original_str)."""
    if value is None:
        return None, "unknown", ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000
        if number > 10_000_000_000:
            number /= 1000
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc), "second", str(value)
        except (OverflowError, OSError, ValueError):
            return None, "unknown", str(value)
    text = str(value).strip()
    if not text:
        return None, "unknown", text
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if "." in text:
            precision = "millisecond" if len(text.split(".")[1].rstrip("Z+00:00")) >= 3 else "second"
        else:
            precision = "second"
        return dt, precision, text
    except ValueError:
        return None, "unknown", text


def build_timeline(
    parsed: dict[str, Any],
    case: Any | None = None,
    case_id: str = "unknown",
    host: str = "unknown",
    user: str = "unknown",
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    timestamp_keys = {
        "timestamp", "event_time", "parsed_at", "date", "last_visit_time",
        "start_time", "visit_time", "added_at", "created_at", "modified", "at",
    }
    modules = parsed.get("modules", parsed)
    for module_name, result in modules.items():
        if not isinstance(result, dict):
            continue
        artifacts = result.get("artifacts") or {}
        for artifact_name, payload in artifacts.items():
            if isinstance(payload, list):
                items = enumerate(payload)
            elif isinstance(payload, dict):
                items = [(0, payload)]
            else:
                items = [(0, {"value": payload})]

            for idx, item in items:
                if isinstance(item, dict):
                    item_host = item.get("host", host)
                    item_user = item.get("user", user)
                    item_event_id = item.get("event_id", item.get("pid", ""))
                    item_category = item.get("category", module_name)
                    item_source_file = item.get("source_file", artifact_name)

                    # Extract any IPs, domains, hashes if present in item
                    item_ips = item.get("ips", [])
                    if isinstance(item.get("remote_ip"), str):
                        item_ips.append(item.get("remote_ip"))
                    item_domains = item.get("domains", [])
                    item_hashes = item.get("hashes", [])
                    if isinstance(item.get("hash_sha256"), str):
                        item_hashes.append(item.get("hash_sha256"))

                    for location, value in _iter_values(item):
                        if location.split(".")[0] in {"ips", "domains", "hashes"}:
                            continue
                        if location.rsplit(".", 1)[-1].lower() not in timestamp_keys:
                            continue
                        dt, precision, orig_str = _parse_timestamp(value)
                        if dt is None:
                            continue
                        events.append({
                            "timestamp": dt.isoformat(),
                            "original_timestamp": orig_str,
                            "source_timezone": "UTC",
                            "timestamp_precision": precision,
                            "case_id": case_id,
                            "evidence_id": item_source_file,
                            "host": str(item_host),
                            "user": str(item_user),
                            "event_category": str(item_category),
                            "event_id": str(item_event_id),
                            "source_file": str(item_source_file),
                            "original_record_reference": {"location": location, "index": idx},
                            "ips": list(set(item_ips)),
                            "domains": list(set(item_domains)),
                            "hashes": list(set(item_hashes)),
                            "parser_name": module_name,
                            "parser_version": __version__,
                            "event": f"[{module_name}/{artifact_name}] {location}={orig_str}",
                        })
                else:
                    dt, precision, orig_str = _parse_timestamp(item)
                    if dt is not None:
                        events.append({
                            "timestamp": dt.isoformat(),
                            "original_timestamp": orig_str,
                            "source_timezone": "UTC",
                            "timestamp_precision": precision,
                            "case_id": case_id,
                            "evidence_id": artifact_name,
                            "host": host,
                            "user": user,
                            "event_category": module_name,
                            "event_id": "",
                            "source_file": artifact_name,
                            "original_record_reference": {"index": idx},
                            "ips": [],
                            "domains": [],
                            "hashes": [],
                            "parser_name": module_name,
                            "parser_version": __version__,
                            "event": f"[{module_name}/{artifact_name}] {orig_str}",
                        })

    # Also add case evidence events
    evidence_list = parsed.get("evidence") or (case.evidence if case else [])
    for ev in evidence_list:
        ev_path = getattr(ev, "path", "") if not isinstance(ev, dict) else ev.get("path", "")
        ev_added = getattr(ev, "added_at", "") if not isinstance(ev, dict) else ev.get("added_at", "")
        ev_hash = getattr(ev, "hash_sha256", "") if not isinstance(ev, dict) else ev.get("hash_sha256", ev.get("hash", ""))
        dt, precision, orig_str = _parse_timestamp(ev_added)
        if dt:
            events.append({
                "timestamp": dt.isoformat(),
                "original_timestamp": orig_str,
                "source_timezone": "UTC",
                "timestamp_precision": precision,
                "case_id": case_id,
                "evidence_id": ev_path,
                "host": host,
                "user": user,
                "event_category": "case/evidence",
                "event_id": "",
                "source_file": ev_path,
                "original_record_reference": {"hash": ev_hash},
                "ips": [],
                "domains": [],
                "hashes": [ev_hash] if ev_hash else [],
                "parser_name": "core",
                "module": "case",
                "parser_version": __version__,
                "event": f"Evidence ingested: {ev_path} (SHA-256: {ev_hash})",
            })

    events.sort(key=lambda item: item["timestamp"])
    return events


def filter_timeline(
    events: list[dict[str, Any]],
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    keyword: Optional[str] = None,
    host: Optional[str] = None,
    user: Optional[str] = None,
    category: Optional[str] = None,
) -> list[dict[str, Any]]:
    filtered = []
    for ev in events:
        ts = ev.get("timestamp", "")
        if start_time and ts < start_time:
            continue
        if end_time and ts > end_time:
            continue
        if host and host.lower() not in ev.get("host", "").lower():
            continue
        if user and user.lower() not in ev.get("user", "").lower():
            continue
        if category and category.lower() not in ev.get("event_category", "").lower():
            continue
        if keyword:
            kw = keyword.lower()
            text = f"{ev.get('event', '')} {ev.get('source_file', '')} {ev.get('parser_name', '')} {ev.get('ips', '')} {ev.get('hashes', '')}".lower()
            if kw not in text:
                continue
        filtered.append(ev)
    return filtered


def export_timeline_csv(events: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    fieldnames = [
        "timestamp", "original_timestamp", "source_timezone", "timestamp_precision",
        "case_id", "evidence_id", "host", "user", "event_category", "event_id",
        "source_file", "ips", "domains", "hashes", "parser_name", "parser_version", "event"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for ev in events:
        row = ev.copy()
        for k in ["ips", "domains", "hashes"]:
            if isinstance(row.get(k), list):
                row[k] = ", ".join(row[k])
        writer.writerow(row)
    return output.getvalue()


def export_timeline_json(events: list[dict[str, Any]]) -> str:
    return json.dumps(events, indent=2, default=str)
