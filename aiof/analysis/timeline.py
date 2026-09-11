from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator


def _iter_values(value: Any, location: str = "$") -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_values(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_values(child, f"{location}[{index}]")
    else:
        yield location, value


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000
        if number > 10_000_000_000:
            number /= 1000
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def build_timeline(parsed: dict[str, Any], case: Any | None = None) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    timestamp_keys = {
        "timestamp", "event_time", "parsed_at", "date", "last_visit_time",
        "start_time", "visit_time", "added_at", "created_at", "modified",
    }
    for module, result in parsed.get("modules", parsed).items():
        for artifact, payload in (result.get("artifacts") or {}).items():
            for location, value in _iter_values(payload):
                if location.rsplit(".", 1)[-1].lower() not in timestamp_keys:
                    continue
                timestamp = _parse_timestamp(value)
                if timestamp is None:
                    continue
                events.append(
                    {
                        "timestamp": timestamp.isoformat(),
                        "module": module,
                        "artifact": artifact,
                        "location": f"{location}",
                        "event": str(value),
                    }
                )
    for evidence in parsed.get("evidence") or (case.evidence if case else []):
        timestamp = _parse_timestamp(evidence.get("added_at") if isinstance(evidence, dict) else evidence.added_at)
        if timestamp:
            events.append(
                {
                    "timestamp": timestamp.isoformat(),
                    "module": "case",
                    "artifact": "evidence",
                    "location": evidence.get("path", "") if isinstance(evidence, dict) else evidence.path,
                    "event": "Evidence ingested",
                }
            )
    events.sort(key=lambda item: item["timestamp"])
    return events
