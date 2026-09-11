from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

PARSER_NAMES = (
    "windows",
    "linux",
    "macos",
    "android",
    "network",
    "cloud",
    "memory",
)


def _load(name: str) -> Callable[[Path], Any]:
    if name == "windows":
        from aiof.parsers.windows import WindowsParser

        return WindowsParser
    if name == "linux":
        from aiof.parsers.linux import LinuxParser

        return LinuxParser
    if name == "macos":
        from aiof.parsers.macos import macOSParser

        return macOSParser
    if name == "android":
        from aiof.parsers.android import AndroidParser

        return AndroidParser
    if name == "network":
        from aiof.parsers.network import NetworkParser

        return NetworkParser
    if name == "cloud":
        from aiof.parsers.cloud import CloudParser

        return CloudParser
    if name == "memory":
        from aiof.parsers.memory import MemoryParser

        return MemoryParser
    raise KeyError(name)


def run_parsers(evidence_dir: Path, modules: list[str] | None = None) -> dict[str, Any]:
    selected = modules or list(PARSER_NAMES)
    results: dict[str, Any] = {}
    findings: list[dict] = []
    for name in selected:
        try:
            parser_cls = _load(name)
            parsed = parser_cls(evidence_dir).parse_all()
        except Exception as exc:
            parsed = {
                "parser": name,
                "error": str(exc),
                "artifacts": {},
                "findings": [
                    {
                        "severity": "Low",
                        "category": name,
                        "description": f"{name} parser skipped",
                        "detail": str(exc),
                    }
                ],
            }
        results[name] = parsed
        findings.extend(parsed.get("findings") or [])
    return {"modules": results, "findings": findings}
