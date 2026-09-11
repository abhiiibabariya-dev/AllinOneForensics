from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class MemoryParser:
    def __init__(self, evidence_dir: Path):
        self.evidence_dir = Path(evidence_dir)
        self.findings: list[dict] = []

    def parse_all(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "parser": "memory",
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": {},
            "findings": self.findings,
        }
        for path in sorted(self.evidence_dir.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".raw", ".dmp", ".mem", ".vmem", ".lime"}:
                continue
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            with path.open("rb") as handle:
                magic = handle.read(32).hex()
            result["artifacts"][path.name] = {
                "path": str(path),
                "size": path.stat().st_size,
                "sha256": digest.hexdigest(),
                "magic": magic,
                "volatility3": self._volatility3_available(),
            }
        return result

    def _volatility3_available(self) -> bool:
        try:
            import volatility3  # noqa: F401
            return True
        except ImportError:
            return False
