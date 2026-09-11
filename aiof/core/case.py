from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from aiof.core.config import DEFAULT_CONFIG

_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sanitize_case_id(value: str) -> str:
    cleaned = _SAFE_ID.sub("-", value.strip()).strip("-")
    return cleaned or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


class Evidence:
    def __init__(
        self,
        path: str,
        hash_sha256: str,
        size_bytes: int,
        analyst: str = "Unknown",
        notes: str = "",
        added_at: Optional[str] = None,
    ):
        self.path = path
        self.hash_sha256 = hash_sha256
        self.size_bytes = size_bytes
        self.added_at = added_at or _utc_now()
        self.analyst = analyst
        self.notes = notes

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "hash_sha256": self.hash_sha256,
            "size_bytes": self.size_bytes,
            "added_at": self.added_at,
            "analyst": self.analyst,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Evidence":
        return cls(
            path=data["path"],
            hash_sha256=data["hash_sha256"],
            size_bytes=data["size_bytes"],
            analyst=data.get("analyst", "Unknown"),
            notes=data.get("notes", ""),
            added_at=data.get("added_at"),
        )


class Case:
    def __init__(self, case_id: str, name: str, examiner: str, status: str = "open"):
        self.case_id = case_id
        self.name = name
        self.examiner = examiner
        self.created_at = _utc_now()
        self.evidence: List[Evidence] = []
        self.custody: List[dict] = []
        self.status = status

    @property
    def path(self) -> Path:
        return Path(DEFAULT_CONFIG.cases_dir) / self.case_id

    def add_custody(self, action: str, actor: str, detail: str = "") -> None:
        self.custody.append(
            {
                "at": _utc_now(),
                "action": action,
                "actor": actor,
                "detail": detail,
            }
        )

    @classmethod
    def create(
        cls,
        name: str,
        examiner: str = "Unknown",
        case_id: Optional[str] = None,
    ) -> "Case":
        cid = sanitize_case_id(case_id or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
        case = cls(case_id=cid, name=name, examiner=examiner)
        case.path.mkdir(parents=True, exist_ok=True)
        (case.path / "evidence").mkdir(exist_ok=True)
        (case.path / "artifacts").mkdir(exist_ok=True)
        (case.path / "reports").mkdir(exist_ok=True)
        case.add_custody("created", examiner, f"Case '{name}' opened")
        case.save()
        return case

    @classmethod
    def _from_json(cls, path: Path) -> "Case":
        data = json.loads(path.read_text(encoding="utf-8"))
        case = cls(
            case_id=data["case_id"],
            name=data["name"],
            examiner=data["examiner"],
            status=data.get("status", "open"),
        )
        case.created_at = data.get("created_at", "")
        case.evidence = [Evidence.from_dict(e) for e in data.get("evidence", [])]
        case.custody = list(data.get("custody", []))
        return case

    @classmethod
    def load(cls, case_id: str) -> Optional["Case"]:
        cases_dir = Path(DEFAULT_CONFIG.cases_dir)
        direct = cases_dir / case_id / "case.json"
        if direct.exists():
            return cls._from_json(direct)
        if not cases_dir.exists():
            return None
        for path in cases_dir.glob("*/case.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if data.get("case_id") == case_id or data.get("name") == case_id:
                return cls._from_json(path)
        return None

    @classmethod
    def list_all(cls) -> List["Case"]:
        cases_dir = Path(DEFAULT_CONFIG.cases_dir)
        if not cases_dir.exists():
            return []
        out: List[Case] = []
        for path in sorted(cases_dir.glob("*/case.json")):
            try:
                out.append(cls._from_json(path))
            except Exception:
                continue
        return out

    def save(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        (self.path / "evidence").mkdir(exist_ok=True)
        (self.path / "artifacts").mkdir(exist_ok=True)
        (self.path / "reports").mkdir(exist_ok=True)
        data = {
            "case_id": self.case_id,
            "name": self.name,
            "examiner": self.examiner,
            "created_at": self.created_at,
            "status": self.status,
            "evidence": [e.to_dict() for e in self.evidence],
            "custody": self.custody,
        }
        (self.path / "case.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    def add_evidence(
        self,
        path: str,
        hash_sha256: str,
        size_bytes: int,
        analyst: str = "Unknown",
        notes: str = "",
    ) -> None:
        self.evidence.append(
            Evidence(
                path=path,
                hash_sha256=hash_sha256,
                size_bytes=size_bytes,
                analyst=analyst,
                notes=notes,
            )
        )
        self.add_custody("ingested", analyst, Path(path).name)
        self.save()

    def list_artifacts(self) -> List[Path]:
        art = self.path / "artifacts"
        if not art.exists():
            return []
        return sorted(p for p in art.glob("*.json") if p.is_file())

    def add_artifact(self, name: str, data: dict) -> Path:
        path = self.path / "artifacts" / f"{name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return path

    def list_reports(self) -> List[Path]:
        reports = self.path / "reports"
        if not reports.exists():
            return []
        return sorted(p for p in reports.iterdir() if p.is_file())
