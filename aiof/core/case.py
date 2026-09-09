import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

DEFAULT_CONFIG = None

# Simple JSON-based model instead of pydantic
class Evidence:
    def __init__(self, path: str, hash_sha256: str, size_bytes: int, analyst: str = "Unknown", notes: str = ""):
        self.path = path
        self.hash_sha256 = hash_sha256
        self.size_bytes = size_bytes
        self.added_at = datetime.now(timezone.utc).isoformat()
        self.analyst = analyst
        self.notes = notes

    def to_dict(self):
        return {
            "path": self.path,
            "hash_sha256": self.hash_sha256,
            "size_bytes": self.size_bytes,
            "added_at": self.added_at,
            "analyst": self.analyst,
            "notes": self.notes
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            path=data["path"],
            hash_sha256=data["hash_sha256"],
            size_bytes=data["size_bytes"],
            analyst=data.get("analyst", "Unknown"),
            notes=data.get("notes", "")
        )


class Case:
    def __init__(self, case_id: str, name: str, examiner: str, status: str = "open"):
        self.case_id = case_id
        self.name = name
        self.examiner = examiner
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.evidence: List[Evidence] = []
        self.status = status

    @property
    def path(self) -> Path:
        return Path("cases") / self.case_id

    @classmethod
    def create(cls, name: str, examiner: str = "Unknown") -> "Case":
        case_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        case = cls(case_id=case_id, name=name, examiner=examiner)
        case.path.mkdir(parents=True, exist_ok=True)
        (case.path / "evidence").mkdir(exist_ok=True)
        (case.path / "artifacts").mkdir(exist_ok=True)
        (case.path / "reports").mkdir(exist_ok=True)
        case.save()
        return case

    @classmethod
    def load(cls, case_id: str) -> Optional["Case"]:
        path = Path("cases") / case_id / "case.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        case = cls(case_id=data["case_id"], name=data["name"], examiner=data["examiner"])
        case.created_at = data.get("created_at", "")
        case.evidence = [Evidence.from_dict(e) for e in data.get("evidence", [])]
        case.status = data.get("status", "open")
        return case

    def save(self) -> None:
        (self.path / "evidence").mkdir(exist_ok=True)
        (self.path / "artifacts").mkdir(exist_ok=True)
        (self.path / "reports").mkdir(exist_ok=True)
        data = {
            "case_id": self.case_id,
            "name": self.name,
            "examiner": self.examiner,
            "created_at": self.created_at,
            "evidence": [e.to_dict() for e in self.evidence],
            "status": self.status
        }
        (self.path / "case.json").write_text(json.dumps(data, indent=2))

    def add_evidence(self, path: str, hash_sha256: str, size_bytes: int, analyst: str = "Unknown") -> None:
        self.evidence.append(Evidence(path=path, hash_sha256=hash_sha256, size_bytes=size_bytes, analyst=analyst))
        self.save()

    def list_artifacts(self) -> List[Path]:
        return list((self.path / "artifacts").glob("*.json"))

    def add_artifact(self, name: str, data: dict) -> Path:
        path = self.path / "artifacts" / f"{name}.json"
        path.write_text(json.dumps(data, indent=2))
        return path

    def list_reports(self) -> List[Path]:
        return list((self.path / "reports").glob("*"))
