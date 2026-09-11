from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import List, Optional

from aiof.core.case import Case


def compute_hash_sha256(path: Path, chunk_size: int = 8192) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _record_file(case: Case, dest: Path, analyst: str) -> None:
    case.add_evidence(
        path=str(dest),
        hash_sha256=compute_hash_sha256(dest),
        size_bytes=dest.stat().st_size,
        analyst=analyst,
    )


def ingest_to_case(case: Case, source_path: str, analyst: str = "Unknown") -> List[Path]:
    source = Path(source_path).expanduser()
    if not source.exists():
        raise FileNotFoundError(f"Evidence not found: {source}")

    dest_root = case.path / "evidence"
    dest_root.mkdir(parents=True, exist_ok=True)
    ingested: List[Path] = []

    if source.is_file():
        dest = dest_root / source.name
        shutil.copy2(source, dest)
        _record_file(case, dest, analyst)
        ingested.append(dest)
        return ingested

    dest = dest_root / source.name
    shutil.copytree(source, dest, dirs_exist_ok=True)
    for file_path in dest.rglob("*"):
        if file_path.is_file():
            _record_file(case, file_path, analyst)
            ingested.append(file_path)
    return ingested


def find_evidence(case: Case, extension: Optional[str] = None) -> list[Path]:
    evidence_dir = case.path / "evidence"
    if not evidence_dir.exists():
        return []
    paths = [p for p in evidence_dir.rglob("*") if p.is_file()]
    if extension:
        suffix = extension if extension.startswith(".") else f".{extension}"
        return [p for p in paths if p.suffix.lower() == suffix.lower()]
    return paths
