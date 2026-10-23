from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, List, Optional

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


def verify_evidence_integrity(case: Case) -> dict[str, Any]:
    results: dict[str, Any] = {"verified": True, "details": []}
    for item in case.evidence:
        p = Path(item.path)
        if not p.exists():
            results["verified"] = False
            results["details"].append({"path": item.path, "status": "missing"})
            continue
        current_hash = compute_hash_sha256(p)
        if current_hash != item.hash_sha256:
            results["verified"] = False
            results["details"].append({
                "path": item.path,
                "status": "modified",
                "expected": item.hash_sha256,
                "actual": current_hash,
            })
        else:
            results["details"].append({"path": item.path, "status": "intact"})
    return results


def export_manifest(case: Case, fmt: str = "json") -> Path:
    manifest_dir = case.path / "artifacts"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    items = [e.to_dict() for e in case.evidence]
    if fmt.lower() == "csv":
        import csv
        path = manifest_dir / "evidence_manifest.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["path", "hash_sha256", "size_bytes", "added_at", "analyst", "notes"])
            writer.writeheader()
            for item in items:
                writer.writerow(item)
        return path
    else:
        path = manifest_dir / "evidence_manifest.json"
        path.write_text(json.dumps(items, indent=2), encoding="utf-8")
        return path

