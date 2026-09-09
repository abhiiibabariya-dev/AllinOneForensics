import hashlib
import shutil
from pathlib import Path
from typing import Optional

from aiof.core.case import Case
from aiof.core.config import DEFAULT_CONFIG


def compute_hash_sha256(path: Path, chunk_size: int = 8192) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def ingest_to_case(case: Case, source_path: str, analyst: str = "Unknown") -> str:
    """
    Copy evidence into case folder and return the new path.
    """
    source = Path(source_path).expanduser()
    if not source.exists():
        raise FileNotFoundError(f"Evidence not found: {source}")

    dest = case.path / "evidence" / source.name
    shutil.copy2(source, dest)
    hash_sha256 = compute_hash_sha256(dest)
    size_bytes = dest.stat().st_size

    case.add_evidence(dest=str(dest), hash_sha256=hash_sha256, size_bytes=size_bytes, analyst=analyst)
    return str(dest)


def find_evidence(case: Case, extension: Optional[str] = None) -> list[Path]:
    """Return all evidence files matching optional extension."""
    paths = list((case.path / "evidence").glob("*"))
    if extension:
        return [p for p in paths if p.suffix == extension]
    return paths
