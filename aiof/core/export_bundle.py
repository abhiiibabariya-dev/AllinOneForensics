from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any, Dict

from aiof.core.case import Case


def export_case_bundle(case: Case) -> Path:
    """Exports the entire case workspace, evidence metadata, timeline, workflow notes, and reports into a secure .aiofbundle zip archive."""
    bundle_path = case.path / f"case_bundle_{case.case_id}.aiofbundle"
    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in case.path.rglob("*"):
            if file_path == bundle_path or file_path.is_dir():
                continue
            arcname = file_path.relative_to(case.path)
            zf.write(file_path, arcname=str(arcname))
    return bundle_path
