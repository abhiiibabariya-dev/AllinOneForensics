from __future__ import annotations

from pathlib import Path
from aiof.core.case import Case
from aiof.core.export_bundle import export_case_bundle
from aiof.core.evidence import ingest_to_case


def test_export_case_bundle(tmp_path: Path) -> None:
    from aiof.core.config import DEFAULT_CONFIG
    DEFAULT_CONFIG.cases_dir = tmp_path / "cases"
    DEFAULT_CONFIG.ensure_dirs()

    case = Case.create(name="IR-BUNDLE", examiner="Analyst")
    ev = tmp_path / "sample.log"
    ev.write_text("test log", encoding="utf-8")
    ingest_to_case(case, str(ev), analyst="Analyst")

    bundle = export_case_bundle(case)
    assert bundle.exists()
    assert bundle.suffix == ".aiofbundle"
