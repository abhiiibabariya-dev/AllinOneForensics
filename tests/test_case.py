from __future__ import annotations

import shutil
from pathlib import Path

from aiof.analysis.ioc import load_iocs
from aiof.analysis.timeline import build_timeline
from aiof.core.case import Case, sanitize_case_id
from aiof.core.config import DEFAULT_CONFIG
from aiof.core.evidence import compute_hash_sha256, find_evidence, ingest_to_case
from aiof.parsers import run_parsers


def _set_cases_dir(tmp_path: Path) -> Path:
    cases_dir = tmp_path / "cases"
    DEFAULT_CONFIG.cases_dir = cases_dir
    DEFAULT_CONFIG.ensure_dirs()
    return cases_dir


def test_case_create(tmp_path: Path) -> None:
    _set_cases_dir(tmp_path)
    case = Case.create(name="IR-001", examiner="Abhi")
    assert (case.path / "case.json").exists()
    assert (case.path / "evidence").is_dir()
    assert (case.path / "artifacts").is_dir()
    assert (case.path / "reports").is_dir()
    assert len(case.custody) == 1


def test_evidence_ingest_and_hash(tmp_path: Path) -> None:
    _set_cases_dir(tmp_path)
    evidence_file = tmp_path / "evidence.txt"
    evidence_file.write_text("hash me", encoding="utf-8")
    case = Case.create(name="IR-002", examiner="Abhi")
    ingested = ingest_to_case(case, str(evidence_file), analyst="Abhi")
    assert len(ingested) == 1
    assert compute_hash_sha256(ingested[0]) == compute_hash_sha256(ingested[0])
    assert find_evidence(case)


def test_parsers_run_on_samples(tmp_path: Path) -> None:
    _set_cases_dir(tmp_path)
    case = Case.create(name="IR-003", examiner="Abhi")
    samples = Path("/storage/emulated/0/projects/AllinOneForensics/samples")
    ingest_to_case(case, str(samples), analyst="Abhi")
    parsed = run_parsers(case.path / "evidence")
    assert "modules" in parsed
    assert "linux" in parsed["modules"]
    assert "network" in parsed["modules"]


def test_timeline_from_case(tmp_path: Path) -> None:
    _set_cases_dir(tmp_path)
    evidence_file = tmp_path / "evidence.txt"
    evidence_file.write_text("timestamp check", encoding="utf-8")
    case = Case.create(name="IR-004", examiner="Abhi")
    ingest_to_case(case, str(evidence_file), analyst="Abhi")
    parsed = run_parsers(case.path / "evidence")
    events = build_timeline(parsed, case)
    assert isinstance(events, list)
    assert any(event["module"] == "case" for event in events)


def test_ioc_file_load() -> None:
    data = load_iocs(Path("/storage/emulated/0/projects/AllinOneForensics/aiof/intel/iocs.json"))
    assert "sha256" in data
    assert "ip" in data
