from __future__ import annotations

from pathlib import Path

from aiof.analysis.correlation import correlate_cross_source
from aiof.analysis.timeline import build_timeline, filter_timeline, export_timeline_csv, export_timeline_json
from aiof.core.case import Case
from aiof.core.workflow import InvestigationWorkflow
from aiof.core.evidence import ingest_to_case
from aiof.parsers import run_parsers
from aiof.reporting import ReportGenerator


def test_cross_source_correlation(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    from aiof.core.config import DEFAULT_CONFIG
    DEFAULT_CONFIG.cases_dir = cases_dir
    DEFAULT_CONFIG.ensure_dirs()

    case = Case.create(name="IR-CORR", examiner="Analyst")
    parsed = {
        "modules": {
            "memory": {
                "artifacts": {
                    "network_connections": [{"remote_ip": "192.168.1.50", "hash_sha256": "abc123sha"}]
                }
            },
            "windows": {
                "artifacts": {
                    "evtx": [{"remote_ip": "192.168.1.50", "hash_sha256": "abc123sha"}]
                }
            }
        }
    }
    correlations = correlate_cross_source(parsed)
    assert len(correlations) >= 2


def test_investigation_workflow(tmp_path: Path) -> None:
    case_path = tmp_path / "case_wf"
    case_path.mkdir()
    wf = InvestigationWorkflow(case_path)
    wf.add_note("Initial Note", "Observed lateral movement", "Analyst")
    wf.add_task("Review logs", "Analyst", "pending")
    wf.add_hypothesis("Attacker used compromised SSH keys", "under_investigation")

    summary = wf.get_summary()
    assert len(summary["notes"]) == 1
    assert len(summary["tasks"]) == 1
    assert len(summary["hypotheses"]) == 1


def test_timeline_filtering_and_export(tmp_path: Path) -> None:
    events = [
        {"timestamp": "2026-03-01T10:00:00Z", "host": "hostA", "user": "admin", "event_category": "auth", "event": "login", "parser_name": "linux"},
        {"timestamp": "2026-03-01T12:00:00Z", "host": "hostB", "user": "root", "event_category": "exec", "event": "cmd", "parser_name": "windows"},
    ]
    filtered = filter_timeline(events, host="hostA")
    assert len(filtered) == 1
    csv_out = export_timeline_csv(events)
    assert "hostA" in csv_out
    json_out = export_timeline_json(events)
    assert "hostB" in json_out


def test_report_generation(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    from aiof.core.config import DEFAULT_CONFIG
    DEFAULT_CONFIG.cases_dir = cases_dir
    DEFAULT_CONFIG.ensure_dirs()

    case = Case.create(name="IR-REP", examiner="Analyst")
    evidence_file = tmp_path / "ev.txt"
    evidence_file.write_text("test", encoding="utf-8")
    ingest_to_case(case, str(evidence_file), analyst="Analyst")

    gen = ReportGenerator(case)
    findings = [{"severity": "High", "category": "Test", "description": "Test finding", "detail": "detail"}]
    evidence = [{"path": str(evidence_file), "size": 4, "hash": "abcd"}]
    reports = gen.generate(["html", "docx", "pdf"], findings, evidence)
    assert len(reports) == 3
    for r in reports:
        assert r.exists()
