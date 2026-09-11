from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from aiof.analysis.ioc import match_iocs
from aiof.analysis.timeline import build_timeline
from aiof.core.case import Case
from aiof.core.config import DEFAULT_CONFIG
from aiof.core.evidence import compute_hash_sha256, find_evidence, ingest_to_case
from aiof.parsers import PARSER_NAMES, run_parsers
from aiof.reporting import ReportGenerator

app = typer.Typer(help="AllinOneForensics — authorized DFIR workbench. Offline-first.")
case_app = typer.Typer(help="Case management")
app.add_typer(case_app, name="case")
console = Console()


def _load_case(case_id: str) -> Case:
    case = Case.load(case_id)
    if not case:
        console.print(f"[red]Case not found:[/red] {case_id}")
        raise typer.Exit(code=1)
    return case


def _artifact_blob(case: Case) -> dict:
    blob: dict = {"modules": {}, "findings": []}
    findings_seen = False
    for path in case.list_artifacts():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if path.stem == "findings":
            blob["findings"].extend(data.get("findings") or [])
            findings_seen = True
        elif path.stem in {"ioc_matches", "timeline", "ingest_summary"}:
            blob[path.stem] = data
        else:
            blob["modules"][path.stem] = data
            if not findings_seen:
                blob["findings"].extend(data.get("findings") or [])
    return blob


@app.callback()
def main(
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config JSON"),
    online: bool = typer.Option(False, "--online", help="Enable optional online enrichment"),
) -> None:
    if config:
        DEFAULT_CONFIG.load(config)
    DEFAULT_CONFIG.online_mode = online
    DEFAULT_CONFIG.ensure_dirs()


@case_app.command("create")
def case_create(
    name: str = typer.Argument(..., help="Case name"),
    examiner: str = typer.Option("Unknown", "--examiner", help="Examiner name"),
    case_id: Optional[str] = typer.Option(None, "--id", help="Optional case ID"),
) -> None:
    case = Case.create(name=name, examiner=examiner, case_id=case_id)
    console.print(f"[green]Case created:[/green] {case.case_id} — {case.name}")


@case_app.command("list")
def case_list() -> None:
    cases = Case.list_all()
    if not cases:
        console.print("[yellow]No cases found.[/yellow]")
        return
    table = Table(title="Cases")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Examiner")
    table.add_column("Evidence")
    for case in cases:
        table.add_row(case.case_id, case.name, case.examiner, str(len(case.evidence)))
    console.print(table)


@app.command("create")
def create_alias(
    name: str = typer.Argument(...),
    examiner: str = typer.Option("Unknown", "--examiner"),
) -> None:
    """Alias for `aiof case create`."""
    case_create(name=name, examiner=examiner, case_id=None)


@app.command()
def ingest(
    case_id: str = typer.Argument(...),
    path: Path = typer.Argument(..., exists=True),
    analyst: str = typer.Option("Unknown", "--analyst"),
) -> None:
    case = _load_case(case_id)
    ingested = ingest_to_case(case, str(path), analyst)
    console.print(f"[green]Ingested {len(ingested)} file(s)[/green] into {case.case_id}")


@app.command()
def parse(
    case_id: str = typer.Argument(...),
    all_flag: bool = typer.Option(False, "--all", help="Parse all modules"),
    module: Optional[str] = typer.Option(None, "--module", help="Single module name"),
) -> None:
    case = _load_case(case_id)
    evidence_dir = case.path / "evidence"
    if not evidence_dir.exists() or not find_evidence(case):
        console.print("[yellow]No evidence to parse.[/yellow]")
        raise typer.Exit(code=1)
    modules = list(PARSER_NAMES) if all_flag or not module else [module]
    parsed = run_parsers(evidence_dir, modules)
    for name, data in parsed["modules"].items():
        case.add_artifact(name, data)
    case.add_artifact("findings", {"findings": parsed["findings"]})
    ioc = match_iocs(parsed)
    case.add_artifact("ioc_matches", ioc)
    timeline = build_timeline(parsed, case)
    case.add_artifact("timeline", {"events": timeline})
    table = Table(title=f"Parsed {case.case_id}")
    table.add_column("Module")
    table.add_column("Findings")
    for name, data in parsed["modules"].items():
        table.add_row(name, str(len(data.get("findings") or [])))
    console.print(table)
    console.print(f"[green]IOC matches:[/green] {ioc['match_count']}")
    console.print(f"[green]Timeline events:[/green] {len(timeline)}")


@app.command()
def hunt(
    case_id: str = typer.Argument(...),
    ioc_file: Optional[Path] = typer.Option(None, "--iocs", help="IOC JSON file"),
) -> None:
    case = _load_case(case_id)
    blob = _artifact_blob(case)
    if not blob.get("modules"):
        console.print("[yellow]No parsed artifacts. Run aiof parse --all first.[/yellow]")
        raise typer.Exit(code=1)
    result = match_iocs(blob, ioc_file)
    case.add_artifact("ioc_matches", result)
    table = Table(title="IOC matches")
    table.add_column("Type")
    table.add_column("Value")
    table.add_column("Location")
    for item in result["matches"]:
        table.add_row(item["type"], item["value"], item["location"])
    console.print(table)
    console.print(f"[green]{result['match_count']} match(es)[/green]")


@app.command()
def timeline(
    case_id: str = typer.Argument(...),
    keyword: Optional[str] = typer.Option(None, "--keyword"),
) -> None:
    case = _load_case(case_id)
    blob = _artifact_blob(case)
    events = blob.get("timeline", {}).get("events") or build_timeline(blob, case)
    if keyword:
        events = [event for event in events if keyword.lower() in json.dumps(event).lower()]
    table = Table(title="Timeline")
    table.add_column("Timestamp")
    table.add_column("Module")
    table.add_column("Event")
    for event in events[:200]:
        table.add_row(str(event.get("timestamp", "")), str(event.get("module", "")), str(event.get("event", ""))[:80])
    console.print(table)


@app.command()
def report(
    case_id: str = typer.Argument(...),
    format: str = typer.Option("html,docx,pdf", "--format", "-f"),
) -> None:
    case = _load_case(case_id)
    blob = _artifact_blob(case)
    findings = blob.get("findings", {}).get("findings") if isinstance(blob.get("findings"), dict) else blob.get("findings") or []
    iocs = (blob.get("ioc_matches") or {}).get("matches", [])
    events = (blob.get("timeline") or {}).get("events", [])
    evidence = [
        {"path": item.path, "size": item.size_bytes, "hash": item.hash_sha256, "analyst": item.analyst}
        for item in case.evidence
    ]
    if not findings:
        findings = [
            {
                "severity": "Low",
                "category": "Evidence",
                "description": f"{len(evidence)} exhibit(s) ingested with SHA-256 verification",
                "detail": "",
            }
        ]
    generated = ReportGenerator(case).generate(
        [part.strip() for part in format.split(",") if part.strip()],
        findings,
        evidence,
        iocs,
        events,
    )
    for path in generated:
        console.print(f"[green]Wrote[/green] {path}")


@app.command()
def ui(
    host: str = typer.Option(DEFAULT_CONFIG.ui_host, "--host"),
    port: int = typer.Option(DEFAULT_CONFIG.ui_port, "--port"),
) -> None:
    import uvicorn
    from aiof.web.app import app as web_app

    console.print(f"[green]Starting UI[/green] http://{host}:{port}")
    uvicorn.run(web_app, host=host, port=port)


if __name__ == "__main__":
    app()
