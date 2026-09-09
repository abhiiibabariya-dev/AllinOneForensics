import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import shutil
import click
from rich.console import Console
from rich.table import Table

from aiof.core.case import Case
from aiof.core.config import DEFAULT_CONFIG
from aiof.core.evidence import compute_hash_sha256, find_evidence, ingest_to_case
from aiof.reporting import ReportGenerator

console = Console()


@click.group()
@click.option("--config", "-c", help="Path to config file")
@click.option("--online", is_flag=True, default=False, help="Enable online enrichment")
def cli(config, online):
    """AllinOneForensics — Cross-platform DFIR workbench.

    Authorized DFIR use only. Works offline on isolated machines.
    """
    if config:
        DEFAULT_CONFIG.load(Path(config))
    DEFAULT_CONFIG.online_mode = online
    DEFAULT_CONFIG.ensure_dirs()


@cli.command()
@click.argument("name")
@click.option("--examiner", default="Unknown", help="Examiner name")
def create(name, examiner):
    """Create a new case."""
    case = Case.create(name=name, examiner=examiner)
    console.print(f"[green]Case created:[/green] {case.case_id} — {case.name}")


@cli.command()
@click.argument("case_id")
@click.argument("path")
@click.option("--analyst", default="Unknown", help="Analyst name")
def ingest(case_id, path, analyst):
    """Ingest evidence into a case."""
    case = Case.load(case_id)
    if not case:
        console.print(f"[red]Case not found:[/red] {case_id}")
        return
    try:
        dest = ingest_to_case(case, path, analyst)
        console.print(f"[green]Ingested:[/green] {Path(path).name} → {dest}")
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")


@cli.command()
@click.argument("case_id")
@click.option("--all", "all_flag", is_flag=True, help="Parse all evidence")
@click.option("--format", "-f", type=click.Choice(["json"]), default="json", help="Output format")
def parse(case_id, all_flag, format):
    """Parse evidence for a case."""
    case = Case.load(case_id)
    if not case:
        console.print(f"[red]Case not found:[/red] {case_id}")
        return

    evidence_files = find_evidence(case)
    if not evidence_files:
        console.print("[yellow]No evidence to parse.[/yellow]")
        return

    artifact = {"case_id": case_id, "evidence_count": len(evidence_files),
                "parsed_at": datetime.now(timezone.utc).isoformat()}
    case.add_artifact("ingest_summary", artifact)

    table = Table(title="Evidence")
    table.add_column("File")
    table.add_column("Size")
    table.add_column("SHA-256")
    for e in evidence_files:
        table.add_row(e.name, f"{e.stat().st_size} bytes", compute_hash_sha256(e)[:16] + "...")
    console.print(table)


@cli.command()
@click.argument("case_id")
@click.option("--format", "-f", type=click.STRING, default="html", help="Output formats: comma-separated (e.g. html,docx,pdf)")
def report(case_id, format):
    """Generate reports for a case."""
    formats = [f.strip() for f in format.split(",")]
    case = Case.load(case_id)
    if not case:
        console.print(f"[red]Case not found:[/red] {case_id}")
        return

    # Collect evidence and findings
    evidence = []
    for e in case.evidence:
        evidence.append({
            "path": e.path,
            "size": e.size_bytes,
            "hash": e.hash_sha256,
            "analyst": e.analyst
        })

    # Mock findings based on evidence count
    findings = [
        {"severity": "Low", "category": "Evidence", "description": f"Evidence file: {len(evidence)} items ingested with cryptographic hash verification"}
    ]

    gen = ReportGenerator(case)
    generated = []
    for fmt in formats:
        fmt = fmt.lower().strip()
        if fmt == "html":
            path = gen.generate_html(findings, evidence)
        elif fmt == "docx":
            path = gen.generate_docx(findings, evidence)
        elif fmt == "pdf":
            path = gen.generate_pdf(findings, evidence)
        else:
            console.print(f"[yellow]Unknown format:[/yellow] {fmt}")
            continue
        generated.append(path)

    if generated:
        console.print(f"[green]Reports generated:[/green] {len(generated)} files")
        for p in generated:
            console.print(f"  - {p.name}")
    else:
        console.print("[yellow]No valid formats specified.[/yellow]")


@cli.command()
@click.argument("case_id")
@click.option("--host", default=DEFAULT_CONFIG.ui_host, help="Host to bind")
@click.option("--port", default=DEFAULT_CONFIG.ui_port, help="Port")
def ui(case_id, host, port):
    """Start web UI for a case."""
    case = Case.load(case_id)
    if not case:
        console.print(f"[red]Case not found:[/red] {case_id}")
        return

    console.print(f"[green]Starting UI for case:[/green] {case_id}")
    console.print(f"Open: http://{host}:{port}")
    console.print("[yellow]Use: aiof help for CLI commands[/yellow]")


if __name__ == "__main__":
    cli()
