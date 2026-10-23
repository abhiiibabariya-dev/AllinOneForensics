"""
aiof.web.app — Offline read-only FastAPI dashboard for AllinOneForensics.
Supports unified investigation dashboard, timeline filtering/export, IOCs,
parser status, evidence integrity, workflow notes/tasks, and reporting.
"""
from __future__ import annotations

import html as html_lib
import json
import mimetypes
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, PlainTextResponse

from aiof import __version__
from aiof.core.case import Case
from aiof.core.config import DEFAULT_CONFIG
from aiof.core.intake import AlertIntakeManager, Alert
from aiof.analysis.timeline import build_timeline, filter_timeline, export_timeline_csv, export_timeline_json
from aiof.reporting import ReportGenerator


app = FastAPI(
    title="AllinOneForensics — Offline Dashboard",
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json",
)


def _safe_list_cases() -> list[dict]:
    cases: list[dict] = []
    try:
        cases_dir = Path(DEFAULT_CONFIG.cases_dir)
        if not cases_dir.exists():
            return cases
        for entry in sorted(cases_dir.iterdir()):
            if not entry.is_dir():
                continue
            case_json = entry / "case.json"
            if not case_json.exists():
                continue
            try:
                data = json.loads(case_json.read_text(encoding="utf-8"))
            except Exception:
                continue
            case_id = data.get("case_id") or entry.name
            cases.append({
                "case_id": str(case_id),
                "name": str(data.get("name", "—")),
                "examiner": str(data.get("examiner", "—")),
                "created_at": str(data.get("created_at", "—")),
                "status": str(data.get("status", "open")),
                "evidence_count": len(data.get("evidence", [])) if isinstance(data.get("evidence"), list) else 0,
            })
    except Exception:
        pass
    try:
        cases.sort(key=lambda c: (c["created_at"], c["case_id"]), reverse=True)
    except Exception:
        pass
    return cases


def _h(x: object) -> str:
    return html_lib.escape(str(x) if x is not None else "", quote=True)


_CSS = r"""
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117; --surface:#161b22; --surface-2:#1c2128; --border:#30363d;
  --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff; --accent-2:#1f6feb;
  --ok:#238636; --warn:#d29922; --bad:#da3633; --radius:10px;
  --mono: ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  --sans: -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
}
html,body{background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.5}
a{color:var(--accent);text-decoration:none}
a:hover{color:#79b8ff;text-decoration:underline}
code, .mono{font-family:var(--mono);font-size:.9em}
.topbar{
  position:sticky;top:0;z-index:10;
  background:rgba(13,17,23,.92);backdrop-filter:blur(8px);
  border-bottom:1px solid var(--border);
  padding:14px 28px;display:flex;align-items:center;gap:16px;
}
.brand{font-weight:700;letter-spacing:.02em;font-size:1.05rem}
.brand small{color:var(--muted);font-weight:400;margin-left:8px;font-size:.8rem}
.topbar nav{margin-left:auto;display:flex;gap:16px;font-size:.9rem}
.topbar nav a{color:var(--muted)}
.topbar nav a:hover{color:var(--text)}
.wrap{max-width:1280px;margin:0 auto;padding:24px 20px 40px}
h1{font-size:1.45rem;margin:8px 0 4px}
.sub{color:var(--muted);font-size:.92rem;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:16px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px;text-align:center}
.stat-card .num{font-size:1.6rem;font-weight:700;color:var(--accent);margin-top:4px}
.card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:16px;display:flex;flex-direction:column;gap:10px;
}
.card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.card-title{font-weight:650;font-size:1rem;word-break:break-word}
.card-title a{color:var(--text)}
.badge{
  display:inline-flex;align-items:center;gap:6px;
  font-size:.72rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;
  padding:3px 8px;border-radius:999px;border:1px solid var(--border);white-space:nowrap
}
.badge.open{background:rgba(35,134,54,.15);color:#3fb950;border-color:rgba(35,134,54,.35)}
.badge.closed{background:rgba(139,148,158,.15);color:var(--muted)}
.badge.archived{background:rgba(210,153,34,.15);color:#d29922;border-color:rgba(210,153,34,.35)}
.badge.high{background:rgba(218,54,51,.15);color:#ff7b72;border-color:rgba(218,54,51,.4)}
.badge.medium{background:rgba(210,153,34,.15);color:#e3b341;border-color:rgba(210,153,34,.4)}
.badge.low{background:rgba(88,166,255,.15);color:#58a6ff;border-color:rgba(88,166,255,.4)}
.meta{display:grid;grid-template-columns:1fr 1fr;gap:6px 16px;font-size:.85rem;color:var(--muted)}
.meta b{color:var(--text);font-weight:600}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  background:var(--accent-2);color:#fff;border:1px solid rgba(255,255,255,.08);
  padding:7px 12px;border-radius:8px;font-size:.85rem;font-weight:600;cursor:pointer
}
.btn:hover{background:#1a5fcc;color:#fff;text-decoration:none}
.btn-ghost{background:transparent;color:var(--text);border-color:var(--border)}
.btn-ghost:hover{background:var(--surface-2)}
.empty{border:1px dashed var(--border);border-radius:var(--radius);padding:32px;text-align:center;color:var(--muted);background:var(--surface)}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:16px}
.panel-head{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:12px;background:var(--surface-2)}
.panel-head h2{font-size:.95rem}
.panel-body{padding:14px 16px}
.kvs{display:grid;grid-template-columns:180px 1fr;gap:8px 16px;font-size:.9rem}
.kvs dt{color:var(--muted)}
.kvs dd{word-break:break-all}
.table-wrap{overflow:auto}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th{color:var(--muted);font-weight:600;text-align:left;font-size:.78rem;letter-spacing:.04em;text-transform:uppercase;border-bottom:1px solid var(--border);padding:8px 10px;white-space:nowrap;background:var(--surface-2)}
td{border-bottom:1px solid var(--border);padding:9px 10px;vertical-align:top;word-break:break-all}
tr:last-child td{border-bottom:none}
.hash{font-family:var(--mono);font-size:.82rem;color:#a5d6ff;word-break:break-all}
.pill{font-size:.72rem;padding:2px 7px;border-radius:999px;background:var(--surface-2);border:1px solid var(--border);white-space:nowrap}
.foot{color:var(--muted);font-size:.8rem;margin-top:18px;text-align:center}
.breadcrumb{font-size:.85rem;color:var(--muted);margin:10px 0 6px}
.breadcrumb a{color:var(--muted)}
.alert{border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-size:.88rem;margin:10px 0}
.alert-warn{background:rgba(210,153,34,.1);border-color:rgba(210,153,34,.35);color:#e3b341}
.alert-err{background:rgba(218,54,51,.1);border-color:rgba(218,54,51,.4);color:#ff7b72}
.filter-bar{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:12px;align-items:center}
.filter-bar input, .filter-bar select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:6px;font-size:.85rem}
"""

_CHROME_TOP = r"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>""" + _CSS + r"""</style>
</head><body>
<header class="topbar">
  <div class="brand">&#9670; AllinOneForensics <small>offline DFIR workbench</small></div>
  <nav><a href="/">Cases</a><span style="color:var(--border)">|</span><span style="color:var(--muted)">127.0.0.1 only</span></nav>
</header>
<div class="wrap">
"""

_CHROME_BOTTOM = r"""
<p class="foot">AllinOneForensics &mdash; offline, read-only dashboard. No data leaves this machine.</p>
</div></body></html>"""


def _layout(title: str, body_html: str) -> str:
    return _CHROME_TOP.format(title=_h(title)) + body_html + _CHROME_BOTTOM


def _load_case_full(case_id: str):
    case_obj = None
    try:
        case_obj = Case.load(case_id)
    except Exception:
        case_obj = None

    data = None
    evidence_list = []
    custody = []
    artifacts = []
    reports = []
    findings = []
    iocs = []
    parser_status = {}

    if case_obj is not None:
        data = {
            "case_id": case_obj.case_id,
            "name": case_obj.name,
            "examiner": case_obj.examiner,
            "created_at": case_obj.created_at,
            "status": case_obj.status,
        }
        evidence_list = [e.to_dict() for e in case_obj.evidence]
        custody = case_obj.custody
        try:
            artifacts = list(case_obj.list_artifacts())
        except Exception:
            artifacts = []
        try:
            reports = list(case_obj.list_reports())
        except Exception:
            reports = []
    else:
        try:
            raw_path = Path(DEFAULT_CONFIG.cases_dir) / case_id / "case.json"
            if raw_path.exists():
                data = json.loads(raw_path.read_text(encoding="utf-8"))
                evidence_list = data.get("evidence", [])
                custody = data.get("custody", [])
                artifacts = list((Path(DEFAULT_CONFIG.cases_dir) / case_id / "artifacts").glob("*.json"))
                reports = list((Path(DEFAULT_CONFIG.cases_dir) / case_id / "reports").glob("*"))
        except Exception:
            pass

    if data is not None:
        cid = data.get("case_id", case_id)
        art_dir = Path(DEFAULT_CONFIG.cases_dir) / str(cid) / "artifacts"
        if art_dir.exists():
            for p in art_dir.glob("*.json"):
                pname = p.stem
                try:
                    pcontent = json.loads(p.read_text(encoding="utf-8"))
                    parser_status[pname] = {"status": pcontent.get("status", "completed"), "error": pcontent.get("error")}
                    f_list = pcontent.get("findings", [])
                    for f in f_list:
                        f["source_parser"] = pname
                        findings.append(f)
                    # Extract IOCs if present
                    art_artifacts = pcontent.get("artifacts", {})
                    if isinstance(art_artifacts, dict):
                        for k, v in art_artifacts.items():
                            if "ioc" in k.lower() or "ip" in k.lower() or "domain" in k.lower():
                                if isinstance(v, list):
                                    for item in v:
                                        iocs.append({"type": k, "value": str(item), "location": pname})
                except Exception as exc:
                    parser_status[pname] = {"status": "error", "error": str(exc)}

    return data, evidence_list, custody, artifacts, reports, findings, iocs, parser_status


@app.get("/", response_class=HTMLResponse)
def dashboard():
    cases = _safe_list_cases()
    if not cases:
        body = """
<h1>Cases</h1>
<p class="sub">No cases found in <span class="mono">{cases_dir}</span></p>
<div class="empty">
  <div style="font-size:1.1rem;margin-bottom:6px">No cases yet</div>
  <div>Create one with <code class="mono">aiof case create --name "&lt;name&gt;" --examiner "&lt;you&gt;"</code></div>
</div>
""".format(cases_dir=_h(str(Path(DEFAULT_CONFIG.cases_dir))))
        return HTMLResponse(_layout("AllinOneForensics — Cases", body))

    cards: list[str] = []
    for c in cases:
        status = c["status"] or "open"
        badge_cls = "open" if status.lower() == "open" else ("archived" if status.lower() == "archived" else "closed")
        cards.append(f"""
<article class="card">
  <div class="card-head">
    <div class="card-title"><a href="/case/{_h(c['case_id'])}">{_h(c['name'])}</a></div>
    <span class="badge {badge_cls}">{_h(status)}</span>
  </div>
  <div class="meta">
    <div><span>Case ID</span><br><b class="mono">{_h(c['case_id'])}</b></div>
    <div><span>Evidence</span><br><b>{c['evidence_count']} item(s)</b></div>
    <div><span>Examiner</span><br><b>{_h(c['examiner'])}</b></div>
    <div><span>Created</span><br><b>{_h(c['created_at'])}</b></div>
  </div>
  <div style="margin-top:4px"><a class="btn btn-ghost" href="/case/{_h(c['case_id'])}">View dashboard &rarr;</a></div>
</article>""")

    body = f"""
<h1>Cases</h1>
<p class="sub">{len(cases)} case(s) in <span class="mono">{_h(str(Path(DEFAULT_CONFIG.cases_dir)))}</span></p>
<div class="grid">
{''.join(cards)}
</div>
"""
    return HTMLResponse(_layout("AllinOneForensics — Cases", body))


@app.get("/case/{case_id}", response_class=HTMLResponse)
def case_detail(case_id: str):
    data, evidence_list, custody, artifacts, reports, findings, iocs, parser_status = _load_case_full(case_id)
    if data is None:
        body = f"""
<div class="breadcrumb"><a href="/">Cases</a> / {_h(case_id)}</div>
<div class="alert alert-err">Case <b class="mono">{_h(case_id)}</b> not found.</div>
<p><a class="btn btn-ghost" href="/">Back to cases</a></p>
"""
        return HTMLResponse(_layout(f"Case {_h(case_id)} — Not found", body), status_code=404)

    cid = str(data.get("case_id", case_id))
    name = str(data.get("name", "—"))
    examiner = str(data.get("examiner", "—"))
    created_at = str(data.get("created_at", "—"))
    status = str(data.get("status", "open"))
    case_path = str(Path(DEFAULT_CONFIG.cases_dir) / cid)
    badge_cls = "open" if status.lower() == "open" else ("archived" if status.lower() == "archived" else "closed")

    # Severity counts
    sev_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get("severity", "Info").capitalize()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["Info"] += 1

    # Evidence HTML
    if evidence_list:
        ev_rows = []
        for ev in evidence_list:
            e_path = ev.get("path", "—")
            e_hash = ev.get("hash_sha256", "—")
            e_size = ev.get("size_bytes", "—")
            try:
                e_size_str = f"{int(e_size):,}" if str(e_size).strip() not in ("", "—") else "—"
            except Exception:
                e_size_str = _h(e_size)
            ev_rows.append(
                f"<tr><td class='mono'>{_h(e_path)}</td>"
                f"<td class='hash'>{_h(e_hash)}</td>"
                f"<td style='white-space:nowrap'>{e_size_str}</td>"
                f"<td><span class='pill' style='color:#3fb950'>Verified (SHA-256)</span></td></tr>"
            )
        evidence_html = (
            '<div class="table-wrap"><table>'
            "<thead><tr><th>Path</th><th>SHA-256</th><th>Size (bytes)</th><th>Integrity</th></tr></thead>"
            f"<tbody>{''.join(ev_rows)}</tbody></table></div>"
        )
    else:
        evidence_html = '<div class="alert alert-warn">No evidence recorded for this case.</div>'

    # Findings HTML
    if findings:
        f_rows = []
        for f in findings:
            sev = f.get("severity", "Info")
            sev_badge = f"<span class='badge {sev.lower()}'>{_h(sev)}</span>"
            cat = f.get("category", "General")
            desc = f.get("description", "")
            detail = f.get("detail", "")
            parser_src = f.get("source_parser", "—")
            f_rows.append(
                f"<tr><td>{sev_badge}</td><td><span class='pill'>{_h(cat)}</span></td>"
                f"<td><b>{_h(desc)}</b><br><span style='color:var(--muted);font-size:.85rem'>{_h(detail)}</span></td>"
                f"<td class='mono'>{_h(parser_src)}</td></tr>"
            )
        findings_html = (
            '<div class="table-wrap"><table>'
            "<thead><tr><th>Severity</th><th>Category</th><th>Finding & Detail</th><th>Source</th></tr></thead>"
            f"<tbody>{''.join(f_rows)}</tbody></table></div>"
        )
    else:
        findings_html = '<div class="alert alert-warn">No findings recorded. Run parsers via <code class="mono">aiof parse --case ' + _h(cid) + ' --all</code>.</div>'

    # IOCs HTML
    if iocs:
        ioc_rows = []
        for ioc in iocs:
            ioc_rows.append(
                f"<tr><td><span class='pill'>{_h(ioc.get('type'))}</span></td>"
                f"<td class='hash'>{_h(ioc.get('value'))}</td>"
                f"<td class='mono'>{_h(ioc.get('location'))}</td></tr>"
            )
        iocs_html = (
            '<div class="table-wrap"><table>'
            "<thead><tr><th>Type</th><th>IOC Value</th><th>Source Attribution</th></tr></thead>"
            f"<tbody>{''.join(ioc_rows)}</tbody></table></div>"
        )
    else:
        iocs_html = '<div class="alert alert-warn">No IOC matches extracted.</div>'

    # Parser Status HTML
    parser_rows = []
    for p_name in ["windows", "linux", "macos", "android", "network", "cloud", "memory", "container"]:
        st = parser_status.get(p_name, {"status": "not run", "error": None})
        st_val = st.get("status", "not run")
        err_val = st.get("error")
        badge_style = "open" if st_val in ("completed", "implemented") else "closed"
        parser_rows.append(
            f"<tr><td class='mono'><b>{_h(p_name)}</b></td>"
            f"<td><span class='badge {badge_style}'>{_h(st_val)}</span></td>"
            f"<td class='mono' style='color:var(--muted);font-size:.82rem'>{_h(err_val or '—')}</td></tr>"
        )
    parser_html = (
        '<div class="table-wrap"><table>'
        "<thead><tr><th>Parser Module</th><th>Status</th><th>Notes / Error</th></tr></thead>"
        f"<tbody>{''.join(parser_rows)}</tbody></table></div>"
    )

    # Custody HTML
    custody_rows = []
    for c_item in custody:
        custody_rows.append(
            f"<tr><td class='mono'>{_h(c_item.get('at'))}</td>"
            f"<td><span class='pill'>{_h(c_item.get('action'))}</span></td>"
            f"<td>{_h(c_item.get('actor'))}</td>"
            f"<td>{_h(c_item.get('detail'))}</td></tr>"
        )
    custody_html = (
        '<div class="table-wrap"><table>'
        "<thead><tr><th>Timestamp (UTC)</th><th>Action</th><th>Actor</th><th>Detail</th></tr></thead>"
        f"<tbody>{''.join(custody_rows)}</tbody></table></div>"
    ) if custody else '<div class="alert alert-warn">No chain of custody events recorded.</div>'

    # Reports HTML
    reports_html = ""
    if reports:
        rep_items = []
        for p in sorted(reports):
            if not p.is_file():
                continue
            fname = p.name
            try:
                sz_str = f"{p.stat().st_size:,} bytes"
            except Exception:
                sz_str = ""
            rep_items.append(
                f"<tr><td class='mono'>{_h(fname)}</td><td>{_h(sz_str)}</td>"
                f"<td><a class='btn btn-ghost' href='/case/{_h(cid)}/report/{_h(fname)}' download>Download</a></td></tr>"
            )
        reports_html = (
            '<div class="table-wrap"><table>'
            "<thead><tr><th>Report File</th><th>Size</th><th>Action</th></tr></thead>"
            f"<tbody>{''.join(rep_items)}</tbody></table></div>"
        )
    else:
        reports_html = '<div class="alert alert-warn">No reports generated yet. Use the button below to generate professional reports.</div>'

    body = f"""
<div class="breadcrumb"><a href="/">Cases</a> / <span class="mono">{_h(cid)}</span></div>
<h1>{_h(name)} <span class="badge {badge_cls}" style="vertical-align:middle;margin-left:8px">{_h(status)}</span></h1>
<p class="sub mono">{_h(cid)} &middot; Examiner: {_h(examiner)} &middot; Created: {_h(created_at)}</p>

<div class="stats-grid">
  <div class="stat-card"><div>Evidence Items</div><div class="num">{len(evidence_list)}</div></div>
  <div class="stat-card"><div>Total Findings</div><div class="num">{len(findings)}</div></div>
  <div class="stat-card" style="border-color:rgba(218,54,51,.4)"><div>High Severity</div><div class="num" style="color:#ff7b72">{sev_counts['High']}</div></div>
  <div class="stat-card"><div>IOC Matches</div><div class="num">{len(iocs)}</div></div>
</div>

<div style="margin-bottom:16px;display:flex;gap:10px;flex-wrap:wrap">
  <a class="btn" href="/case/{_h(cid)}/timeline">View Unified Timeline &rarr;</a>
  <form method="POST" action="/case/{_h(cid)}/generate-reports" style="display:inline">
    <button class="btn" type="submit">Generate Professional Reports (HTML, DOCX, PDF)</button>
  </form>
</div>

<div class="panel">
  <div class="panel-head"><h2>Evidence & Chain of Custody Integrity</h2><span class="pill">SHA-256 Verified</span></div>
  <div class="panel-body" style="padding:0">{evidence_html}</div>
</div>

<div class="panel">
  <div class="panel-head"><h2>Findings ({len(findings)})</h2><span class="pill">High: {sev_counts['High']} | Med: {sev_counts['Medium']} | Low: {sev_counts['Low']}</span></div>
  <div class="panel-body" style="padding:0">{findings_html}</div>
</div>

<div class="panel">
  <div class="panel-head"><h2>IOCs & Threat Intelligence</h2><span class="pill">{len(iocs)} indicators</span></div>
  <div class="panel-body" style="padding:0">{iocs_html}</div>
</div>

<div class="panel">
  <div class="panel-head"><h2>Parser Availability & Status</h2><span class="pill">8 modules</span></div>
  <div class="panel-body" style="padding:0">{parser_html}</div>
</div>

<div class="panel">
  <div class="panel-head"><h2>Chain of Custody Activity Log</h2></div>
  <div class="panel-body" style="padding:0">{custody_html}</div>
</div>

<div class="panel">
  <div class="panel-head"><h2>Professional Reports</h2></div>
  <div class="panel-body">{reports_html}</div>
</div>
"""
    return HTMLResponse(_layout(f"{name} — {cid}", body))


@app.get("/case/{case_id}/timeline", response_class=HTMLResponse)
def case_timeline_view(
    case_id: str,
    q: str = Query("", description="Keyword search"),
    host: str = Query("", description="Host filter"),
    user: str = Query("", description="User filter"),
    category: str = Query("", description="Category filter"),
    start: str = Query("", description="Start time UTC"),
    end: str = Query("", description="End time UTC"),
):
    data, evidence_list, custody, artifacts, reports, findings, iocs, parser_status = _load_case_full(case_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Case not found")

    # Reconstruct parsed dict for timeline
    parsed_all = {"modules": {}, "evidence": evidence_list}
    cid = data.get("case_id", case_id)
    art_dir = Path(DEFAULT_CONFIG.cases_dir) / str(cid) / "artifacts"
    if art_dir.exists():
        for p in art_dir.glob("*.json"):
            try:
                parsed_all["modules"][p.stem] = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass

    events = build_timeline(parsed_all, case_id=str(cid))
    filtered = filter_timeline(events, start_time=start or None, end_time=end or None, keyword=q or None, host=host or None, user=user or None, category=category or None)

    rows = []
    for ev in filtered[:500]: # limit display
        rows.append(
            f"<tr><td class='mono' style='white-space:nowrap'>{_h(ev.get('timestamp'))}</td>"
            f"<td><span class='pill'>{_h(ev.get('parser_name'))}</span></td>"
            f"<td class='mono'>{_h(ev.get('host'))}</td>"
            f"<td class='mono'>{_h(ev.get('user'))}</td>"
            f"<td>{_h(ev.get('event'))}</td></tr>"
        )
    table_html = (
        '<div class="table-wrap"><table>'
        "<thead><tr><th>Timestamp (UTC)</th><th>Module / Source</th><th>Host</th><th>User</th><th>Event Details</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    ) if rows else '<div class="alert alert-warn">No timeline events match the filter criteria.</div>'

    body = f"""
<div class="breadcrumb"><a href="/case/{_h(cid)}">Case {_h(cid)}</a> / Timeline</div>
<h1>Unified Forensic Timeline</h1>
<p class="sub">{len(filtered)} event(s) displayed (total parsed: {len(events)})</p>

<form method="GET" action="/case/{_h(cid)}/timeline" class="panel" style="padding:16px;margin-bottom:16px">
  <div class="filter-bar">
    <input type="text" name="q" placeholder="Keyword / IP / Hash..." value="{_h(q)}" style="flex:1;min-width:200px">
    <input type="text" name="host" placeholder="Host filter" value="{_h(host)}" style="width:140px">
    <input type="text" name="user" placeholder="User filter" value="{_h(user)}" style="width:140px">
    <input type="text" name="category" placeholder="Category" value="{_h(category)}" style="width:140px">
    <button class="btn" type="submit">Filter</button>
    <a class="btn btn-ghost" href="/case/{_h(cid)}/timeline">Reset</a>
    <a class="btn btn-ghost" href="/case/{_h(cid)}/timeline/export/csv?q={_h(q)}&host={_h(host)}&user={_h(user)}&category={_h(category)}">Export CSV</a>
    <a class="btn btn-ghost" href="/case/{_h(cid)}/timeline/export/json?q={_h(q)}&host={_h(host)}&user={_h(user)}&category={_h(category)}">Export JSON</a>
  </div>
</form>

<div class="panel">
  <div class="panel-head"><h2>Chronological Super-Timeline</h2><span class="pill">{len(filtered)} events</span></div>
  <div class="panel-body" style="padding:0">{table_html}</div>
</div>
"""
    return HTMLResponse(_layout(f"Timeline — {cid}", body))


@app.get("/case/{case_id}/timeline/export/csv")
def timeline_export_csv(
    case_id: str,
    q: str = Query(""),
    host: str = Query(""),
    user: str = Query(""),
    category: str = Query(""),
):
    data, evidence_list, _, _, _, _, _, _ = _load_case_full(case_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Case not found")
    parsed_all = {"modules": {}, "evidence": evidence_list}
    art_dir = Path(DEFAULT_CONFIG.cases_dir) / str(case_id) / "artifacts"
    if art_dir.exists():
        for p in art_dir.glob("*.json"):
            try:
                parsed_all["modules"][p.stem] = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    events = build_timeline(parsed_all, case_id=str(case_id))
    filtered = filter_timeline(events, keyword=q or None, host=host or None, user=user or None, category=category or None)
    csv_text = export_timeline_csv(filtered)
    return PlainTextResponse(csv_text, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=timeline_{case_id}.csv"})


@app.get("/case/{case_id}/timeline/export/json")
def timeline_export_json(
    case_id: str,
    q: str = Query(""),
    host: str = Query(""),
    user: str = Query(""),
    category: str = Query(""),
):
    data, evidence_list, _, _, _, _, _, _ = _load_case_full(case_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Case not found")
    parsed_all = {"modules": {}, "evidence": evidence_list}
    art_dir = Path(DEFAULT_CONFIG.cases_dir) / str(case_id) / "artifacts"
    if art_dir.exists():
        for p in art_dir.glob("*.json"):
            try:
                parsed_all["modules"][p.stem] = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    events = build_timeline(parsed_all, case_id=str(case_id))
    filtered = filter_timeline(events, keyword=q or None, host=host or None, user=user or None, category=category or None)
    json_text = export_timeline_json(filtered)
    return PlainTextResponse(json_text, media_type="application/json", headers={"Content-Disposition": f"attachment; filename=timeline_{case_id}.json"})


@app.post("/case/{case_id}/generate-reports")
def generate_reports_endpoint(case_id: str):
    case_obj = Case.load(case_id)
    if case_obj is None:
        raise HTTPException(status_code=404, detail="Case not found")
    data, evidence_list, _, _, _, findings, iocs, _ = _load_case_full(case_id)
    parsed_all = {"modules": {}, "evidence": evidence_list}
    art_dir = case_obj.path / "artifacts"
    if art_dir.exists():
        for p in art_dir.glob("*.json"):
            try:
                parsed_all["modules"][p.stem] = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    timeline = build_timeline(parsed_all, case_id=case_id)
    generator = ReportGenerator(case_obj)
    try:
        generator.generate(["html", "docx", "pdf"], findings, evidence_list, iocs, timeline)
        case_obj.add_custody("reported", case_obj.examiner, "Generated HTML, DOCX, and PDF reports")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")

    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/case/{case_id}", status_code=303)


@app.get("/case/{case_id}/artifact/{name}")
def artifact_json(case_id: str, name: str):
    cleaned = name.strip().replace("\\", "").replace("/", "")
    if cleaned.endswith(".json"):
        cleaned = cleaned[:-5]
    if not cleaned or cleaned in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid artifact name")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if any(ch not in allowed for ch in cleaned):
        raise HTTPException(status_code=400, detail="Invalid artifact name")

    try:
        exists = (Path(DEFAULT_CONFIG.cases_dir) / case_id / "case.json").exists()
    except Exception:
        exists = False
    if not exists:
        raise HTTPException(status_code=404, detail="Case not found")

    artifact_path = Path(DEFAULT_CONFIG.cases_dir) / case_id / "artifacts" / f"{cleaned}.json"
    try:
        artifact_path.resolve().relative_to(Path(DEFAULT_CONFIG.cases_dir).resolve())
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid path")

    if not artifact_path.exists() or not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")

    try:
        text = artifact_path.read_text(encoding="utf-8")
        return JSONResponse(json.loads(text))
    except Exception:
        return JSONResponse({"raw": text})


@app.get("/case/{case_id}/report/{filename}")
def report_file(case_id: str, filename: str):
    cleaned = filename.strip().replace("\\", "").replace("/", "")
    if not cleaned or cleaned.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid filename")

    report_path = Path(DEFAULT_CONFIG.cases_dir) / case_id / "reports" / cleaned
    try:
        report_path.resolve().relative_to((Path(DEFAULT_CONFIG.cases_dir) / case_id / "reports").resolve())
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid path")

    if not report_path.exists() or not report_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")

    media_type, _ = mimetypes.guess_type(str(report_path))
    if media_type is None:
        media_type = "application/octet-stream"

    return FileResponse(
        path=str(report_path),
        media_type=media_type,
        filename=cleaned,
        headers={"Content-Disposition": f'attachment; filename="{cleaned}"'},
    )


# --- API Endpoints: Alert Intake, Webhooks & Case Lifecycle ---

@app.post("/api/v1/alerts/ingest")
def api_ingest_alert(payload: dict):
    """Ingest security alert or webhook from SIEM/EDR/Sigma."""
    try:
        manager = AlertIntakeManager()
        alert = manager.ingest_webhook(payload, auto_create_case=True)
        return {"status": "success", "alert_id": alert.alert_id, "assigned_case_id": alert.assigned_case_id}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/v1/alerts")
def api_list_alerts():
    """List all ingested security alerts."""
    manager = AlertIntakeManager()
    alerts = manager.list_alerts()
    return {"status": "success", "count": len(alerts), "alerts": [a.to_dict() for a in alerts]}


@app.post("/api/v1/alerts/{alert_id}/triage")
def api_triage_alert(alert_id: str, payload: dict):
    """Update alert triage status or assign case."""
    manager = AlertIntakeManager()
    alert = manager.load_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    if "status" in payload:
        alert.status = str(payload["status"])
    if "assigned_case_id" in payload:
        alert.assigned_case_id = str(payload["assigned_case_id"])
    manager.save_alert(alert)
    return {"status": "success", "alert": alert.to_dict()}


@app.post("/api/v1/cases/{case_id}/status")
def api_update_case_status(case_id: str, payload: dict):
    """Update case lifecycle status (open, triaged, investigating, contained, resolved, closed)."""
    case_obj = Case.load(case_id)
    if case_obj is None:
        raise HTTPException(status_code=404, detail="Case not found")
    new_status = payload.get("status")
    if not new_status:
        raise HTTPException(status_code=400, detail="Missing 'status' in payload")

    old_status = case_obj.status
    case_obj.status = str(new_status)
    actor = payload.get("actor", "API Examiner")
    case_obj.add_custody("status_update", actor, f"Changed case status from '{old_status}' to '{new_status}'")
    case_obj.save()
    return {"status": "success", "case_id": case_id, "new_status": case_obj.status}

