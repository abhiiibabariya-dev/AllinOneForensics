"""
aiof.web.app — Offline read-only FastAPI dashboard for AllinOneForensics.

No external CDN, no filesystem writes. All HTML is inline.
Binds to 127.0.0.1 by default. Every file read is wrapped in try/except.
"""
from __future__ import annotations

import json
import mimetypes
import html as html_lib
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse

from aiof.core.case import Case
from aiof.core.config import DEFAULT_CONFIG


app = FastAPI(
    title="AllinOneForensics — Offline Dashboard",
    docs_url=None,        # no swagger on isolated machines unless needed
    redoc_url=None,
    openapi_url="/openapi.json",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_list_cases() -> list[dict]:
    """List all cases by scanning cases_dir. Never raises."""
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
            # Normalize fields defensively
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

    # Sort by created_at descending-ish (newest first). Falls back to case_id.
    try:
        cases.sort(key=lambda c: (c["created_at"], c["case_id"]), reverse=True)
    except Exception:
        pass
    return cases


def _h(x: object) -> str:
    """HTML-escape."""
    return html_lib.escape(str(x) if x is not None else "", quote=True)


# ---------------------------------------------------------------------------
# Inline CSS / shared chrome
# ---------------------------------------------------------------------------

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
.wrap{max-width:1120px;margin:0 auto;padding:24px 20px 40px}
h1{font-size:1.45rem;margin:8px 0 4px}
.sub{color:var(--muted);font-size:.92rem;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}
.card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:16px 16px 14px;display:flex;flex-direction:column;gap:10px;
  transition:border-color .15s, transform .15s;
}
.card:hover{border-color:#3d444d;transform:translateY(-1px)}
.card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.card-title{font-weight:650;font-size:1rem;word-break:break-word}
.card-title a{color:var(--text)}
.card-title a:hover{color:var(--accent)}
.badge{
  display:inline-flex;align-items:center;gap:6px;
  font-size:.72rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;
  padding:3px 8px;border-radius:999px;border:1px solid var(--border);white-space:nowrap
}
.badge.open{background:rgba(35,134,54,.15);color:#3fb950;border-color:rgba(35,134,54,.35)}
.badge.closed{background:rgba(139,148,158,.15);color:var(--muted)}
.badge.archived{background:rgba(210,153,34,.15);color:#d29922;border-color:rgba(210,153,34,.35)}
.meta{display:grid;grid-template-columns:1fr 1fr;gap:6px 16px;font-size:.85rem;color:var(--muted)}
.meta b{color:var(--text);font-weight:600}
.kv{font-size:.85rem}
.kv span{color:var(--muted)}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  background:var(--accent-2);color:#fff;border:1px solid rgba(255,255,255,.08);
  padding:7px 12px;border-radius:8px;font-size:.85rem;font-weight:600;cursor:pointer
}
.btn:hover{background:#1a5fcc;color:#fff;text-decoration:none}
.btn-ghost{background:transparent;color:var(--text);border-color:var(--border)}
.btn-ghost:hover{background:var(--surface-2)}
.empty{
  border:1px dashed var(--border);border-radius:var(--radius);
  padding:32px;text-align:center;color:var(--muted);background:var(--surface)
}
.panel{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  overflow:hidden;margin-top:16px
}
.panel-head{
  padding:12px 16px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  background:var(--surface-2)
}
.panel-head h2{font-size:.95rem}
.panel-body{padding:14px 16px}
.kvs{display:grid;grid-template-columns:180px 1fr;gap:8px 16px;font-size:.9rem}
.kvs dt{color:var(--muted)}
.kvs dd{word-break:break-all}
.table-wrap{overflow:auto}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th{color:var(--muted);font-weight:600;text-align:left;font-size:.78rem;letter-spacing:.04em;text-transform:uppercase;
   border-bottom:1px solid var(--border);padding:8px 10px;white-space:nowrap;background:var(--surface-2)}
td{border-bottom:1px solid var(--border);padding:9px 10px;vertical-align:top;word-break:break-all}
tr:last-child td{border-bottom:none}
.hash{font-family:var(--mono);font-size:.82rem;color:#a5d6ff;word-break:break-all}
.pill{font-size:.72rem;padding:2px 7px;border-radius:999px;background:var(--surface-2);border:1px solid var(--border);white-space:nowrap}
.foot{color:var(--muted);font-size:.8rem;margin-top:18px;text-align:center}
pre.json{
  background:#0b0f14;border:1px solid var(--border);border-radius:8px;
  padding:14px;overflow:auto;font-family:var(--mono);font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word
}
.breadcrumb{font-size:.85rem;color:var(--muted);margin:10px 0 6px}
.breadcrumb a{color:var(--muted)}
.breadcrumb a:hover{color:var(--text)}
.alert{
  border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-size:.88rem;margin:10px 0
}
.alert-warn{background:rgba(210,153,34,.1);border-color:rgba(210,153,34,.35);color:#e3b341}
.alert-err{background:rgba(218,54,51,.1);border-color:rgba(218,54,51,.4);color:#ff7b72}
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard():
    cases = _safe_list_cases()
    if not cases:
        body = """
<h1>Cases</h1>
<p class="sub">No cases found in <span class="mono">{cases_dir}</span></p>
<div class="empty">
  <div style="font-size:1.1rem;margin-bottom:6px">No cases yet</div>
  <div>Create one with <code class="mono">aiof create "&lt;name&gt;" --examiner "&lt;you&gt;"</code></div>
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
  <div style="margin-top:4px"><a class="btn btn-ghost" href="/case/{_h(c['case_id'])}">View case &rarr;</a></div>
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
    # Load via Case class (defensive), fall back to raw JSON read
    data: dict | None = None
    artifacts: list[Path] = []
    reports: list[Path] = []
    evidence_list: list[dict] = []

    case_obj = None
    try:
        case_obj = Case.load(case_id)
    except Exception:
        case_obj = None

    if case_obj is not None:
        try:
            data = {
                "case_id": case_obj.case_id,
                "name": case_obj.name,
                "examiner": case_obj.examiner,
                "created_at": case_obj.created_at,
                "status": case_obj.status,
            }
            evidence_list = [
                {
                    "path": getattr(e, "path", ""),
                    "hash_sha256": getattr(e, "hash_sha256", ""),
                    "size_bytes": getattr(e, "size_bytes", ""),
                    "analyst": getattr(e, "analyst", ""),
                    "added_at": getattr(e, "added_at", ""),
                    "notes": getattr(e, "notes", ""),
                }
                for e in (getattr(case_obj, "evidence", []) or [])
            ]
        except Exception:
            data = None
        try:
            artifacts = list(case_obj.list_artifacts())
        except Exception:
            artifacts = []
        try:
            reports = list(case_obj.list_reports())
        except Exception:
            reports = []
    else:
        # Try raw read so we can still handle cases that exist on disk but
        # Case.load failed for any reason.
        try:
            raw_path = Path(DEFAULT_CONFIG.cases_dir) / case_id / "case.json"
            if raw_path.exists():
                data = json.loads(raw_path.read_text(encoding="utf-8"))
                evidence_list = data.get("evidence", []) if isinstance(data.get("evidence"), list) else []
                try:
                    artifacts = list((Path(DEFAULT_CONFIG.cases_dir) / case_id / "artifacts").glob("*.json"))
                except Exception:
                    artifacts = []
                try:
                    reports = list((Path(DEFAULT_CONFIG.cases_dir) / case_id / "reports").glob("*"))
                except Exception:
                    reports = []
        except Exception:
            data = None

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

    # Evidence rows
    if evidence_list:
        ev_rows: list[str] = []
        for ev in evidence_list:
            # Support both Evidence.to_dict shape and any ad-hoc dict
            e_path = ev.get("path", ev.get("file", "—"))
            e_hash = ev.get("hash_sha256", ev.get("hash", ev.get("sha256", "—")))
            e_size = ev.get("size_bytes", ev.get("size", "—"))
            try:
                e_size_str = f"{int(e_size):,}" if str(e_size).strip() not in ("", "—") else "—"
            except Exception:
                e_size_str = _h(e_size)
            ev_rows.append(
                f"<tr><td class='mono'>{_h(e_path)}</td>"
                f"<td class='hash'>{_h(e_hash)}</td>"
                f"<td style='white-space:nowrap'>{e_size_str}</td></tr>"
            )
        evidence_html = (
            '<div class="table-wrap"><table>'
            "<thead><tr><th>Path</th><th>SHA-256</th><th>Size (bytes)</th></tr></thead>"
            f"<tbody>{''.join(ev_rows)}</tbody></table></div>"
        )
    else:
        evidence_html = '<div class="alert alert-warn">No evidence recorded for this case.</div>'

    # Artifacts
    if artifacts:
        art_items: list[str] = []
        for p in sorted(artifacts):
            try:
                name_fs = p.name
                stem = p.stem
            except Exception:
                continue
            art_items.append(
                f'<tr><td class="mono">{_h(name_fs)}</td>'
                f'<td><a href="/case/{_h(cid)}/artifact/{_h(stem)}">View JSON</a></td></tr>'
            )
        artifacts_html = (
            '<div class="table-wrap"><table>'
            "<thead><tr><th>Artifact</th><th>Action</th></tr></thead>"
            f"<tbody>{''.join(art_items)}</tbody></table></div>"
        )
    else:
        artifacts_html = '<div class="alert alert-warn">No artifacts yet. Run <code class="mono">aiof parse ' + _h(cid) + '</code> to generate artifacts.</div>'

    # Reports
    if reports:
        rep_items: list[str] = []
        for p in sorted(reports):
            try:
                # Only list files, not dirs
                if not p.is_file():
                    continue
                fname = p.name
                try:
                    sz = p.stat().st_size
                    sz_str = f"{sz:,} bytes"
                except Exception:
                    sz_str = ""
            except Exception:
                continue
            rep_items.append(
                f'<tr><td class="mono">{_h(fname)}</td>'
                f'<td>{_h(sz_str)}</td>'
                f'<td><a href="/case/{_h(cid)}/report/{_h(fname)}" download>Download</a></td></tr>'
            )
        if rep_items:
            reports_html = (
                '<div class="table-wrap"><table>'
                "<thead><tr><th>Report</th><th>Size</th><th>Action</th></tr></thead>"
                f"<tbody>{''.join(rep_items)}</tbody></table></div>"
            )
        else:
            reports_html = '<div class="alert alert-warn">No report files found.</div>'
    else:
        reports_html = '<div class="alert alert-warn">No reports yet. Run <code class="mono">aiof report ' + _h(cid) + '</code> to generate reports.</div>'

    body = f"""
<div class="breadcrumb"><a href="/">Cases</a> / <span class="mono">{_h(cid)}</span></div>
<h1>{_h(name)} <span class="badge {badge_cls}" style="vertical-align:middle;margin-left:8px">{_h(status)}</span></h1>
<p class="sub mono">{_h(cid)} &middot; { _h(case_path) }</p>

<div class="panel">
  <div class="panel-head"><h2>Case Information</h2></div>
  <div class="panel-body">
    <dl class="kvs">
      <dt>Case ID</dt><dd class="mono">{_h(cid)}</dd>
      <dt>Name</dt><dd>{_h(name)}</dd>
      <dt>Examiner</dt><dd>{_h(examiner)}</dd>
      <dt>Created</dt><dd class="mono">{_h(created_at)}</dd>
      <dt>Status</dt><dd><span class="pill">{_h(status)}</span></dd>
      <dt>Path</dt><dd class="mono">{_h(case_path)}</dd>
      <dt>Evidence items</dt><dd>{len(evidence_list)}</dd>
    </dl>
  </div>
</div>

<div class="panel">
  <div class="panel-head"><h2>Evidence</h2><span class="pill">{len(evidence_list)} item(s)</span></div>
  <div class="panel-body" style="padding:0">{evidence_html}</div>
</div>

<div class="panel">
  <div class="panel-head"><h2>Artifacts</h2><span class="pill">{len(artifacts)} file(s)</span></div>
  <div class="panel-body" style="padding:0">{artifacts_html}</div>
</div>

<div class="panel">
  <div class="panel-head"><h2>Reports</h2><span class="pill">{len(reports)} file(s)</span></div>
  <div class="panel-body" style="padding:0">{reports_html}</div>
</div>
"""
    return HTMLResponse(_layout(f"{name} — {cid}", body))


@app.get("/case/{case_id}/artifact/{name}")
def artifact_json(case_id: str, name: str):
    # Validate name to prevent path traversal — allow only safe characters
    # Strip .json if provided, then re-append.
    cleaned = name.strip().replace("\\", "").replace("/", "")
    if cleaned.endswith(".json"):
        cleaned = cleaned[:-5]
    if not cleaned or cleaned in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid artifact name")
    # Extra safety: only allow alnum, dash, underscore, dot
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if any(ch not in allowed for ch in cleaned):
        raise HTTPException(status_code=400, detail="Invalid artifact name")

    # Verify case exists
    try:
        exists = (Path(DEFAULT_CONFIG.cases_dir) / case_id / "case.json").exists()
    except Exception:
        exists = False
    if not exists:
        try:
            if Case.load(case_id) is None:
                raise HTTPException(status_code=404, detail="Case not found")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=404, detail="Case not found")

    artifact_path = Path(DEFAULT_CONFIG.cases_dir) / case_id / "artifacts" / f"{cleaned}.json"
    # Ensure resolved path is still inside cases_dir (no traversal)
    try:
        artifact_path.resolve().relative_to(Path(DEFAULT_CONFIG.cases_dir).resolve())
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid path")

    if not artifact_path.exists() or not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")

    try:
        text = artifact_path.read_text(encoding="utf-8")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read artifact: {exc}")

    # Try to return parsed JSON; fall back to raw text
    try:
        data = json.loads(text)
        return JSONResponse(data)
    except Exception:
        return JSONResponse({"raw": text})


@app.get("/case/{case_id}/report/{filename}")
def report_file(case_id: str, filename: str):
    # Prevent path traversal
    cleaned = filename.strip().replace("\\", "").replace("/", "")
    if not cleaned or cleaned in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename")
    # Allow common report extensions; block hidden files
    if cleaned.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Verify case exists
    try:
        exists = (Path(DEFAULT_CONFIG.cases_dir) / case_id / "case.json").exists()
    except Exception:
        exists = False
    if not exists:
        try:
            if Case.load(case_id) is None:
                raise HTTPException(status_code=404, detail="Case not found")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=404, detail="Case not found")

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

    # FileResponse handles streaming + headers; wrap in try for safety
    try:
        return FileResponse(
            path=str(report_path),
            media_type=media_type,
            filename=cleaned,
            headers={"Content-Disposition": f'attachment; filename="{cleaned}"'},
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to serve report: {exc}")
