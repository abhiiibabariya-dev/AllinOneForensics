from __future__ import annotations

from html import escape

from fastapi.responses import HTMLResponse


DEMO_DATA = {
    "case_id": "DEMO-2026-001",
    "name": "Synthetic Phishing Investigation",
    "examiner": "Demo Analyst",
    "evidence": [
        {"name": "mailbox.eml", "sha256": "a3f4…9c21", "status": "Verified"},
        {"name": "auth.log", "sha256": "7b82…11de", "status": "Verified"},
    ],
    "findings": [
        {"severity": "High", "title": "Suspicious credential-harvesting link", "source": "email"},
        {"severity": "Medium", "title": "Authentication from unusual location", "source": "linux"},
    ],
    "iocs": [
        {"type": "domain", "value": "login-example.invalid"},
        {"type": "sha256", "value": "a3f4…9c21"},
    ],
    "timeline": [
        {"time": "2026-01-14 08:42 UTC", "event": "Message received", "source": "email"},
        {"time": "2026-01-14 08:47 UTC", "event": "Credential link clicked", "source": "browser"},
        {"time": "2026-01-14 08:51 UTC", "event": "Suspicious login observed", "source": "linux"},
    ],
    "steps": [
        ("1", "Preserve", "Hash evidence and record chain of custody."),
        ("2", "Parse", "Run platform parsers against the evidence set."),
        ("3", "Correlate", "Match IOCs and map behavior to MITRE ATT&CK."),
        ("4", "Report", "Review the timeline and export an investigation report."),
    ],
}


def demo_payload() -> dict:
    return {"mode": "synthetic-read-only", "notice": "All data is synthetic.", **DEMO_DATA}


def _rows(items: list[dict], columns: list[tuple[str, str]]) -> str:
    return "".join(
        "<tr>" + "".join(f"<td>{escape(str(item.get(key, '—')))}</td>" for key, _ in columns) + "</tr>"
        for item in items
    )


def render_demo() -> HTMLResponse:
    steps = "".join(
        f"<article class='step'><span>{number}</span><div><b>{escape(title)}</b><p>{escape(description)}</p></div></article>"
        for number, title, description in DEMO_DATA["steps"]
    )
    evidence = _rows(DEMO_DATA["evidence"], [("name", "Evidence"), ("sha256", "SHA-256"), ("status", "Integrity")])
    findings = _rows(DEMO_DATA["findings"], [("severity", "Severity"), ("title", "Finding"), ("source", "Source")])
    iocs = _rows(DEMO_DATA["iocs"], [("type", "Type"), ("value", "Value")])
    timeline = _rows(DEMO_DATA["timeline"], [("time", "Time"), ("event", "Event"), ("source", "Source")])
    html = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'><title>AIOF Guided Demo</title>
<style>
:root{{--bg:#08111f;--surface:#111d2e;--line:#29405e;--text:#edf5ff;--muted:#9fb2ca;--blue:#4da3ff;--green:#35d39a;--orange:#ffbd69;--red:#ff6b7a}}
*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(145deg,#08111f,#0d1a2c);color:var(--text);font:16px system-ui,sans-serif;line-height:1.55}}main{{max-width:1120px;margin:auto;padding:28px 20px 64px}}a{{color:var(--blue)}}h1{{font-size:clamp(2rem,5vw,4rem);line-height:1.08;margin:18px 0}}h2{{margin-top:0}}.eyebrow{{color:var(--green);font-weight:700;letter-spacing:.12em;text-transform:uppercase;font-size:.8rem}}.notice{{border:1px solid #6c4f20;background:#2a2113;color:#ffd996;padding:14px 16px;border-radius:10px;margin:22px 0}}.hero,.panel{{background:rgba(17,29,46,.92);border:1px solid var(--line);border-radius:16px;padding:24px;margin:18px 0;box-shadow:0 14px 35px #0003}}.hero p,.muted{{color:var(--muted)}}.buttons{{display:flex;flex-wrap:wrap;gap:12px;margin-top:22px}}.button{{display:inline-block;padding:10px 16px;border-radius:9px;background:var(--blue);color:#07111e;text-decoration:none;font-weight:700}}.button.alt{{background:#243752;color:var(--text)}}.steps{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}}.step{{display:flex;gap:12px;background:#172943;border:1px solid var(--line);padding:16px;border-radius:12px}}.step>span{{display:grid;place-items:center;flex:none;width:32px;height:32px;background:var(--blue);color:#07111e;border-radius:50%;font-weight:800}}.step p{{color:var(--muted);margin:.35rem 0 0;font-size:.9rem}}.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}.stat{{background:#172943;border:1px solid var(--line);padding:16px;border-radius:12px}}.stat b{{display:block;font-size:1.8rem}}.stat small{{color:var(--muted)}}.table-wrap{{overflow:auto}}table{{border-collapse:collapse;width:100%;min-width:460px}}th,td{{text-align:left;padding:11px;border-bottom:1px solid var(--line)}}th{{color:var(--muted);font-size:.8rem;text-transform:uppercase}}.ok{{color:var(--green)}}.high{{color:var(--red)}}footer{{color:var(--muted);text-align:center;margin-top:35px;font-size:.9rem}}
</style></head><body><main>
<section class='hero'><div class='eyebrow'>AllinOneForensics · Guided Demo</div><h1>From evidence to an explainable incident report.</h1><p>This safe, read-only walkthrough uses a synthetic phishing case. It demonstrates the investigation workflow without reading your computer, uploading files, or changing cases.</p><div class='buttons'><a class='button' href='/api/v1/demo'>View demo JSON</a><a class='button alt' href='https://github.com/abhiiibabariya-dev/AllinOneForensics/blob/main/docs/DEMO.md'>Read the tutorial</a><a class='button alt' href='/docs'>API documentation</a><button class='button alt' id='listen' type='button'>▶ Listen to overview</button></div><p id='audio-status' class='muted' aria-live='polite'>Audio narration uses your browser's built-in voice and sends no data anywhere.</p></section>
<script>
const listen = document.getElementById('listen');
const status = document.getElementById('audio-status');
const narration = 'Welcome to the AllinOneForensics guided demo. This synthetic case shows the four investigation steps: preserve evidence, parse artifacts, correlate indicators, and report the results. Every item on this page is synthetic and read only.';
listen.addEventListener('click', () => {{
  if (!('speechSynthesis' in window)) {{ status.textContent = 'Audio narration is not supported in this browser.'; return; }}
  if (speechSynthesis.speaking) {{ speechSynthesis.cancel(); listen.textContent = '▶ Listen to overview'; status.textContent = 'Narration stopped.'; return; }}
  const utterance = new SpeechSynthesisUtterance(narration);
  utterance.rate = 0.95;
  utterance.onend = () => {{ listen.textContent = '▶ Listen to overview'; status.textContent = 'Narration complete.'; }};
  speechSynthesis.speak(utterance);
  listen.textContent = '■ Stop narration'; status.textContent = 'Playing local narration.';
}});
</script>
<div class='notice'><b>Demo safety:</b> Synthetic data only · no login required · no uploads · no persistence · no network enrichment.</div>
<section class='panel'><h2>How an investigation works</h2><div class='steps'>{steps}</div></section>
<section class='panel'><h2>Case overview</h2><p class='muted'>{escape(DEMO_DATA['case_id'])} · {escape(DEMO_DATA['name'])} · {escape(DEMO_DATA['examiner'])}</p><div class='stats'><div class='stat'><b>2</b><small>Evidence items</small></div><div class='stat'><b class='high'>2</b><small>Findings</small></div><div class='stat'><b>2</b><small>IOCs extracted</small></div><div class='stat'><b class='ok'>Verified</b><small>Chain of custody</small></div></div></section>
<section class='panel'><h2>Evidence integrity</h2><div class='table-wrap'><table><thead><tr><th>Evidence</th><th>SHA-256</th><th>Integrity</th></tr></thead><tbody>{evidence}</tbody></table></div></section>
<section class='panel'><h2>Findings and indicators</h2><div class='table-wrap'><table><thead><tr><th>Severity</th><th>Finding</th><th>Source</th></tr></thead><tbody>{findings}</tbody></table></div><br><div class='table-wrap'><table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>{iocs}</tbody></table></div></section>
<section class='panel'><h2>Unified timeline</h2><div class='table-wrap'><table><thead><tr><th>Time</th><th>Event</th><th>Source</th></tr></thead><tbody>{timeline}</tbody></table></div></section>
<section class='panel'><h2>Next steps for a real case</h2><p>Install the package, create a case, ingest a forensic copy, run parsers, review findings, and generate reports. Keep the service on a private network, protect evidence originals, and never upload sensitive material to an untrusted host.</p><pre><code>pip install -e ".[dev]"
aiof case create --name "Incident-001" --examiner "Analyst"
aiof ingest Incident-001 ./evidence
aiof parse Incident-001 --all
aiof ui</code></pre></section>
<footer>AIOF synthetic demo · Offline-first DFIR workbench · <a href='/'>Open local dashboard</a></footer></main></body></html>"""
    return HTMLResponse(html)
