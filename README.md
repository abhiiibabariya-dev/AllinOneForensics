# AllinOneForensics

**All-in-one authorized DFIR workbench:** host, mobile, network, and cloud forensics. Works offline on isolated machines. Generates court-style DOCX/PDF/HTML reports.

**Usage:** Authorized DFIR investigations only (lab, client, your own devices). No offensive exploits or unauthorized access.

## Install

```bash
pip install allinoneforensics
```

Or from source:

```bash
git clone https://github.com/abhiiibabariya-dev/AllinOneForensics.git
cd AllinOneForensics
pip install -e .
```

## Quick Start

```bash
# Create case
aiof case create --name "IR-2026-091" --examiner "Abhi Babariya"

# Ingest evidence (read-only)
aiof ingest --case IR-2026-091 --path ./evidence/disk.E01
aiof ingest --case IR-2026-091 --path ./evidence/memory.raw
aiof ingest --case IR-2026-091 --path ./evidence/capture.pcap

# Parse artifacts
aiof parse --case IR-2026-091 --all

# Generate reports
aiof report --case IR-2026-091 --format html,docx,pdf

# Start web UI
aiof ui --case IR-2026-091
# Opens: http://127.0.0.1:8088
```

## Coverage

| Domain | v1 Status |
|--------|-----------|
| **Windows** | EVTX, registry, prefetch, Amcache, LNK, browser, JumpLists |
| **Linux** | `/var/log`, bash history, cron, systemd, users |
| **macOS** | Unified log (best-effort), LaunchAgents, browser |
| **Android** | ADB backup, packages, logcat, Chrome/SMS when unencrypted |
| **Memory** | Volatility3 adapter; fallback to hash + strings |
| **Network** | pcap ingest, DNS/HTTP/SNI parsing, beaconing heuristics |
| **Cloud** | CloudTrail/Azure Activity/GCP Audit JSON analysis |
| **IOC match** | Local hash/IP/domain/URL matching; optional `--online` feed |
| **Timeline** | Super-timeline merge with filter |
| **Reports** | HTML, DOCX, PDF with custody, findings, IOCs, MITRE ATT&CK |

## Documentation

Comprehensive forensic reference documentation lives in [`docs/`](docs/):

| Doc | Topic |
|-----|-------|
| [01](docs/01-computer-forensics-fundamentals.md) | Computer Forensics Fundamentals, Order of Volatility, Live vs Dead |
| [02](docs/02-windows-forensics.md) | Windows Forensics: MFT, Registry, Event Logs, Prefetch, LNK, JumpLists |
| [03](docs/03-memory-forensics.md) | Memory Forensics: acquisition, Volatility 3, injection/credential analysis |
| [04](docs/04-network-forensics.md) | Network Forensics: PCAP, DNS, JA3, beaconing, flow analysis |
| [05](docs/05-mobile-forensics.md) | Mobile Forensics: Android/iOS artifacts and acquisition |
| [06](docs/06-cloud-forensics.md) | Cloud Forensics: AWS/Azure/GCP audit log analysis |
| [07](docs/07-email-forensics.md) | Email Forensics: headers, SPF/DKIM/DMARC, PST/OST analysis |
| [08](docs/08-malware-forensics.md) | Malware Forensics: static/dynamic analysis, YARA, IOC extraction |
| [09](docs/09-timeline-analysis.md) | Timeline Analysis: super-timelines, cross-artifact correlation |
| [10](docs/10-forensic-tools.md) | Forensic Tools reference catalog and selection guide |
| [11](docs/11-dfir-workflow.md) | Complete DFIR Investigation Workflow (NIST SP 800-86) |
| [12](docs/12-case-studies.md) | Realistic Forensic Case Studies (ransomware, insider, APT, cloud, mobile) |
| [13](docs/13-interview-questions.md) | Forensic Interview & Scenario-Based Questions |
| [14](docs/14-quick-reference-tables.md) | Quick-Reference Tables for lookup during investigations |

## Offline-First

Every module works with zero network. Online enrichment is **disabled** unless you pass `--online`. Isolated machines supported.

## Roadmap (v1.x)

- Autopsy-style disk carving depth
- Full AXIOM artifact catalog
- Volatility3 default bundle
- Windows credential-artifact module (LSASS/SAM/DPAPI, analyst-confirmed)

## License

Apache-2.0. For authorized DFIR only.

## Contributing

See `CONTRIBUTING.md` for setup and testing.
