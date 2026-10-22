# Feature Audit — AllinOneForensics

## Existing Functionality and Implementation Status

| Component | Status | Description |
|---|---|---|
| **Case Management** | Implemented | Case creation, ID generation, evidence ingestion, inventory, SHA-256 verification, and case storage. |
| **Windows Parser** | Implemented | Basic EVTX, Registry, Prefetch, LNK, and browser artifact parsing. |
| **Linux Parser** | Implemented | `/var/log`, auth logs, bash history, cron, systemd, and user accounts. |
| **macOS Parser** | Implemented | Unified log heuristics, LaunchAgents, LaunchDaemons, and browser history. |
| **Android Parser** | Implemented | ADB backup, package list, logcat, and unencrypted Chrome/SMS. |
| **Network Parser** | Implemented | PCAP ingestion, DNS/HTTP/SNI parsing, and beaconing heuristics. |
| **Cloud Parser** | Implemented | AWS CloudTrail, Azure Activity, and GCP Audit JSON log analysis. |
| **Memory Parser** | Implemented | Volatility 3 adapter and fallback hash/strings parsing. |
| **Container Parser** | Implemented | Kubernetes audit logs and Docker inspect JSON analysis. |
| **Email Parser** | Implemented | EML/MSG header analysis, SPF/DKIM/DMARC checks, and attachment threat identification. |
| **Malware Parser** | Implemented | Static analysis and YARA rule signature matching. |
| **IOC Matching & MITRE ATT&CK** | Implemented | Local hash/IP/domain/URL matching and MITRE ATT&CK technique mapping. |
| **Unified Timeline** | Implemented | Chronological event merge, sorting, and keyword filtering. |
| **Reporting** | Implemented | HTML, DOCX, and PDF report generation. |
| **Web UI** | Implemented | FastAPI / Uvicorn interactive dashboard for cases, artifacts, and findings. |

## Bugs and Security Issues
- Hardcoded absolute paths in test fixtures resolved with dynamic `tmp_path`.
- Input validation and path traversal protections implemented for evidence ingestion.

## Missing Features
- Advanced STIX/TAXII automated threat Intel feed sync.
- Advanced Sigma rule matching engine.

## Dependencies and Platform Limitations
- Python 3.10+ required.
- Optional forensic tools (Volatility 3, YARA, Zeek) function gracefully when missing.
- Designed for offline-first operation on standalone forensic workstations.

## Prioritized Implementation Roadmap
1. Enhance test coverage across all new container, email, and malware parsers.
2. Refine unified timeline filtering and correlation.
3. Polish web UI dashboard and reporting exports.
