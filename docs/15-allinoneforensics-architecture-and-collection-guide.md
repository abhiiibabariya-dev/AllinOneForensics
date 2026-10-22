# AllinOneForensics — Architecture, Process & Evidence Collection Guide
**Author / Maintainer:** Abhishek Babariya  
**Repository:** [AllinOneForensics](https://github.com/abhiiibabariya-dev/AllinOneForensics)

---

## 1. How It Works (Architecture)

AllinOneForensics (`aiof`) is an offline-first, modular Digital Forensics and Incident Response (DFIR) workbench. It operates entirely locally without requiring internet connectivity unless explicit `--online` enrichment is requested.

### Core Workflow Pipeline
1. **Case Creation (`aiof case create`)**: Initializes a secure case workspace with cryptographic chain-of-custody tracking.
2. **Evidence Ingestion (`aiof ingest`)**: Imports forensic exhibits (disk images, memory dumps, PCAPs, audit logs) while computing SHA-256 hashes to guarantee evidence integrity.
3. **Artifact Parsing (`aiof parse`)**: Dispatches modular parsers across domains (Windows, Linux, macOS, Android, Cloud, Containers, Memory, Network, Email, Malware).
4. **IOC Matching & Timeline Correlation (`aiof hunt` / `aiof timeline`)**: Correlates extracted artifacts against IOC databases and builds a unified chronological super-timeline.
5. **Reporting (`aiof report`)**: Generates court-ready HTML, DOCX, and PDF reports including MITRE ATT&CK technique mappings and chain-of-custody logs.
6. **Web UI (`aiof ui`)**: Launches a FastAPI/Uvicorn interactive local web interface for case review.

---

## 2. Forensic Process (NIST SP 800-86 Aligned)

1. **Preparation**: Establish legal authorization, tooling, and secure offline workbench environment.
2. **Collection & Acquisition**: Acquire volatile and non-volatile data maintaining cryptographic integrity (SHA-256).
3. **Examination & Parsing**: Run domain-specific parsers to extract artifacts, logs, registry keys, and process tables.
4. **Analysis & Threat Hunting**: Cross-reference against IOCs, analyze beaconing heuristics, inspect memory injections, and evaluate cloud/container audit logs.
5. **Reporting & Presentation**: Export findings into professional reports with MITRE ATT&CK technique classifications and IRIS/MobSF interoperability.

---

## 3. What to Collect (Evidence Matrix)

| Domain | Recommended Artifacts / Exhibits | Key Forensic Value |
| :--- | :--- | :--- |
| **Windows** | `$MFT`, Registry (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`), EVTX Event Logs, Prefetch, Amcache, LNK files, JumpLists | Execution, persistence, user activity, file access |
| **Linux** | `/var/log/*`, `/etc/passwd`, `/etc/shadow`, Bash history, crontab, systemd units | Access logs, privilege escalation, persistence mechanisms |
| **macOS** | Unified logs (`.log`, `.traceV3`), LaunchAgents (`~/Library/LaunchAgents`), browser history | Persistence, user execution |
| **Android** | ADB backups, package lists, logcat dumps, unencrypted SMS/Chrome databases | Mobile app activity, communications, device state |
| **Cloud** | AWS CloudTrail JSON, Azure Activity Logs, GCP Audit Logs | IAM privilege abuse, unauthorized API calls, resource creation |
| **Containers** | Kubernetes audit logs (`audit.json`), Docker inspect JSON (`HostConfig`) | Unauthenticated API access, privileged containers, host mount escapes |
| **Memory** | Raw RAM dumps (`.raw`, `.dmp`), Volatility 3 JSON output (`pslist`, `netscan`, `malfind`) | Running processes, injected code, network connections |
| **Network** | Packet captures (`.pcap`, `.pcapng`) | C2 beaconing, DNS tunneling, exfiltration, HTTP headers |
| **Email** | `.eml`, `.msg` files | Phishing campaigns, SPF/DKIM/DMARC failures, malicious attachments |
| **Malware** | PE executables, suspicious scripts, MobSF scan reports | Static analysis, YARA rule matching, CVE vulnerabilities |

---
