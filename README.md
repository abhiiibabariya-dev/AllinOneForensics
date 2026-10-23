# AllinOneForensics (AIOF)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-production--ready-green)]()

**All-in-one authorized Digital Forensics and Incident Response (DFIR) workbench.** Engineered for comprehensive host, mobile, network, cloud, container, and memory analysis. Designed for offline-first operation on standalone forensic workstations with zero external dependency requirements.

---

## 🏗️ Architecture & Investigation Workflow

AllinOneForensics follows the **NIST SP 800-86** incident response lifecycle and rigorous chain-of-custody standards:

```
[1. Acquisition & Ingestion] ---> (SHA-256 Hashing & Custody Log)
              │
              ▼
[2. Multi-Platform Parsing] ----> (Windows, Linux, macOS, Cloud, Container, Memory, Network, Mobile)
              │
              ▼
[3. Advanced Analysis Engine] --> (IOC Matching, STIX/TAXII Threat Intel, Sigma Rule Correlation, MITRE ATT&CK)
              │
              ▼
[4. Unified Chronology] --------> (Super-timeline Generation & Keyword Filtering)
              │
              ▼
[5. Actionable Output] ---------> (Interactive Web UI, HTML / DOCX / PDF Reports, CSV Manifests)
```

---

## 🚀 Key Features & Modules

### 1. Evidence Ingestion & Chain of Custody
- **Cryptographic Integrity:** Computes SHA-256 hashes for all ingested files/directories.
- **Integrity Verification:** Continuous verification (`verify_evidence_integrity`) detecting missing or modified evidence.
- **Manifest Export:** Export tamper-evident manifests in JSON and CSV formats.

### 2. Multi-Platform Artifact Parsers
- **Windows:** EVTX event logs, Registry hives, Prefetch, Amcache, LNK files, JumpLists, and browser history.
- **Linux:** `/var/log` analysis, auth logs, bash history, cron jobs, systemd services, and user accounts.
- **macOS:** Unified log heuristics, LaunchAgents, LaunchDaemons, and browser artifacts.
- **Android & Mobile:** ADB backup extraction, package list inspection, logcat dumps, and unencrypted Chrome/SMS.
- **Network & PCAP:** Ingestion of `.pcap` files, DNS/HTTP/SNI extraction, and beaconing frequency heuristics.
- **Cloud Auditing:** JSON log analysis for AWS CloudTrail, Azure Activity, and GCP Audit logs.
- **Memory Forensics:** Volatility 3 integration with robust string/hash fallbacks.
- **Container Security:** Kubernetes audit log analysis (unauthenticated access, dangerous RBAC bindings) and Docker inspect JSON analysis (privileged containers, host volume binds).
- **Email & Malware:** EML/MSG header analysis, SPF/DKIM/DMARC checks, static malware analysis, and YARA rule signature matching.

### 3. Advanced Threat Intelligence & Detection
- **STIX/TAXII Threat Intel Sync:** Automated parsing and integration of STIX 2.x bundles (`aiof/intel/stix_sync.py`).
- **Sigma Rule Matching Engine:** High-fidelity event pattern matching against custom or built-in Sigma rules (`aiof/analysis/sigma.py`).
- **MITRE ATT&CK Mapping:** Automatic association of findings to ATT&CK tactics and techniques.

---

## 📦 Installation

```bash
pip install allinoneforensics
```

Or clone and install in editable mode:
```bash
git clone https://github.com/abhiiibabariya-dev/AllinOneForensics.git
cd AllinOneForensics
pip install -e .
```

---

## 🕹️ Quick Start Guide

```bash
# 1. Create a new forensic case
aiof case create --name "IR-2026-091" --examiner "Analyst Name"

# 2. Ingest evidence (read-only preservation)
aiof ingest --case IR-2026-091 --path ./evidence/disk_image.raw
aiof ingest --case IR-2026-091 --path ./evidence/k8s_audit.json

# 3. Run multi-platform parsers and analysis
aiof parse --case IR-2026-091 --all

# 4. Generate court-ready reports (HTML, DOCX, PDF)
aiof report --case IR-2026-091 --format html,docx,pdf

# 5. Launch interactive Web UI dashboard
aiof ui --case IR-2026-091
# Access at: http://127.0.0.1:8088
```

---

## 📺 Visual Demo & UI Walkthrough

### Terminal CLI Execution
```text
$ aiof parse --case IR-2026-091 --all
[+] Loading forensic case: IR-2026-091
[+] Verifying evidence integrity (SHA-256): 12 files intact (0 modified)
[+] Running Windows, Linux, macOS, Network, and Cloud Artifact Parsers...
[+] Sigma Rule Engine matched 3 high-severity indicators.
[+] Super-timeline generated successfully (1,420 events).
[✓] Analysis complete. Reports generated: ./cases/IR-2026-091/reports/
```

### Interactive Web UI Dashboard
```text
 +-----------------------------------------------------------------------+
 | AllinOneForensics (AIOF) - Active Case: IR-2026-091                   |
 +-----------------------------------------------------------------------+
 | [Cases] [Evidence & Integrity] [Parsers] [Timeline] [IOCs] [Reports]  |
 +-----------------------------------------------------------------------+
 | 📊 Case Statistics & Evidence Integrity:                              |
 |   - Total Evidence Items: 12   - SHA-256 Verified: 100% Intact        |
 |   - High-Severity Findings: 3  - IOC Matches: 2                       |
 |                                                                       |
 | 🔍 Recent Suspicious Findings:                                        |
 |   [High] Sigma/sigma-001: PowerShell Encoded Command Execution        |
 |   [High] Windows/Defender/Threat: Trojan:Win32/Emotet detected         |
 |   [Med]  Linux/Auth: Failed SSH login attempt from 192.168.1.50       |
 +-----------------------------------------------------------------------+
```

---

## 🔒 Offline-First Guarantee

AllinOneForensics operates 100% offline by default. No external telemetry or telemetry egress unless explicitly requested via `--online`. Fully compatible with air-gapped secure labs.

---

## 📄 License & Compliance

Licensed under the **Apache-2.0 License**. Authorized DFIR, security research, and educational use only.
