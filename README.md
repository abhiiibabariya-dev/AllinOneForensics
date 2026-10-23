<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=0,12,25,36,54&height=200&section=header&text=AllinOneForensics%20(AIOF)&fontSize=40&fontColor=fff&fontAlignY=38&desc=Unified%20DFIR,%20Incident%20Response%20&%20Threat%20Hunting%20Workbench&descSize=16&descAlignY=62" />
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-informational?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/Tests-28%2F28%20Passing-success?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/Mode-Offline%20First-orange?style=flat-square" alt="Mode">
</p>

---

## ⚡ Overview

**AllinOneForensics (AIOF)** is an extensible, offline-first Digital Forensics and Incident Response (DFIR) workbench designed for security teams, SOC analysts, and forensic investigators. It streamlines evidence preservation, tamper-evident audit logging, multi-platform artifact parsing, RBAC authorization, and NIST/ISO compliance reporting into a single high-speed Python application.

---

## 🧭 Navigation

- [Quick Start](#-quick-start)
- [Core Features](#-core-features)
- [Architecture & Workflow](#-architecture--workflow)
- [Documentation Hub](#-documentation-hub)
- [Security & Compliance](#-security--compliance)
- [Contributing & License](#-contributing--license)

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/abhiiibabariya-dev/AllinOneForensics.git
cd AllinOneForensics

# Install in editable mode with development dependencies
pip install -e .[dev,windows,memory,yara]

# Create a forensic case
aiof case create --name "Incident-2026-001" --examiner "Lead Analyst"

# Ingest evidence with automatic SHA-256 verification
aiof ingest Incident-2026-001 ./evidence/sample.evtx

# Parse artifacts & run threat correlation
aiof parse Incident-2026-001 --all

# Generate compliance & forensic reports (HTML, DOCX, PDF)
aiof report Incident-2026-001 --format html,docx,pdf

# Launch the interactive FastAPI Web UI dashboard
aiof ui
# Access locally at http://127.0.0.1:8088
```

---

## 🛡️ Core Capabilities

- **Evidence Preservation (`aiof/core/evidence.py`):** Computes cryptographic SHA-256 hashes and maintains immutable chain-of-custody manifests.
- **Tamper-Evident Audit Logging (`aiof/core/audit.py`):** HMAC-SHA256 hash-chained event logs protecting audit trails against undetected tampering.
- **Role-Based Access Control (`aiof/core/rbac.py`):** Enforces strict privilege tiers (`Admin`, `Senior Analyst`, `Junior Analyst`, `Auditor`, `Guest`).
- **Multi-Platform Parsers (`aiof/parsers/`):** Extracts logs, registry hives, and volatile structures across Windows, Linux, memory, and cloud outputs.
- **Threat Intelligence & Sigma (`aiof/analysis/`):** Matches IoCs and correlates behavior against Sigma detection rules and MITRE ATT&CK TTPs.
- **Compliance Center (`aiof/core/compliance.py`):** Generates automated assurance packages mapped to NIST CSF 2.0 and ISO 27001 controls.

---

## 🏗️ Architecture Blueprint

```mermaid
graph TD
    subgraph Ingestion ["1. Evidence Ingestion"]
        E1["Disk / RAM / Logs"] --> H["SHA-256 Hashing"]
        H --> M["Custody Manifest"]
    end
    subgraph Analysis ["2. Artifact Parsers & Intelligence"]
        M --> P["Parsers (Windows, Linux, Cloud)"]
        P --> S["Sigma & IoC Matcher"]
        S --> T["Chronological Super-Timeline"]
    end
    subgraph Delivery ["3. Actionable Output"]
        T --> UI["FastAPI Web Dashboard"]
        T --> R["HTML / DOCX / PDF Reports"]
    end
    style Ingestion fill:#111827,stroke:#374151,color:#fff
    style Analysis fill:#111827,stroke:#374151,color:#fff
    style Delivery fill:#111827,stroke:#374151,color:#fff
```

---

## 📚 Documentation Hub

- [Product Audit & Test Validation](docs/PRODUCT_AUDIT.md)
- [Enterprise Deployment Guide](docs/ENTERPRISE_DEPLOYMENT.md)
- [Plugin Development Guide](docs/PLUGIN_DEVELOPMENT.md)
- [Security Policy & Vulnerability Reporting](SECURITY.md)

---

## 🔒 Security & Offline Operation

- **Air-Gapped Design:** Operates fully offline without required external telemetry or cloud egress.
- **Cryptographic Assurance:** Every evidence exhibit and audit log entry is cryptographically bound and verifiable.

---

## 📄 License & Contributing

Distributed under the **Apache-2.0 License**. Contributions, bug reports, and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
