# AllinOneForensics (AIOF)

> Unified Digital Forensics, Incident Response, and Security Investigation Workbench.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/abhiiibabariya-dev/AllinOneForensics/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-informational)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-28%2F28%20Passing-success)](docs/PRODUCT_AUDIT.md)

---

## Navigation

- [Quick Start](#quick-start)
- [Core Features](#core-features)
- [Architecture & Workflow](#architecture--workflow)
- [Documentation & Product Audit](docs/PRODUCT_AUDIT.md)
- [Security & Compliance](SECURITY.md)

---

## Core Features

- **Case & Evidence Management:** Ingest evidence with automatic SHA-256 integrity verification and custody tracking (`aiof/core/`).
- **Tamper-Evident Audit Trails:** HMAC-SHA256 hash-chained event logging ensuring verifiable integrity (`aiof/core/audit.py`).
- **Role-Based Access Control (RBAC):** Granular permission enforcement and decorators (`aiof/core/rbac.py`).
- **Plugin Trust & Verification:** Cryptographic plugin signing and registry management (`aiof/core/plugins.py`).
- **Compliance Reporting:** Export packages mapped to NIST CSF 2.0 and ISO 27001 standards (`aiof/core/compliance.py`).
- **Interactive Web Dashboard:** FastAPI-powered investigator workspace (`aiof/web/app.py`).

---

## Architecture & Workflow

```mermaid
graph TD
    A[Evidence Ingestion] --> B[SHA-256 Hashing & Manifest]
    B --> C[Multi-Platform Parsers]
    C --> D[Sigma & IOC Detection]
    D --> E[Chronological Super-Timeline]
    E --> F[FastAPI Web UI & Reports]
```

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/abhiiibabariya-dev/AllinOneForensics.git
cd AllinOneForensics

# Install package in editable mode
pip install -e .[dev]

# Run test suite
pytest
```

---

## License

Distributed under the Apache-2.0 License. Designed for authorized digital forensics and incident response.
