<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=0,12,25,36,54&height=220&section=header&text=AllinOneForensics%20(AIOF)&fontSize=45&fontColor=fff&fontAlignY=38&desc=Enterprise-Grade%20DFIR,%20Incident%20Response%20&%20Security%20Investigation%20Workbench&descSize=18&descAlignY=62" />
</p>

<p align="center">
  <a href="https://github.com/abhiiibabariya-dev/AllinOneForensics/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge&logo=opensourceinitiative&logoColor=white" /></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-informational?style=for-the-badge&logo=python&logoColor=yellow" />
  <img src="https://img.shields.io/badge/Tests-28%2F28%20Passing-success?style=for-the-badge&logo=checkmarx&logoColor=white" />
  <img src="https://img.shields.io/badge/Air--Gapped-100%25%20Offline-orange?style=for-the-badge&logo=tor&logoColor=white" />
  <img src="https://img.shields.io/badge/Architecture-Modular%20Plugin-purple?style=for-the-badge&logo=plugin&logoColor=white" />
</p>

---

## 🎯 1. Overview & Objectives

**AllinOneForensics (AIOF)** is a unified, high-speed, offline-first digital forensics and threat hunting workbench designed for security operations centers (SOCs), incident response (IR) teams, and forensic laboratories. Built adhering to **NIST SP 800-86** standards and enterprise security requirements, AIOF streamlines evidence ingestion, multi-platform artifact parsing, tamper-evident audit logging, RBAC authorization, and automated compliance reporting into a single robust platform.

---

## 🗺️ 2. Architectural Blueprint & Data Flow

```mermaid
graph TD
    subgraph INGESTION ["Phase 1: Secure Ingestion & Preservation"]
        I1["Disk Images (.raw, .img)"] --> HASH["SHA-256 Hashing Engine"]
        I2["Memory Dumps (.dmp)"] --> HASH
        I3["Cloud & Container Logs"] --> HASH
        HASH --> MANIFEST["Tamper-Evident Custody Manifest"]
    end

    subgraph PARSERS ["Phase 2: Multi-Platform Artifact Parsing"]
        MANIFEST --> P1["Windows Parser (EVTX, Registry, MFT)"]
        MANIFEST --> P2["Linux Parser (Auth, Syslog, Cron)"]
        MANIFEST --> P3["macOS Parser (Unified Logs, Plists)"]
        MANIFEST --> P4["Memory Parser (Volatility 3, RWX)"]
        MANIFEST --> P5["Cloud & Container (AWS, K8s Audit)"]
        MANIFEST --> P6["Network PCAP & Mobile Parser"]
    end

    subgraph INTELLIGENCE ["Phase 3: Threat Intelligence & Detection"]
        P1 & P2 & P3 & P4 & P5 & P6 --> S1["IOC Regex Matcher (IP, Domain, Hash)"]
        P1 & P2 & P3 & P4 & P5 & P6 --> S2["Sigma Rule Engine (Correlates Attacks)"]
        P1 & P2 & P3 & P4 & P5 & P6 --> S3["STIX/TAXII Intelligence Sync"]
        S1 & S2 & S3 --> MITRE["MITRE ATT&CK TTP Mapping (T1059, etc.)"]
    end

    subgraph OUTPUT ["Phase 4: Chronology & Actionable Action"]
        MITRE --> TL["Unified Chronological Super-Timeline"]
        TL --> UI["Interactive FastAPI Web UI Dashboard"]
        TL --> REP["Automated HTML / DOCX / PDF Reports"]
    end

    style INGESTION fill:#1e1e2e,stroke:#89b4fa,stroke-width:2px,color:#fff
    style PARSERS fill:#1e1e2e,stroke:#a6e3a1,stroke-width:2px,color:#fff
    style INTELLIGENCE fill:#1e1e2e,stroke:#f38ba8,stroke-width:2px,color:#fff
    style OUTPUT fill:#1e1e2e,stroke:#fab387,stroke-width:2px,color:#fff
```

---

## 🛠️ 3. Advanced Tool Suite: Purpose & Implementation

| Advanced Tool / Module | Code Path Reference | Purpose & What It Does | Implementation Status |
| :--- | :--- | :--- | :--- |
| **Case & Evidence Manager** | `aiof/core/` | Ingests evidence, computes SHA-256 hashes, and maintains chain of custody. | **Implemented & Tested** |
| **Tamper-Evident Audit Log** | `aiof/core/audit.py` | HMAC-SHA256 hash chaining ensuring tamper-resistant audit trails. | **Implemented & Tested** |
| **RBAC Authorization** | `aiof/core/rbac.py` | Role-based access control and permission verification decorators. | **Implemented & Tested** |
| **Plugin Trust Manager** | `aiof/core/plugins.py` | Plugin registry, signature verification, and security status control. | **Implemented & Tested** |
| **Compliance Exporter** | `aiof/core/compliance.py` | Generates NIST CSF 2.0 & ISO 27001 compliance export packages. | **Implemented & Tested** |
| **Interactive Web UI** | `aiof/web/app.py` | FastAPI web dashboard with KPI stats, alerts, and tool widgets. | **Implemented & Tested** |

---

## 📦 4. Quick Start Guide

```bash
# Clone the repository
git clone https://github.com/abhiiibabariya-dev/AllinOneForensics.git
cd AllinOneForensics

# Install in editable mode with all dependencies
pip install -e .[dev,windows,memory,yara]

# Run automated tests
pytest
```

---

## 🔒 5. Offline-First Security Guarantee

- **Air-Gapped Compliance:** Designed specifically for secure, air-gapped forensic laboratories with zero external telemetry egress by default.
- **Cryptographic Integrity:** SHA-256 evidence hashing and HMAC-SHA256 audit log chaining guarantee court admissibility and tamper resistance.

---

## 📄 6. License

Distributed under the **Apache-2.0 License**. Engineered exclusively for authorized Digital Forensics and Incident Response (DFIR) and educational contexts.
