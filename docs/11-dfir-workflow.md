# Complete DFIR Investigation Workflow

## Overview

This document outlines the standard workflow for conducting a Digital Forensics and Incident Response (DFIR) investigation. The workflow follows NIST SP 800-86 and industry best practices.

---

## Phase 1: Preparation

### Activities
- Maintain forensic workstation readiness
- Keep tools updated and tested
- Document standard operating procedures (SOPs)
- Train team on evidence handling
- Establish relationships with legal and management

### Checklist
- [ ] Forensic workstation imaged and verified
- [ ] Write-blockers tested
- [ ] Trusted tools on external media ready
- [ ] Chain of custody forms prepared
- [ ] Evidence storage secured
- [ ] Legal authorization templates ready
- [ ] Communication plan established

---

## Phase 2: Detection and Analysis

### Activities
- Triage alerts from SIEM/EDR
- Determine scope and impact
- Identify affected systems and data
- Preserve volatile evidence
- Document initial findings

### Analysis Steps
1. **Alert triage** — Determine if the alert is a true positive
2. **Scope assessment** — How many systems are affected?
3. **Evidence preservation** — Capture volatile data before it's lost
4. **Initial analysis** — What happened, when, and how?
5. **IOC generation** — Extract hashes, IPs, domains, URLs
6. **Hunt operations** — Search for additional compromised systems

### Investigation Decision Tree
```
Alert received
├── Is it a true positive?
│   ├── Yes → Begin incident response
│   └── No → Document as false positive, tune detection
├── What is the scope?
│   ├── Single host → Host-based investigation
│   ├── Multiple hosts → Network investigation
│   └── Cloud environment → Cloud investigation
└── What data is at risk?
    ├── PII → Legal notification requirements
    ├── Financial → Business impact assessment
    └── Intellectual property → Espionage investigation
```

---

## Phase 3: Containment

### Short-Term Containment
- Isolate affected systems from network
- Preserve evidence before system changes
- Block malicious IPs/domains at firewall
- Disable compromised accounts

### Long-Term Containment
- Deploy temporary network segmentation
- Implement additional monitoring
- Patch vulnerabilities
- Harden affected systems

### Containment Decision Matrix

| Scenario | Immediate Action | Follow-up |
|----------|-----------------|-----------|
| **Active malware** | Isolate host (don't power off) | Memory dump, disk image |
| **Compromised account** | Disable account, revoke sessions | Password reset, MFA |
| **Data exfiltration** | Block outbound connections | Forensic analysis |
| **Ransomware** | Isolate immediately | Image before analysis |
| **Insider threat** | Monitor, don't alert suspect | Covert investigation |

---

## Phase 4: Eradication

### Activities
- Remove malware from all affected systems
- Delete persistence mechanisms (registry keys, scheduled tasks)
- Patch exploited vulnerabilities
- Reset all compromised credentials
- Verify system integrity

### Eradication Checklist
- [ ] All malware binaries identified and removed
- [ ] Registry persistence keys deleted
- [ ] Scheduled tasks removed
- [ ] Services stopped and disabled
- [ ] Compromised accounts disabled and passwords reset
- [ ] Vulnerabilities patched
- [ ] System files verified (SFC /scannow)
- [ ] Backdoor accounts removed

---

## Phase 5: Recovery

### Activities
- Restore systems from known-good backups
- Rebuild systems if necessary
- Implement additional monitoring
- Validate system functionality
- Return systems to production

### Recovery Steps
1. **Verify backup integrity** — Ensure backups are clean
2. **Rebuild systems** — Fresh OS installation if compromise was deep
3. **Restore data** — From verified clean backups
4. **Harden systems** — Apply security baselines
5. **Monitor closely** — Enhanced logging and alerting
6. **Validate functionality** — Ensure business operations resume

---

## Phase 6: Post-Incident Activity

### Activities
- Conduct lessons learned meeting
- Update detection rules
- Improve security controls
- Document timeline and findings
- Generate forensic report

### Post-Incident Report Structure
```
1. Executive Summary
2. Incident Timeline
3. Technical Findings
4. Evidence Inventory
5. IOCs and MITRE ATT&CK Mapping
6. Recommendations
7. Lessons Learned
```

---

## Using AllinOneForensics in the Workflow

### Complete Investigation Commands
```bash
# 1. Create case
aiof case create --name "IR-2024-091" --examiner "Analyst Name"

# 2. Ingest evidence
aiof ingest IR-2024-091 ./evidence/disk.E01
aiof ingest IR-2024-091 ./evidence/memory.raw
aiof ingest IR-2024-091 ./evidence/capture.pcap

# 3. Parse all artifacts
aiof parse IR-2024-091 --all

# 4. Hunt for IOCs
aiof hunt IR-2024-091 --iocs ./intel/custom_iocs.json

# 5. Build timeline
aiof timeline IR-2024-091

# 6. Generate report
aiof report IR-2024-091 --format html,docx,pdf

# 7. View in web UI
aiof ui IR-2024-091
```

---

## DFIR Workflow Quick Reference

| Phase | Key Activities | Primary Tools |
|-------|---------------|--------------|
| **Preparation** | SOPs, tool readiness | Playbooks, training |
| **Detection** | Alert triage, scope assessment | SIEM, EDR, AllinOneForensics |
| **Containment** | Isolate, preserve, block | Network controls, EDR |
| **Eradication** | Remove malware, patch, harden | Manual removal, scripting |
| **Recovery** | Restore, rebuild, validate | Backups, monitoring |
| **Lessons Learned** | Review, improve | Reporting, AllinOneForensics |
