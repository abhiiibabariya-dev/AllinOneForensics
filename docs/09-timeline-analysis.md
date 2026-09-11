# Timeline Analysis in Digital Forensics

## Overview

Timeline analysis reconstructs the sequence of events during an incident by correlating timestamps from multiple evidence sources into a unified chronological view. It is one of the most powerful techniques for understanding what happened, when, and in what order.

---

## 1. What Is a Super-Timeline?

### WHAT It Is
A super-timeline merges timestamps from all available evidence sources (filesystem, registry, logs, network) into a single chronological list. This allows investigators to see the full picture of an incident.

### Sources for Timeline Construction

| Source | Timestamp Type | What It Shows |
|--------|---------------|---------------|
| **NTFS MFT** | $STANDARD_INFORMATION, $FILE_NAME | File creation/modification/access |
| **Prefetch** | Last run time | Program execution |
| **Registry** | Key/value timestamps | Configuration changes |
| **Event Logs** | Event timestamps | System/security activity |
| **Browser history** | Visit timestamps | Web activity |
| **LNK files** | Target timestamps | File access |
| **Jump Lists** | Access timestamps | Application file access |
| **ShimCache** | Execution timestamps | Program execution |
| **Amcache** | Creation timestamps | Program installation/execution |
| **BAM/DAM** | Execution timestamps | Program execution per user |
| **SRUM** | Usage timestamps | Resource usage per program |
| **Network logs** | Connection timestamps | Network activity |
| **USB artifacts** | Connection/disconnect times | Device usage |

### HOW to Build a Super-Timeline

```bash
# Using Plaso (log2timeline)
log2timeline.py --storage-file timeline.plaso evidence_image.E01

# Generate CSV output
psort.py -o l2tcsv timeline.plaso -w timeline.csv

# Using AllinOneForensics
aiof parse CASE-001 --all
aiof timeline CASE-001 --keyword "malware"

# Manual timeline from Windows artifacts
MFTECmd.exe -f "$MFT" --csv mft.csv
EvtxECmd.exe -f Security.evtx --csv security.csv
PECmd.exe -d Prefetch/ --csv prefetch.csv
```

### Investigation Scenario: Ransomware Incident Timeline

**Scenario:** Ransomware encrypts files on a workstation. Build a timeline to understand the attack chain.

**Super-timeline reconstruction:**

| Time | Source | Event |
|------|--------|-------|
| 09:14:32 | Browser History | User visited phishing site |
| 09:14:55 | Browser Downloads | `invoice.pdf.exe` downloaded |
| 09:15:02 | LNK File | User opened file from Downloads |
| 09:15:03 | Prefetch | WINWORD.EXE executed |
| 09:15:05 | PowerShell Log | PowerShell spawned by Word |
| 09:15:08 | Sysmon Event 3 | Outbound connection to 185.141.27.99 |
| 09:15:10 | Registry | Run key persistence added |
| 09:15:12 | Amcache | Malware hash recorded |
| 09:15:15 | Security Log 4688 | `updater.exe` process created |
| 09:15:20 | MFT | File enumeration began (NTFS journal) |
| 09:15:30 | MFT | First files encrypted (.locked extension) |
| 09:16:00 | Ransom Note | `README-DECRYPT.txt` created |
| 09:25:00 | Security Log 1102 | Security log cleared (anti-forensics) |

---

## 2. Timeline Correlation Techniques

### Cross-Artifact Correlation
**WHAT:** Matching timestamps across different evidence sources to build a complete picture.

**Example:**
```
Prefetch: SVCHOST.EXE-11223344.pf  Last run: 09:15:03
    ↓ correlates with
Security Event 4688: svchost.exe spawned at 09:15:03 by updater.exe
    ↓ correlates with
Network Log: Connection to 185.141.27.99:443 at 09:15:08
    ↓ correlates with
MFT: File encryption began at 09:15:30
```

### Timestomping Detection in Timelines
**WHAT:** Comparing timestamps from different sources to detect timestamp manipulation.

**Technique:**
```
Cross-reference MFT $STANDARD_INFORMATION vs $FILE_NAME timestamps
Compare Prefetch last run with MFT creation time
Check Amcache hash timestamps against MFT
Verify Event Log timestamps against system clock
```

### Clock Skew Detection
**WHAT:** Identifying if the system clock was manipulated during the attack.

**Technique:**
- Compare Event Log timestamps with NTP server logs
- Check if timestamps jump forward/backward
- Correlate with external evidence (network logs, email timestamps)

---

## 3. Timeline Filtering and Analysis

### Filtering by Time Window
```bash
# Using AllinOneForensics timeline filter
aiof timeline CASE-001 --keyword "powershell"

# Using Plaso
psort.py timeline.plaso -a "2024-09-01 14:00:00" -b "2024-09-01 15:00:00"

# Manual CSV filtering
grep "2024-09-01 14:" timeline.csv
```

### Filtering by Artifact Type
```bash
# Only filesystem changes
grep -i "mft\|ntfs" timeline.csv

# Only program execution
grep -i "prefetch\|amcache\|bam\|shimcache" timeline.csv

# Only network activity
grep -i "network\|dns\|http" timeline.csv

# Only registry changes
grep -i "registry\|reg" timeline.csv
```

---

## 4. Timeline Analysis Quick Reference

| Analysis Goal | Primary Sources | Key Artifacts |
|--------------|----------------|---------------|
| **Program execution** | MFT, Prefetch, Amcache, BAM, UserAssist | File creation, last run times |
| **File access** | MFT, LNK, Jump Lists, Browser | Timestamps, target paths |
| **Network activity** | Network logs, DNS, Event Logs | Connections, queries |
| **User activity** | Browser, Recent Docs, ShellBags | Browsing, folder access |
| **Persistence** | Registry, Scheduled Tasks, Services | Run keys, task creation |
| **Privilege escalation** | Event Logs, Registry | Admin logon, group changes |
| **Anti-forensics** | Event Log gaps, timestomping detection | Log clearing, timestamp changes |
| **Lateral movement** | Event Logs 4624/4648, Network | RDP, SMB, WMI connections |
