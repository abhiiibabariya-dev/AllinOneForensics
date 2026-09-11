# Forensic Tools Reference

## Overview

This document provides a comprehensive catalog of digital forensic tools organized by function. All tools listed are industry-standard and used in authorized DFIR investigations.

---

## 1. Disk Imaging and Acquisition

| Tool | Platform | License | Purpose |
|------|----------|---------|---------|
| **FTK Imager** | Windows | Free | Disk imaging, evidence preview |
| **dd/dcfldd** | Linux | Open source | Bit-for-bit disk imaging |
| **Guymager** | Linux | Open source | GUI disk imaging |
| **X-Ways Forensics** | Windows | Commercial | Imaging, analysis |
| **EnCase** | Windows | Commercial | Complete forensic platform |
| **Autopsy** | Cross-platform | Open source | Disk forensics platform |

### Imaging Commands
```bash
# Linux disk imaging with hash verification
dcfldd if=/dev/sda of=/mnt/usb/evidence.E01 bs=4M hash=sha256 hashlog=/mnt/usb/hash.txt

# Create forensic image with compression
ewfacquire /dev/sdb -t /mnt/usb/evidence -C "Case-001" -e "Analyst" -d 2024-09-01
```

---

## 2. Memory Forensics

| Tool | Platform | License | Purpose |
|------|----------|---------|---------|
| **Volatility 3** | Cross-platform | Open source | Memory analysis framework |
| **LiME** | Linux | Open source | Linux memory acquisition |
| **WinPmem** | Windows | Open source | Windows memory acquisition |
| **DumpIt** | Windows | Free | Simple Windows memory dump |
| **Rekall** | Cross-platform | Open source | Memory analysis (legacy) |
| **Redline** | Windows | Free | Memory analysis (Mandiant) |

### Volatility 3 Commands
```bash
# Process listing
vol3 -f memory.raw windows.pslist

# Network connections
vol3 -f memory.raw windows.netscan

# Detect injected code
vol3 -f memory.raw windows.malfind

# Extract password hashes
vol3 -f memory.raw windows.hashdump
```

---

## 3. Network Forensics

| Tool | Platform | License | Purpose |
|------|----------|---------|---------|
| **Wireshark** | Cross-platform | Open source | Packet analysis GUI |
| **tshark** | Cross-platform | Open source | Packet analysis CLI |
| **Zeek (Bro)** | Linux | Open source | Network security monitoring |
| **RITA** | Linux | Open source | Beaconing detection |
| **NetworkMiner** | Windows | Free | Network forensic analysis |
| **Suricata** | Cross-platform | Open source | IDS/IPS and log generation |

### Network Analysis Commands
```bash
# Wireshark display filter examples
tshark -r evidence.pcap -Y "http.request" -T fields -e http.host
tshark -r evidence.pcap -Y "dns" -T fields -e dns.qry.name
tshark -r evidence.pcap -q -z conv,tcp

# Beaconing detection with RITA
rita analyze-captured evidence.pcap
rita show-beacons
```

---

## 4. Windows Artifact Analysis

| Tool | Platform | License | Purpose |
|------|----------|---------|---------|
| **Eric Zimmerman Tools** | Windows | Free | Complete Windows artifact analysis |
| **Autopsy** | Cross-platform | Open source | Comprehensive disk forensics |
| **Registry Explorer** | Windows | Free | Registry hive analysis |
| **MFTECmd** | Windows | Free | MFT parsing |
| **PECmd** | Windows | Free | Prefetch parsing |
| **EvtxECmd** | Windows | Free | Event log parsing |
| **ShellBags Explorer** | Windows | Free | ShellBags analysis |
| **JumpList Explorer** | Windows | Free | Jump List analysis |
| **AmcacheParser** | Windows | Free | Amcache analysis |

### Eric Zimmerman Tools Usage
```bash
# Parse MFT
MFTECmd.exe -f "C:\$MFT" --csv "C:\output" --csvf mft.csv

# Parse Prefetch
PECmd.exe -d C:\Windows\Prefetch --csv "C:\output"

# Parse Event Logs
EvtxECmd.exe -f Security.evtx --csv "C:\output"

# Parse Registry
RegistryExplorer.exe -f SOFTWARE
```

---

## 5. Mobile Forensics

| Tool | Platform | License | Purpose |
|------|----------|---------|---------|
| **Cellebrite UFED** | Windows | Commercial | Mobile extraction |
| **Magnet AXIOM** | Windows | Commercial | Mobile + computer forensics |
| **Oxygen Forensic Detective** | Windows | Commercial | Mobile forensics |
| **ADB** | Cross-platform | Open source | Android debugging/extraction |
| **libimobiledevice** | Linux/macOS | Open source | iOS device access |
| **ALEAPP** | Cross-platform | Open source | Android log analysis |
| **iLEAPP** | Cross-platform | Open source | iOS log analysis |

---

## 6. Malware Analysis

| Tool | Platform | License | Purpose |
|------|----------|---------|---------|
| **Ghidra** | Cross-platform | Open source | Reverse engineering |
| **IDA Pro** | Cross-platform | Commercial | Reverse engineering |
| **x64dbg** | Windows | Open source | Dynamic analysis debugger |
| **YARA** | Cross-platform | Open source | Pattern matching |
| **PE-bear** | Windows | Open source | PE analysis |
| **Detect It Easy** | Cross-platform | Open source | Binary identification |
| **FLOSS** | Cross-platform | Open source | Advanced string extraction |

---

## 7. Reporting and Documentation

| Tool | Platform | License | Purpose |
|------|----------|---------|---------|
| **AllinOneForensics** | Cross-platform | Open source | Complete DFIR workbench |
| **Log2Timeline/Plaso** | Cross-platform | Open source | Timeline generation |
| **Timesketch** | Cross-platform | Open source | Timeline collaboration |
| **KAPE** | Windows | Free | Artifact collection/triage |
| **Velociraptor** | Cross-platform | Open source | Endpoint monitoring/forensics |

---

## 8. Live Response

| Tool | Platform | License | Purpose |
|------|----------|---------|---------|
| **Velociraptor** | Cross-platform | Open source | Live endpoint collection |
| **KAPE** | Windows | Free | Quick artifact collection |
| **Autoruns** | Windows | Free | Persistence detection |
| **Process Explorer** | Windows | Free | Process analysis |
| **Process Monitor** | Windows | Free | Real-time monitoring |
| **Sysinternals Suite** | Windows | Free | Complete system utilities |
| **osquery** | Cross-platform | Open source | SQL-based system queries |

### Live Response Commands
```bash
# Using KAPE for quick triage
kape.exe --tsource C: --tdest D:\triage --module Evtx,Registry,Prefetch

# Using osquery
osqueryi "SELECT * FROM processes WHERE name = 'powershell.exe';"
osqueryi "SELECT * FROM listening_ports;"
osqueryi "SELECT * FROM hash WHERE path = '/tmp/suspicious.exe';"
```

---

## Tool Selection Guide

| Investigation Type | Primary Tools | Secondary Tools |
|-------------------|---------------|-----------------|
| **Disk forensics** | Autopsy, X-Ways, EnCase | FTK Imager, Guymager |
| **Memory forensics** | Volatility 3, LiME | Redline, Rekall |
| **Network forensics** | Wireshark, tshark | Zeek, RITA, Suricata |
| **Windows artifacts** | Eric Zimmerman Tools | Autopsy, Registry Explorer |
| **Mobile forensics** | Cellebrite, ALEAPP/iLEAPP | Oxygen, Magnet AXIOM |
| **Malware analysis** | Ghidra, YARA, CAPE | IDA Pro, x64dbg, FLOSS |
| **Timeline** | Plaso, AllinOneForensics | Timesketch |
| **Live response** | Velociraptor, KAPE | Autoruns, Process Explorer |
| **Triage** | KAPE, Velociraptor | AllinOneForensics |
| **Reporting** | AllinOneForensics | KAPE, Plaso |
