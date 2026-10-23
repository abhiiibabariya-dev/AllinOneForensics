# Tool Catalog

AllinOneForensics integrates proven open-source DFIR tools through standardized Python adapters.

| Tool Name | Category | Supported Formats / Evidence | Integration Method | Offline Compatible | License |
|---|---|---|---|---|---|
| **Volatility 3** | Memory | Raw memory dumps (`.raw`, `.dmp`, `.img`) | CLI / Python Library | Yes | VSL / PSF |
| **The Sleuth Kit** | Disk / FS | Raw disk images (`.dd`, `.raw`), E01 | CLI / Python wrappers | Yes | CPL 1.0 / GPLv2 |
| **Plaso** | Timeline | Disk images, storage artifacts, EVTX | CLI wrapper (`log2timeline`) | Yes | Apache 2.0 |
| **Hayabusa** | Windows EVTX | Windows Event Logs (`.evtx`) | Standalone binary / CLI | Yes | MIT |
| **Chainsaw** | Windows EVTX / Sigma | Windows Event Logs (`.evtx`), Sigma rules | Rust CLI wrapper | Yes | AGPL-3.0 |
| **YARA** | Malware / Triage | Any file, memory dumps, streams | `yara-python` / CLI | Yes | BSD 3-Clause |
| **Sigma** | Threat Intel | EVTX, JSON logs, structured events | PySigma / Rule Engine | Yes | MIT |
| **Zeek** | Network | PCAP, PCAPNG, packet captures | CLI wrapper / Log parser | Yes | BSD |
| **Suricata** | Network / IDS | PCAP, network traffic | CLI / Alert log parser | Yes | GPLv2 |
| **ALEAPP / iLEAPP** | Mobile | Android/iOS target directories, sqlite, tars | Python module / CLI | Yes | MIT |
| **Capa** | Malware | PE, ELF, shellcode binaries | Python library / CLI | Yes | Apache 2.0 |
