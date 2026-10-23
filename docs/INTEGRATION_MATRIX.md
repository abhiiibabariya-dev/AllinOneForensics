# Integration Matrix

Mapping of external forensic tools to AllinOneForensics workbench modules, execution modes, and platform compatibility.

| Module | Tool | Execution Wrapper | Platforms | Input Requirements | Output Normalization |
|---|---|---|---|---|---|
| `aiof.integrations.volatility3` | Volatility 3 | Subprocess / Python API | Linux, macOS, Windows | Raw Memory Dump (`.dmp`/`.raw`) | Standardized process list, network connections |
| `aiof.integrations.sleuthkit` | TSK (fls, mmls, icat) | Subprocess (`fls`, `mmls`, `icat`) | Linux, macOS, Windows | Disk Image (`.dd`, `.raw`) | File metadata, partition table, path records |
| `aiof.integrations.plaso` | Plaso (log2timeline) | Subprocess (`log2timeline`, `psort`) | Linux, macOS | Disk images, directories | Normalized timeline event stream (`.jsonl`) |
| `aiof.integrations.hayabusa` | Hayabusa | Subprocess (`hayabusa`) | Linux, macOS, Windows | Windows Event Logs (`.evtx`) | Timelines, threat level findings, alerts |
| `aiof.integrations.chainsaw` | Chainsaw | Subprocess (`chainsaw`) | Linux, macOS, Windows | EVTX + Sigma rules | Structured threat matches |
| `aiof.integrations.yara` | YARA | `yara-python` / Subprocess | All platforms | Any file / directory / memory | Rule matches, offsets, tags |
| `aiof.integrations.sigma` | PySigma Engine | Native Python parser | All platforms | Sigma YAML rules + log records | Correlated security alerts |
| `aiof.integrations.zeek` | Zeek | Subprocess (`zeek`) | Linux, macOS | PCAP / PCAPNG | Conn, dns, http JSON event logs |
| `aiof.integrations.suricata` | Suricata | Subprocess (`suricata`) | Linux, macOS, Windows | PCAP / Live interface | `fast.log`, `eve.json` alerts |
| `aiof.integrations.mobile` | ALEAPP / iLEAPP | Python module / Subprocess | All platforms | Device backup / extraction path | Artifact parsed records |
| `aiof.integrations.malware` | Capa / File Intel | Python / Subprocess | All platforms | Executables (PE/ELF) | Capability taxonomy, metadata |
