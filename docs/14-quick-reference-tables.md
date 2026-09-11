# Forensic Quick-Reference Tables

## Overview

This document consolidates the most-used forensic reference information into single-source tables for rapid lookup during investigations. Each table is designed to be printed or kept open on a second monitor.

---

## 1. Order of Volatility

| Priority | Data Source | Notes |
|----------|-------------|-------|
| 1 | Registers, processor cache | Lost instantly |
| 2 | RAM (physical memory) | Lost on power-off / reboot |
| 3 | Network state, live connections | Lost on disconnect |
| 4 | Running processes, open files | Lost on process termination |
| 5 | Swap / pagefile | Persists temporarily after shutdown |
| 6 | Disk (persistent storage) | Survives reboot |
| 7 | Remote logs, cloud telemetry | Survives, but retention-limited |
| 8 | Archival / backups | Most stable, longest retention |

**Rule:** Collect from 1 → 8, never reverse-order when volatile evidence is at stake.

---

## 2. Windows Timeline Construction Sources

| Artifact | Location | Timestamp | Reveals |
|----------|----------|-----------|---------|
| **MFT** | `$MFT` (NTFS root) | SI/FN creation, mtime, atime | File lifecycle, timestomping |
| **$LogFile** | `$LogFile` | Historical write ops | File creation before/after timestamps |
| **$USN Journal** | `$Extend\$UsnJrnl` | Journal timestamps | File ops not reflected in MFT |
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | Last-run time, run count | Program execution |
| **Amcache** | `C:\Windows\AppCompat\Programs\Amcache.hve` | Install/exec time | Program install chains |
| **ShimCache** | SYSTEM hive | Last-modified | Program execution (system-wide) |
| **UserAssist** | NTUSER.DAT | Last-run, run count | GUI program usage (ROT-13) |
| **BAM/DAM** | SYSTEM hive | Execution timestamps | Per-user program execution |
| **Event Logs** | `C:\Windows\System32\winevt\Logs\*.evtx` | Event time | Logons, process creation, services |
| **ShellBags** | USRCLASS.DAT | Last access | Folder navigation history |
| **Jumplists** | `AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` | File access | Application-specific file access |
| **LNK files** | `AppData\...\Recent\*.lnk` | Target timestamps | File access evidence |
| **Browser history** | SQlite DBs (Chrome/Firefox) | Visit time, download time | Web activity |

---

## 3. Critical Windows Event IDs

| Event ID | Description | Forensic Value |
|----------|-------------|----------------|
| **4624** | Successful logon | Who logged in, from where (key field: LogonType) |
| **4625** | Failed logon | Brute-force / password spray indicators |
| **4648** | Explicit credentials logon | Lateral movement / pass-the-hash |
| **4672** | Special privileges assigned | Admin account use |
| **4688** | Process creation | Malware execution, process chain |
| **4720** | User account created | Account creation (attack or persistence) |
| **4732 / 4728** | User added to local/global group | Privilege escalation |
| **7045** | Service installed | Service-based persistence / malware |
| **1102** | Audit log cleared | Anti-forensics signature |
| **4104** | PowerShell script block logged | Fileless / script-based attacks |
| **Sysmon 1** | Process create | Deeper process tracking (with Sysmon) |
| **Sysmon 3** | Network connect | Outbound C2 connection |
| **Sysmon 11** | File create | Dropper / ransomware file creation |
| **Sysmon 22** | DNS query | DNS exfil / DGA detection |

### Windows Logon Types

| Type | Name | Meaning |
|------|------|---------|
| 2 | Interactive | Local keyboard login, console |
| 3 | Network | SMB / UNC share access |
| 4 | Batch | Scheduled task / batch job |
| 5 | Service | Service account logon |
| 7 | Unlock | Unlocking a locked screen |
| 8 | NetworkCleartext | Cleartext network auth (IIS) |
| 10 | RemoteInteractive | RDP (different IP = remote compromise) |
| 11 | CachedInteractive | Offline cached domain logon |

---

## 4. Registry Forensic Keys

| Key | Evidence | What It Shows |
|-----|----------|---------------|
| `...\Run` / `RunOnce` (HKCU & HKLM) | Persistence | Programs auto-starting at logon |
| `...\RunService` | Persistence | Services auto-starting |
| `HKLM\SYSTEM\...\Enum\USBSTOR` | USB history | Device serial, first/last connected |
| `HKLM\SYSTEM\...\MountedDevices` | Drive mapping | Volume GUIDs, drive letters |
| `HKCU\...\UserAssist\{GUID}\Count` | Execution (ROT-13) | Program run count, last run |
| `HKCU\...\Explorer\RecentDocs` | MRU files | Recently opened documents |
| `HKCU\...\Shell\BagMRU` / `UserAssist` | ShellBags | Folder navigation (USRCLASS.DAT) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\...\ShimCache` | ShimCache | System-wide execution trace |
| `HKLM\SYSTEM\...\Services` | Services | Service persistence, binary paths |
| `HKLM\SAM` | Account hashes | Local account password hashes |
| `HKCU\...\TypedPaths` | Traversal | Paths typed into Explorer dialogs |

---

## 5. Volatility 3 Plugins (Common)

| Plugin | Purpose | When to Use |
|--------|---------|-------------|
| `windows.pslist` | List processes | General process view (uses EPROCESS list) |
| `windows.psscan` | Scan for processes | Detect hidden/unlinked processes |
| `windows.pstree` | Process tree | Parent/child relationship analysis |
| `windows.netscan` | Network connections | Live C2 connections, exfiltration |
| `windows.malfind` | Injected code | Shellcode, process hollowing |
| `windows.dlllist` | Loaded DLLs | Malicious DLL injection |
| `windows.handles` | Kernel handles | Files/devices a process opened |
| `windows.cmdline` | Command lines | What each process was invoked with |
| `windows.envars` | Environment | Evidence of configuration changes |
| `windows.hashdump` | Password hashes | Extract SAM/SYSTEM hashes |
| `windows.dumpfiles` | Extract files | Pull files/executables from memory |
| `windows.vadinfo` / `vadwalk` | Virtual memory regions | Region protections, injection detection |
| `windows.cachedump` | Cached credentials | Stored domain credentials |
| `windows.registry.printkey` / `hivelist` | Registry from memory | Live registry state, Run keys |

---

## 6. Network Forensics Quick Reference

| Task | Command / Tool | Notes |
|------|---------------|-------|
| Read PCAP | `tshark -r file.pcap` | Base read |
| HTTP requests | `tshark -r file.pcap -Y "http.request" -T fields -e http.host` | Hosts, URIs |
| DNS queries | `tshark -r file.pcap -Y "dns" -T fields -e dns.qry.name` | Query analysis |
| IP conversations | `tshark -r file.pcap -q -z conv,tcp` | Top talkers |
| Extract files | `tshark -r file.pcap --export-objects http,outdir/` | Payload extraction |
| Beaconing | `rita analyze-captured pcap; rita show-beacons` | C2 beacon detection |
| TLS fingerprint | JA3/JA3S hash via Suricata/CAPESandbox | Client identification |
| Stream reassembly | Wireshark "Follow TCP Stream" | Payload reading |

### Network Anomaly Indicators

| Indicator | Possible Meaning |
|-----------|------------------|
| Periodic same-size connections | Beacons (C2) |
| Long random DNS labels | DNS tunneling / exfil |
| Rapid high-volume DNS | DGA / fast flux |
| Newly registered domains | Campaign infrastructure |
| High ports + known-bad JA3 | Malicious TLS client |
| Large outbound transfers at night | Data exfiltration |

---

## 7. Mobile Forensics Quick Reference

| Platform | Key Artifact | Location | Evidence |
|----------|--------------|----------|----------|
| **Android** | SMS/MMS | `/data/data/com.android.providers.telephony/databases/mmssms.db` | SMS content, numbers, dates |
| **Android** | Call log | `/data/data/com.android.providers.contacts/databases/calllog.db` | Calls, durations |
| **Android** | Installed apps | `/data/system/packages.xml` | App list, installer source |
| **Android** | Web history | Chrome `/data/data/com.android.chrome/app_chrome/Default/History` | Browsing, downloads |
| **Android** | Wifi | `/data/misc/wifi/WifiConfigStore.xml` | Networks, passwords, last use |
| **iOS** | SMS/iMessage | `var/mobile/Library/SMS/sms.db` | Messages incl. deleted |
| **iOS** | Call history | `var/wireless/Library/CallHistory/call_history.db` | Calls |
| **iOS** | Keychain | `var/mobile/Library/Keychains/keychain-2.db` | Credentials, tokens |
| **iOS** | System log | `var/mobile/Library/Logs/CrashReporter/DiagnosticLogs` + `Consolidated.db` | System/user behavior |

---

## 8. Cloud Forensics Quick Reference

| Cloud | Log Source | Critical Events |
|-------|-----------|-----------------|
| **AWS** | CloudTrail | `ConsoleLogin`, `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `PutBucketPolicy`, `DeleteBucket`, `GetObject` |
| **AWS** | VPC Flow Logs | Traffic volumes, exfiltration paths |
| **Azure** | Activity Log / Sign-in Logs | Sign-in anomalies, role assignments, Resource Manager operations |
| **GCP** | Cloud Audit Logs | Admin activity, data access, policy changes |

---

## 9. Email Forensics Quick Reference

| Check | Header Field | What It Proves |
|-------|--------------|----------------|
| **SPF** | `Received-SPF` | Authorized sending IP |
| **DKIM** | `DKIM-Signature` | Message authenticity / signing domain |
| **DMARC** | `Authentication-Results` | SPF+DKIM alignment policy |
| **Route** | `Received` chain | Actual mail path (hop-by-hop) |
| **Spoof check** | From vs Reply-To vs Envelope-From | Display-name spoofing |
| **Origin** | `X-Originating-IP` (Exchange) | Sender's real IP |
| **X-Headers** | `X-Mailer`, `X-Originating` | Sending client identity |

---

## 10. DFIR Phases (NIST SP 800-86)

| Phase | Goal | Key Output |
|-------|------|-----------|
| **Collection** | Acquire evidence (volatile → persistent) | Hash-verified images |
| **Examination** | Extract artifacts without alteration | Parsed artifact sets |
| **Analysis** | Correlate artifacts to reconstruct events | Incident timeline, root cause |
| **Reporting** | Document findings and recommendations | Forensic report, IOCs |

---

## 11. Common Ransomware & C2 IOCs to Hunt

| IOC Type | Example |
|----------|---------|
| SHA-256 hash | `a1b2c3d4...` (binary hash) |
| IP | `185.141.27.99` (C2) |
| Domain | `update-service.evil.com` |
| JA3 | `a0e9f5d64349fb13191bc781f81f42e1` |
| Mutex | `Global\LockBot_Mutex_v3` |
| File extension | `.locked`, `.encrypted` |
| Ransom note | `README-DECRYPT.txt` |
| Registry Run key | `...\Run\WindowsUpdate` |

---

## 12. Quick Tool Lookup

| Need | Tool |
|------|------|
| Disk imaging | FTK Imager, Guymager, dcldd, X-Ways |
| Memory analysis | Volatility 3, Rekall, Redline |
| Memory acquisition | LiME, WinPmem, DumpIt |
| Windows artifacts | Eric Zimmerman Tools (MFTECmd, PECmd, EvtxECmd) |
| Registry | Registry Explorer, RegRipper |
| Network | Wireshark, tshark, Zeek, RITA, Suricata |
| Mobile | Cellebrite, ALEAPP, iLEAPP, ADB, libimobiledevice |
| Malware / reversing | Ghidra, YARA, CAPE, Floss, Detect It Easy |
| Timeline | Plaso/log2timeline, Timesketch, AllinOneForensics |
| Live IR | Velociraptor, KAPE, osquery, Sysinternals |
| All-in-one | **AllinOneForensics** (this project) |