# Computer Forensics Fundamentals

## What Is Computer Forensics?

Computer forensics (digital forensics) is the application of investigation and analysis techniques to collect and preserve digital evidence from computing devices in a manner suitable for legal proceedings. It encompasses the recovery, analysis, and presentation of data stored on computers, servers, mobile devices, and storage media.

**Core Goal:** Identify, preserve, extract, and document digital evidence while maintaining its integrity and admissibility in court.

---

## Core Principles

### 1. Chain of Custody
Every piece of evidence must be tracked from collection through analysis to presentation.

| Stage | Action | Documentation Required |
|-------|--------|----------------------|
| Collection | Image/copy the evidence | Hash (SHA-256), timestamp, collector name |
| Transport | Move evidence securely | Sealed bag, transport log |
| Storage | Store in evidence locker | Access log, environmental conditions |
| Analysis | Work on forensic copies | Original hash verified, analyst notes |
| Presentation | Court/proceedings | Hash match verification, methodology |

**HOW an investigator applies it:** Before touching any evidence, record who collected it, when, where, and compute a cryptographic hash. Every subsequent access is logged.

**WHY it matters:** Without documented chain of custody, evidence can be challenged and excluded in court proceedings.

---

### 2. Order of Volatility

Data must be collected from most volatile to least volatile to prevent evidence loss.

| Priority | Source | Typical Volatility | Acquisition Window |
|----------|--------|-------------------|-------------------|
| 1 | CPU registers, cache | Nanoseconds | Impossible (power-off only) |
| 2 | Routing/ARP cache, process table | Seconds-minutes | Capture immediately |
| 3 | RAM (memory) | Minutes-hours | Before power-off |
| 4 | Temporary file systems (swap, /tmp) | Hours-days | After RAM |
| 5 | Disk (MFT, journal, hibernation) | Days-weeks | Standard imaging |
| 6 | Remote logging, IDS alerts | Weeks-months | Collect from remote |
| 7 | Archival media, backups | Months-years | Last priority |

**Investigation Scenario:** During live response on a compromised server, the analyst first dumps RAM (capturing encryption keys, running processes, network connections), then captures the ARP cache and running process list, then images the disk. If the order is reversed, RAM contents are lost forever when the machine is powered down.

---

### 3. Forensic Soundness

All analysis must be performed on forensic copies, never the original evidence.

**WHAT it means:** The original media is write-blocked or imaged with bit-for-bit accuracy. All analysis happens on the copy.

**WHERE it applies:** Every forensic workstation uses hardware or software write-blockers during acquisition.

**HOW an investigator ensures it:**
1. Connect evidence via hardware write-blocker (Tableau, WiebeTech)
2. Create forensic image (E01, dd/raw format)
3. Verify image hash matches source
4. All analysis performed on the image copy
5. Original evidence sealed and stored

---

### 4. Examination Methodology

Follow a repeatable, documented process:

```
Identification -> Collection -> Examination -> Analysis -> Reporting
```

| Phase | Activities | Tools Used |
|-------|-----------|------------|
| **Identification** | Locate potential evidence sources | FTK Imager, OSINT |
| **Collection** | Acquire forensic images | dd, FTK Imager, Cellebrite |
| **Examination** | Extract data from images | Autopsy, X-Ways, Volatility |
| **Analysis** | Correlate findings, build timeline | Plaso, Timesketch, custom scripts |
| **Reporting** | Document findings for stakeholders | AllinOneForensics, report templates |

---

## Live vs. Dead Forensics

### Live Forensics (Volatile Data Collection)

**WHAT it is:** Collecting data from a running system before shutting it down.

**WHERE it is performed:** On the original system while it remains powered on and operational.

**WHAT evidence it captures:**
- Running processes and their arguments
- Network connections (established, listening)
- Logged-in users and sessions
- RAM contents (encryption keys, passwords, decrypted data)
- Mounted filesystems and network shares
- Loaded kernel modules/drivers
- Registry cache (Windows)
- ARP/路由 cache

**WHY it matters:** Many modern attack artifacts exist only in memory. Fileless malware, encrypted connections, and active C2 channels disappear when the system is powered off.

**HOW an investigator performs it:**
1. Document system state (screen photo, time synchronization)
2. Run trusted tools from external media (never install on suspect system)
3. Capture RAM dump first (most volatile)
4. Run collection scripts for process, network, and user data
5. Compute hashes of all collected artifacts
6. Document everything with timestamps

**Investigation Scenario:** A SOC analyst detects suspicious network traffic from a workstation. Live forensics reveals a PowerShell process downloading and executing a fileless payload entirely in memory — evidence that would be completely lost with dead forensic imaging.

```
# Live acquisition commands (Linux trusted media)
sudo dd if=/dev/mem of=/mnt/usb/memdump.raw bs=1M
sudo ps auxf > /mnt/usb/processes.txt
sudo netstat -tulnp > /mnt/usb/network_connections.txt
sudo lsof > /mnt/usb/open_files.txt
```

### Dead Forensics (Offline Analysis)

**WHAT it is:** Analyzing a forensic image of powered-off media.

**WHERE it is performed:** On a forensic workstation using a copy of the evidence.

**WHAT evidence it captures:**
- File system contents (MFT, inodes, journal)
- Deleted files (carved from unallocated space)
- Registry hives (Windows)
- Event logs (EVTX)
- Browser history, cookies, cache
- Prefetch, Amcache, ShimCache
- Slack space and metadata

**WHY it matters:** Dead forensics allows exhaustive, non-destructive analysis. The entire filesystem can be searched, carved, and reconstructed without risk of altering evidence.

**HOW an investigator performs it:**
1. Verify forensic image integrity (hash comparison)
2. Mount image in read-only mode
3. Run automated parsers (Autopsy, AllinOneForensics)
4. Manual examination of flagged artifacts
5. Timeline reconstruction
6. Documentation and reporting

**Investigation Scenario:** After a ransomware incident, the encrypted workstation is imaged (dead forensics). Analysis of the MFT reveals the ransomware binary was downloaded from a phishing email, executed from the Downloads folder, and the Registry Run key confirms persistence was established before encryption began.

### Comparison Table

| Aspect | Live Forensics | Dead Forensics |
|--------|---------------|----------------|
| System state | Running, volatile data available | Powered off, static snapshot |
| Risk to evidence | Higher (system may change) | Lower (image is immutable) |
| Volatile data | Captured | Lost |
| Analysis depth | Limited (time-constrained) | Exhaustive |
| Court admissibility | High if properly documented | High if image verified |
| When to use | Active incident, data at risk of destruction | Post-incident, formal investigation |

---

## File System Fundamentals

### Windows NTFS

| Structure | What It Is | Location | Forensic Value |
|-----------|-----------|----------|---------------|
| **MFT** (Master File Table) | Database of every file/directory | `$MFT` at volume root | File metadata, deleted files, timestamps |
| **$LogFile** | Transaction journal | Volume root | File system changes, timestamps |
| **$UsnJrnl** | Change journal | Volume root | File creation/modification/delete events |
| **$I30** | Index entries | Inside directories | Directory listings, deleted entries |
| **$Secure** | Access control list | Volume root | File permissions |
| **$BadClus** | Bad cluster map | Volume root | Hidden data in bad sectors |

### Linux ext4

| Structure | What It Is | Location | Forensic Value |
|-----------|-----------|----------|---------------|
| **Inode table** | File metadata | Group descriptors | Timestamps, permissions, extents |
| **Journal (ext4-jbd2)** | Transaction log | `.journal` or inline | File system changes |
| **Directory entries** | File name mappings | Directory inodes | File names, deletion status |
| **Superblock** | Filesystem metadata | Block group 0 (backup at 1, 31, etc.) | FS size, block count, mount history |

### macOS APFS/HFS+

| Structure | What It Is | Forensic Value |
|-----------|-----------|---------------|
| **APFS container** | Encryption, snapshots | Volume encryption state, snapshots |
| **HFS+ B-tree catalog** | File/folder records | Metadata, deleted files |
| **Extended attributes** | Quarantine, download origin | File provenance (com.apple.quarantine) |

---

## Timestamps in Digital Forensics

Every filesystem records multiple timestamps. Understanding their meaning is critical.

### Windows FILETIME (NTFS)

| Timestamp | What It Records | When It Changes |
|-----------|----------------|----------------|
| **$STANDARD_INFORMATION.Created** | When the file was created on this volume | Rarely (survives copy) |
| **$STANDARD_INFORMATION.Modified** | When file content was last changed | File save/edit |
| **$STANDARD_INFORMATION.Accessed** | When file was last read/opened | Any access |
| **$STANDARD_INFORMATION.MFTChanged** | When MFT record was updated | Metadata changes |
| **$FILE_NAME.Created** | When the filename entry was created | Name change, creation |
| **$FILE_NAME.Modified** | When the filename entry was changed | Any change |
| **$FILE_NAME.Accessed** | When the filename was accessed | Any access |

**Investigation Scenario:** An attacker uses a timestomping tool to change `$STANDARD_INFORMATION.Modified` to 2020. However, `$FILE_NAME` timestamps (stored in a different MFT attribute) still show the real creation time of 2024. Cross-referencing both timestamp sets reveals the deception.

### Linux/Unix Timestamps

| Timestamp | What It Records | Common Attack Use |
|-----------|----------------|-------------------|
| **atime** | Last access time | Rarely useful (often disabled) |
| **mtime** | Last modification time | Timestomping target |
| **ctime** | Last metadata change | Harder to fake (kernel-managed) |
| **btime** (ext4) | Birth/creation time | Most reliable creation time |

---

## Volatile Data Sources

| Data Source | What It Contains | Acquisition Tool | Typical Lifetime |
|------------|-----------------|-----------------|-----------------|
| **RAM** | Processes, keys, passwords, network state | WinPmem, LiME, DumpIt | Until power-off |
| **ARP cache** | IP-MAC mappings | `arp -a` | Minutes |
| **Routing table** | Network paths | `route print` / `ip route` | Until reboot |
| **DNS cache** | Recently resolved domains | `ipconfig /displaydns` | Hours |
| **Clipboard** | Copied text/images | Custom script | Until next copy |
| **Open files** | Active file handles | `lsof` / Handle.exe | Until closed |
| **Running processes** | Active programs, arguments | `ps` / Process Explorer | Until terminated |
| **Network sockets** | Active connections | `netstat -tulnp` | Until closed |

---

## Key Terminology

| Term | Definition |
|------|-----------|
| **Acquisition** | Creating a forensic copy of evidence |
| **Bit-stream image** | Exact binary copy of every sector on media |
| **Write-blocker** | Hardware/software that prevents writes to evidence |
| **Hash** | Cryptographic fingerprint (SHA-256, MD5) for integrity verification |
| **Carving** | Recovering files by scanning raw data for known headers/footers |
| **Slack space** | Unused space between end of file and end of allocated cluster |
| **Unallocated space** | Clusters not assigned to any file (deleted data remains) |
| **Steganography** | Hiding data within other files (images, audio) |
| **Timestomping** | Modifying file timestamps to evade detection |
| **Anti-forensics** | Techniques to hinder or mislead forensic analysis |
| **FOCA** | Fingerprinting Organizations with Collected Archives |
| **Plaintext** | Unencrypted, readable data |
| **Metadata** | Data about data (timestamps, permissions, author info) |
| **IOC** | Indicator of Compromise (hash, IP, domain, URL) |

---

## Legal Considerations

| Requirement | Description |
|-------------|-------------|
| **Authorization** | Written permission to examine specific devices |
| **Scope** | Investigation limited to authorized systems/timeframes |
| **Consent** | Voluntary permission (where applicable) |
| **Warrant** | Court-ordered search (criminal cases) |
| **Proportionality** | Search method proportional to suspected offense |
| **Data protection** | GDPR/CCPA compliance when personal data is involved |
| **Jurisdiction** | Cloud/multi-national evidence may require multiple legal processes |
| **Privilege** | Attorney-client privilege may apply to some evidence |

**HOW an investigator ensures compliance:** Document all legal authority before beginning collection. Maintain detailed logs. Never exceed the scope of authorization. Consult legal counsel when uncertain about jurisdiction or privilege.

---

## References

- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
- SANS DFIR Poster Series
- NIST Computer Forensics Tool Testing (CFTT) Program
- ACPO Good Practice Guide for Digital Evidence
- ISO/IEC 27037: Guidelines for identification, collection, acquisition and preservation of digital evidence
