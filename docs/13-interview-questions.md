# Forensic Interview and Scenario-Based Questions

## Overview

This document contains realistic interview questions and scenario-based exercises for digital forensics and DFIR roles. Each section covers foundational knowledge, artifact-level questions, and practical investigation scenarios designed to test both theoretical understanding and hands-on methodology.

---

## 1. Foundational Forensics Questions

### General Methodology
1. **What is the difference between live forensics and dead forensics? When would you choose each?**
   > Live forensics collects volatile data from a running system (RAM, active network connections, running processes). Dead forensics examines a powered-off system via disk imaging. Choose live when the system must stay online (servers, critical infrastructure, volatile evidence at risk). Choose dead for forensically sound, repeatable analysis of persistent storage.

2. **Explain the Order of Volatility. Why does it matter?**
   > Evidence must be collected from most volatile to least volatile: registers/cache → RAM → swap/pagefile → disk → remote logs → archival backups. Volatile data is lost as soon as the system is powered off, so it must be captured first.

3. **What is chain of custody and why is it critical?**
   > A documented chronological record of who collected, handled, analyzed, and transferred evidence. It proves the evidence was not tampered with, is required for admissibility in court, and includes unique evidence IDs, timestamps, and signatures.

4. **Why do we use write-blockers during acquisition?**
   > Write-blockers prevent any modification to the source media. Forensic soundness requires that the evidence is an exact, unaltered copy — the hash of the copy must match the source.

5. **What is forensic soundness?**
   > The assurance that evidence is authentic, unaltered, and reproducible. It is achieved through write-blocking, hashing (SHA-256), and documented procedures that another examiner could reproduce.

6. **What tools are in your forensic toolkit, and why?**
   > Example: FTK Imager/Guymager (imaging), Volatility 3 (memory), Eric Zimmerman Tools (Windows artifacts), Wireshark/tshark (network), Autopsy (disk analysis), Plaso (timeline), YARA (malware).

### Windows Foundation
7. **What is the MFT and why is it important?**
   > The Master File Table is the NTFS index of every file and folder. Each entry contains two critical timestamps: $STANDARD_INFORMATION (SI, often modified by malware) and $FILE_NAME (FN, harder to forge). Comparing SI vs FN detects timestomping.

8. **Name the Windows Registry hives and what each contains.**
   > SYSTEM (boot config, services, mounted devices), SOFTWARE (installed apps, Run keys), SAM (local accounts/hashes), SECURITY (logon/auth policy), NTUSER.DAT (per-user settings, MRU), USRCLASS.DAT (ShellBags, file associations).

9. **Which Event IDs matter for logon forensics?**
   > 4624 (successful logon), 4625 (failed logon), 4648 (explicit logon), 4672 (admin privileges), 4688 (process creation), 7045 (service installed), 1102 (log cleared), 4104 (PowerShell script block). Combine with Logon Types to understand access method.

10. **What are the Windows Logon Types and what do they reveal?**
    > Type 2 (interactive), Type 3 (network/SMB), Type 4 (batch), Type 5 (service), Type 10 (RDP). A Type 3 from a suspicious IP suggests lateral movement; a Type 10 from an unusual time suggests remote compromise.

11. **Where do you find evidence of connected USB devices?**
    > HKLM\SYSTEM\...\Enum\USBSTOR (device serial, first/last connected, GUID), plus SetupAPI logs, and MountedDevices. Cross-reference with LNK/RECENT files and MFT to prove file transfer.

12. **What is UserAssist and how do you decode it?**
    > Located in NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist. It records program execution counts and last-run times with names ROT-13 encoded. Decodes to reveal hidden GUI program usage.

### Memory Forensics
13. **What information would you lose if you powered off a compromised machine?**
    > Running processes (including injected/unlinked ones), live network connections, executing malware that never touched disk, encryption keys/passwords in memory, command lines, and open file handles.

14. **Name key Volatility 3 plugins and their purpose.**
    > `windows.pslist` (process list), `windows.pstree` (process tree), `windows.netscan` (network connections), `windows.malfind` (injected code), `windows.hashdump` (password hashes), `windows.dumpfiles` (extract files), `windows.psscan` (unlinked processes), `windows.cmdline` (command lines).

15. **How do you detect process injection in memory?**
    > `malfind` flags regions with PAGE_EXECUTE_READWRITE permissions and shellcode signatures. Look for processes with abnormal child/parent relationships or loaded suspicious DLLs via `dlllist`.

---

## 2. Artifact-Specific Scenario Questions

### The Timestomping Question
**Scenario:** An attacker modified files on a Windows system. The defense claims the files were legitimately created on that date.

**Q: How would you determine if timestamps were forged, and which artifacts would you use?**
> Compare MFT $SI vs $FN timestamps — malicious tools often only modify $SI, leaving $FN timestamps revealing the true age. Cross-reference Prefetch, Amcache (records binary hashes and compile time), and Event Log 4688 process-creation times. An attacker cannot easily rewrite Prefetch or $USN journal entries, which will preserve the manipulation activity.

### The "Clean" System Question
**Scenario:** A controller claims a victim machine was "completely wiped" with a fresh OS install after an infection.

**Q: Can you still find evidence of the previous compromise?**
> Yes. MFT $FILE_NAME entries and the $LogFile/$USN journal may survive a quick reinstall if the partition wasn't zeroed. Partition slack and unallocated space retain fragments. The presence of a "fresh install" is itself an action of note — spot-check MFT record numbers on system files: $LogFile stores historical write records whose MFT record numbers won't match a genuine fresh install.

### The Malicious Email Question
**Scenario:** An executive received a phishing email that installed malware.

**Q: Walk me through your acquisition and analysis plan.**
> 1. Preserve the email (full headers + attachment) and isolate the host.
> 2. Capture memory first (order of volatility), then image the disk.
> 3. Parse the header: SPF/DKIM/DMARC alignment, X-Originating-IP, and Reply-to vs From mismatch.
> 4. Hash and static-analyze the attachment (strings, PE imports, YARA).
> 5. Correlate with host artifacts: Prefetch for the payload, Registry Run keys for persistence, Event 4688 for process chain, netscan for C2.
> 6. Build a timeline to firmly place email-open → execution → beaconing.

### The Lateral Movement Question
**Scenario:** One workstation is compromised, and you must find the full scope.

**Q: What artifacts do you prioritize and in what order?**
> 1. Event Log 4624/4648 with Logon Type 3/10 from the infected host's IP → find every system it authenticated to.
> 2. `windows.netscan` from memory dump → show SMB/RDP connections.
> 3. Cache/Prefetch for PsExec/Cobalt Strike/wmic lateral-movement binaries.
> 4. Registry for dropped services or WMI subscriptions (Event 7045).
> 5. DNS logs → identify other compromised hosts beaconing to the same C2 domain.

### The USB Exfiltration Question
**Scenario:** An insider copied files to a USB drive and denied it.

**Q: How do you prove files were transferred to a specific USB device?**
> Correlate USBSTOR serial number, the drive's Volume GUID from MountedDevices, MFT records for source files accessed at connection time, `.lnk`/RecentDocs references on drive letter E:, ShellBags entries for the USB path, and $USN journal around the copy timestamp. Bonus: Amcache and SetupAPI logs date the first insertion.

### The Ransomware Question
**Scenario:** You arrive at a hospital where ransomware encrypts files while the system is still running.

**Q: What is your immediate and forensic sequence?**
> 1. Isolate the host without powering off — this preserves memory encryption keys.
> 2. Capture memory (keys, running process, live C2 connection).
> 3. Image the disk — encrypted files + Prefetch + MFT let you timestamp every encryption event.
> 4. Search for the ransom note and `.evtx` logs cleared (Event 1102) as anti-forensics signature.
> 5. Identify C2 IP from `netscan` and DNS logs; block it; hunt laterally via 4624 logs.

---

## 3. Network and Cloud Scenarios

### The Beacon Question
**Scenario:** A server shows regular 60-second outbound HTTPS connections to a static IP, always the same size, with ~30% timing jitter.

**Q: What does this pattern indicate and how do you confirm?**
> It is the classic Cobalt Strike beacon signature. Confirm with RITA (beacon score >0.8), JA3/JA3S fingerprint matching, TLS SNI/destination overlap, and memory analysis (`netscan`, `malfind`). Check for sleeping, periodic reconnection, and a stable packet-size signature.

### The DNS Tunneling Question
**Scenario:** A host performs thousands of unusual DNS queries with long, random-looking subdomains to a single domain.

**Q: How do you investigate?**
> The random labels are exfiltrated data encoded in DNS queries (classic tunneling). Analyze with passive DNS + PCAP: query entropy, label lengths, query cadence, response sizes. Correlate with the tunnel client on the host (memory/Disk) and reconstruct the exfiltrated data from query labels.

### The Cloud Compromise Question
**Scenario:** An AWS account creates a new IAM user with AdministratorAccess and downloads from a previously-private S3 bucket.

**Q: How do you reconstruct the incident?**
> CloudTrail: `ConsoleLogin` (note MFA status, source IP, access key vs console) → `CreateUser` → `AttachUserPolicy` → `CreateAccessKey` → `PutBucketPolicy`/`GetObject`. Cross-reference VPC Flow Logs for the exfiltration volume. Check for a deleted logging bucket (anti-forensics) and review IAM policy for root cause (overprivileged role, missing MFA).

---

## 4. Interview Evaluation Scenarios (Whiteboard)

### Scenario A: Ordering Your Investigation
You receive one physical disk image, one 8 GB memory dump, one network capture, and one email PST — from a suspected data-breach workstation, 4 hours before a hard deadline.

**What do you do step-by-step?**
1. Start memory first — it has the shortest-lived evidence (running processes, C2 connections, encryption keys).
2. Parse the network capture for the C2 evidence and any exfiltration volumes.
3. Process the disk image artifacts (MFT, Prefetch, Registry, browser) in parallel while memory runs.
4. Use the email PST to establish the initial phishing vector and the timeline's anchor.
5. Merge everything into a Plaso super-timeline and correlate.

### Scenario B: Hashes Don't Match
During acquisition, the disk image SHA-256 doesn't match the source media signature you recorded.

**What do you do?**
> Stop and document immediately. The image is not forensically sound — do not analyze it as evidence. Document the discrepancy, verify the write-blocker, re-image, and re-hash. Determine whether the source changed (was it mounted read-write?) or the original signature was captured incorrectly. Provide the original artifacts and all documentation to the requester; do not silently continue.

### Scenario C: The Missing Logs
Windows Security logs were cleared (Event 1102) on your key host.

**Can the investigation proceed, and how?**
> Yes. Event 1102 itself is evidence of intent (anti-forensics). The $LogFile, Prefetch, Amcache, ShimCache, MFT, and .evtx files in unallocated space survive log clearing. Correlate with domain controllers' 4624 logs (they log the logon independently), EDR telemetry, and network captures to rebuild the timeline without the local logs.

---

## 5. Quick-Answer Rapid-Fire Section

1. **Question:** What file does the volatile evidence get stored in to survive reboot? **Answer:** hiberfil.sys (plus pagefile.sys for paged memory).
2. **Question:** Where does Windows store last-executed programs per user? **Answer:** UserAssist (ROT-13 encoded) and recent-apps in NTUSER.DAT.
3. **Question:** What artifact records program execution independently of the filesystem MFT? **Answer:** Prefetch (.pf) in C:\Windows\Prefetch.
4. **Question:** What does a `malfind` hit in Volatility indicate? **Answer:** Suspicious executable memory region — likely injected code / shellcode.
5. **Question:** Which Event ID proves a process was created and what fields matter? **Answer:** 4688 — NewProcessName, ParentProcessName, and the token integrity (for privilege escalation).
6. **Question:** What two MFT timestamp fields do you compare to catch timestomping? **Answer:** $STANDARD_INFORMATION vs $FILE_NAME.
7. **Question:** What is the difference between a domain (DNS) tunnel and a DGA? **Answer:** Tunneling = data carried in query labels to a fixed domain; DGA = algorithmically generated domains for C2 resilience.
8. **Question:** Which cloud log proves data was removed from a bucket? **Answer:** CloudTrail `DeleteObject` / `GetObject` events with the caller identity and source IP.
9. **Question:** What is a JA3 hash? **Answer:** An MD5 of the client's TLS hello fields — a fingerprint of the client software, used to identify C2 tools.
10. **Question:** Why image with write-blocking plus SHA-256? **Answer:** To guarantee the copy is bit-for-bit identical and provably unmodified — forensic soundness and admissibility.

---

## 6. Evaluation Rubric (What Interviewers Look For)

| Skill | Strong Signal | Weak Signal |
|-------|---------------|-------------|
| **Order of Volatility** | Names RAM first, justifies why | Images disk first, powers down |
| **Timestomping** | Knows SI vs FN comparison | Relies on a single timestamp |
| **Lateral movement** | Logon Type analysis + netscan + services | Only checks one host |
| **Anti-forensics** | Treats log-clearing as evidence, rebuilds via domain logs | Assumes investigation is dead |
| **Soundness** | Re-images when hash mismatches | Analyzes unsound image anyway |
| **Correlation** | Builds a cross-artifact timeline | Analyzes each artifact in isolation |