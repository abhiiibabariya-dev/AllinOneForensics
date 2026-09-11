# Memory Forensics

## Overview

Memory forensics (volatile data analysis) involves the acquisition and analysis of RAM contents from running systems. Memory contains ephemeral data that is lost when the system powers off, making it one of the most valuable sources of evidence in modern investigations.

---

## Why Memory Forensics Is Critical

Modern attacks increasingly operate entirely in memory:
- **Fileless malware** resides only in RAM, leaving minimal disk artifacts
- **Encrypted communications** have decryption keys in memory only while active
- **Running processes** reveal command-line arguments, loaded DLLs, and network handles
- **Encryption keys** for VeraCrypt, BitLocker, or BitLocker keys may be in RAM
- **Password tokens**, Kerberos tickets, and NTLM hashes exist in memory
- **Active network connections** reveal C2 channels and lateral movement

---

## Memory Acquisition Methods

### Live Acquisition (System Running)

| Method | Platform | Tool | Notes |
|--------|----------|------|-------|
| **Kernel module** | Linux | LiME | Loadable kernel module, reliable |
| **Physical memory access** | Windows | WinPmem, DumpIt | Direct physical memory read |
| **API-based** | Windows | FTK Imager Lite | Uses Windows API |
| **Hypervisor** | VMs | VMware snapshot | Captures entire VM state |
| **Firewire** | Legacy | Inception/DMA | IEEE 1394 DMA attack (requires physical access) |

### Dead Acquisition (System Off)

| Method | Description | Notes |
|--------|-------------|-------|
| **Hibernation file** | Decompress `hiberfil.sys` | Windows hibernation dump |
| **Crash dump** | Analyze `MEMORY.DMP` or minidump | Created by BSOD |
| **Page file** | Parse `pagefile.sys` | Partial memory, may have sensitive data |
| **VM snapshot** | Snapshot from hypervisor | Complete VM state |

### Acquisition Best Practices
1. **Use trusted tools** from external media (never install on suspect system)
2. **Acquire RAM first** (most volatile data)
3. **Document the system state** (running processes, time, network connections)
4. **Minimize tool footprint** — use tools with small memory footprint
5. **Write to external media** — never write to the suspect disk
6. **Record the acquisition time** with hash verification

### Investigation Scenario: RAM Acquisition on Live System
**Scenario:** SOC detects suspicious activity on a server. Before shutting down:
```bash
# 1. Record system state
date > /mnt/usb/acquisition_time.txt
uptime >> /mnt/usb/acquisition_time.txt

# 2. Capture running processes
ps auxf > /mnt/usb/processes.txt

# 3. Capture network connections
netstat -tulnp > /mnt/usb/netstat.txt

# 4. Dump RAM using LiME
sudo insmod lime.ko "path=/mnt/usb/memory.lime format=lime"

# 5. Verify integrity
sha256sum /mnt/usb/memory.lime > /mnt/usb/memory.lime.sha256
```

---

## Volatility Framework

### WHAT It Is
Volatility is the industry-standard open-source framework for memory forensics. Volatility 3 (current) supports Windows, Linux, and macOS memory images.

### Key Volatility 3 Plugins

| Plugin | What It Does | Forensic Value |
|--------|-------------|---------------|
| **windows.pslist** | Lists running processes | Identify running programs |
| **windows.pstree** | Process tree (parent-child) | Detect anomalous process hierarchies |
| **windows.netscan** | Network connections | Find active C2 connections |
| **windows.filescan** | Open file handles | Identify accessed files |
| **windows.handles** | Object handles | Track resource access |
| **windows.dlllist** | Loaded DLLs per process | Detect DLL injection |
| **windows.cmdline** | Command-line arguments | Reveal PowerShell commands, scripts |
| **windows.envars** | Environment variables | Capture PATH, secrets |
| **windows.registry.hivelist** | Loaded registry hives | Analyze registry in memory |
| **windows.registry.printkey** | Registry key values | Read Run keys, services |
| **windows.malfind** | Detect injected code | Find process hollowing, shellcode |
| **windows.svcscan** | Service entries | Find hidden/malicious services |
| **windows.dumpfiles** | Dump file contents | Extract executables from memory |
| **windows.vadinfo** | Virtual Address Descriptor | Detect suspicious memory regions |
| **windows.memmap** | Memory map of processes | Locate specific memory regions |
| **windows.hashdump** | Extract password hashes | Credential extraction |
| **windows.cachedump** | Extract cached domain hashes | Offline domain credentials |
| **linux.pslist** | Linux process list | Identify running processes |
| **linux.bash** | Bash command history | User activity |
| **linux.check_syscall** | Syscall table hooks | Detect rootkits |
| **linux.check_modules** | Kernel module integrity | Detect rootkit modules |
| **macos.pslist** | macOS process list | Identify running processes |
| **macos.bash** | macOS bash history | User activity |

### Using Volatility 3

```bash
# List running processes
vol3 -f memory.raw windows.pslist

# Process tree (parent-child relationships)
vol3 -f memory.raw windows.pstree

# Network connections
vol3 -f memory.raw windows.netscan

# Detect injected code
vol3 -f memory.raw windows.malfind

# Extract password hashes
vol3 -f memory.raw windows.hashdump

# Command-line arguments
vol3 -f memory.raw windows.cmdline

# Dump a specific process
vol3 -f memory.raw windows.dumpfiles --pid 1234

# Linux process list
vol3 -f linux_mem.lime linux.pslist

# Detect syscall hooks (rootkit)
vol3 -f linux_mem.lime linux.check_syscall
```

### Investigation Scenario: Process Injection Detection
**Scenario:** Malware injects code into `svchost.exe` to hide its presence.

**Volatility evidence:**
```
$ vol3 -f memory.raw windows.malfind
PID: 3840  Process: svchost.exe
VAD: 0x1c50000  Protection: PAGE_EXECUTE_READWRITE
Hexdump:
  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00  MZ..............
  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ........@.......

$ vol3 -f memory.raw windows.netscan | grep 3840
Offset: 0x1c5a2e0  Local: 10.0.0.5:49832  Remote: 185.141.27.99:443
```
**Analysis:** `malfind` detects executable code in a VAD region marked `PAGE_EXECUTE_READWRITE` — classic process injection. `netscan` shows the injected process is communicating with a known C2 IP.

---

## What Memory Reveals

### Process Analysis

| Artifact | What It Shows | Investigation Value |
|----------|--------------|-------------------|
| **Process list** | Running programs | Identify malicious processes |
| **Process tree** | Parent-child relationships | Detect process hollowing |
| **Command-line args** | How programs were launched | Reveal PowerShell attacks |
| **DLLs loaded** | Libraries in use | Detect injection, hooking |
| **Handles** | Open files, registry keys, mutexes | Track resource access |
| **Environment vars** | PATH, secrets, config | Capture credentials, config |

### Network Artifacts

| Artifact | What It Shows | Investigation Value |
|----------|--------------|-------------------|
| **Active connections** | Established TCP/UDP connections | Find C2 channels |
| **Listening sockets** | Open ports | Identify backdoors |
| **DNS cache** | Recently resolved domains | Reveal DNS-based C2 |
| **Socket owners** | Process owning each connection | Attribute connections to malware |

### Credential Extraction

| Artifact | What It Shows | Investigation Value |
|----------|--------------|-------------------|
| **LSASS process** | Windows authentication data | Password hashes, Kerberos tickets |
| **NTLM hashes** | Cached credential hashes | Pass-the-hash attacks |
| **Kerberos tickets** | TGTs and service tickets | Golden/Silver ticket detection |
| **Cleartext passwords** | Unencrypted credentials | Browser/app passwords |
| **LSA Secrets** | Service account passwords | Scheduled task credentials |

### Malware Indicators

| Artifact | What It Shows | Investigation Value |
|----------|--------------|-------------------|
| **Injected code** | Code in unexpected memory regions | Process injection attacks |
| **Unlinked processes** | Hidden from task manager | Process hiding/rootkit |
| **Modified DLLs** | Altered system DLLs | API hooking, rootkit |
| **Hidden processes** | Not visible in normal enumeration | Kernel-level rootkit |
| **Malicious services** | Suspicious service entries | Persistence mechanism |

---

## Memory Forensics Techniques

### 1. Process Hollowing Detection
**WHAT:** Malware creates a legitimate process (e.g., `svchost.exe`) in suspended state, replaces its memory with malicious code, then resumes it.

**HOW to detect:**
```bash
# Compare pslist with psscan (psscan finds unlinked processes)
vol3 -f mem.raw windows.pslist
vol3 -f mem.raw windows.psscan

# Check for executable pages in non-executable processes
vol3 -f mem.raw windows.vadinfo --pid <PID>

# Look for PE headers in unexpected memory regions
vol3 -f mem.raw windows.malfind --pid <PID>
```

### 2. DLL Injection Detection
**WHAT:** Malware injects a malicious DLL into a legitimate process to evade detection.

**HOW to detect:**
```bash
# List loaded modules per process
vol3 -f mem.raw windows.dlllist --pid <PID>

# Check for mapped PE files
vol3 -f mem.raw windows.vadinfo --pid <PID>

# Compare with known good DLL lists
vol3 -f mem.raw windows.dlllist | grep -v "System32"
```

### 3. Rootkit Detection
**WHAT:** Kernel-level rootkits modify system structures to hide their presence.

**HOW to detect:**
```bash
# Linux: Check syscall table for hooks
vol3 -f linux_mem.lime linux.check_syscall

# Linux: Check kernel modules against /proc/modules
vol3 -f linux_mem.lime linux.check_modules

# Windows: Compare pslist vs psscan
vol3 -f mem.raw windows.pslist > pslist.txt
vol3 -f mem.raw windows.psscan > psscan.txt
diff pslist.txt psscan.txt  # Differences indicate hidden processes
```

### 4. Encryption Key Recovery
**WHAT:** Encryption keys for BitLocker, VeraCrypt, or full-disk encryption may be resident in memory.

**HOW to extract:**
```bash
# Extract BitLocker FVEK (Full Volume Encryption Key)
vol3 -f mem.raw windows.bitlocker  # (custom plugin needed)

# Look for encryption-related processes
vol3 -f mem.raw windows.pslist | grep -i "veracrypt\|bitlocker\|crypt"

# Extract keys from LSASS memory
vol3 -f mem.raw windows.hashdump
```

---

## Memory Analysis Workflow

```
1. ACQUIRE    → Dump RAM (LiME/WinPmem/DumpIt)
2. VERIFY     → SHA-256 hash of memory dump
3. IDENTIFY   → Determine OS version, profile
4. PROCESSES  → List processes (pslist, pstree)
5. NETWORK    → Scan connections (netscan)
6. MALWARE    → Detect injection (malfind, vadinfo)
7. CREDENTIALS → Extract hashes (hashdump, cachedump)
8. FILES      → Extract relevant executables (dumpfiles)
9. TIMELINE   → Build memory timeline
10. REPORT    → Document findings with volatility output
```

---

## Memory Forensics Quick Reference

| Question | Plugin/Technique |
|----------|-----------------|
| What processes are running? | `windows.pslist` |
| What is the process hierarchy? | `windows.pstree` |
| What network connections exist? | `windows.netscan` |
| Is there process injection? | `windows.malfind` |
| What DLLs are loaded? | `windows.dlllist` |
| What command lines were used? | `windows.cmdline` |
| What registry hives are loaded? | `windows.registry.hivelist` |
| Are there hidden processes? | Compare `pslist` vs `psscan` |
| Are there rootkit hooks? | `linux.check_syscall` |
| What files are open? | `windows.filescan` |
| What are the environment variables? | `windows.envars` |
| Extract password hashes | `windows.hashdump` |
| Extract a specific process | `windows.dumpfiles --pid N` |
