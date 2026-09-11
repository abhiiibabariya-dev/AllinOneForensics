# Realistic Forensic Case Studies

## Overview

This document presents realistic digital forensics case studies that demonstrate the application of forensic techniques, tools, and investigation methodology. Each case includes the scenario, evidence, analysis, and findings.

---

## Case Study 1: Ransomware Incident

### Scenario
A hospital's IT department reports that multiple workstations have been encrypted by ransomware. The attack began at 09:15 AM on September 1, 2024. One workstation (WS-001) is still operational and may be the patient zero.

### Evidence Collected
1. Memory dump from WS-001 (LiME, 8GB)
2. Disk image from WS-001 (E01 format)
3. Network traffic capture from the segment (PCAP, 2GB)
4. Email server logs (EVTX, 500MB)
5. Firewall logs (CSV, 100MB)

### Analysis

**Memory Analysis (Volatility 3):**
```
$ vol3 -f ws001.raw windows.pslist
PID  Process
---- -------
  4 System
 384 svchost.exe
 1245 svchost.exe  (parent: services.exe)
 3840 svchost.exe  (parent: services.exe)
 4521 cmd.exe      (parent: winlogon.exe) ← SUSPICIOUS
 4533 updater.exe  (parent: cmd.exe) ← SUSPICIOUS

$ vol3 -f ws001.raw windows.netscan | grep 4533
Offset  LocalAddr    RemoteAddr    RemotePort
0x...   10.0.0.5:49832  185.141.27.99:443  ESTABLISHED
```

**Disk Analysis (AllinOneForensics):**
```
$ aiof parse IR-2024-091 --module windows

Prefetch: UPDATER.EXE-AABBCCDD.pf
  Run count: 3
  Last run: 2024-09-01 09:15:12
  
Registry Run Key: HKCU\...\Run\WindowsUpdate
  Value: "C:\Users\doctor\AppData\Roaming\updater.exe"
  
Amcache: SHA-1 match → Known LockBit 3.0 variant

Browser History: 
  09:14:32 - https://hospital-portal.phishing.com/login
  09:14:55 - Downloaded "staff_directory.pdf.exe"
```

**Network Analysis:**
```
DNS Queries:
  09:15:08 - update-service.evil.com → 185.141.27.99
  
HTTPS Connections:
  09:15:08 - 10.0.0.5:49832 → 185.141.27.99:443
    JA3: a0e9f5d64349fb13191bc781f81f42e1 (Cobalt Strike)
  
  09:15:15 - 10.0.0.5:49833 → 10.0.0.12:445 (SMB lateral movement)
  09:15:20 - 10.0.0.5:49834 → 10.0.0.15:445 (SMB lateral movement)
```

### Findings
1. **Root Cause:** Phishing email with malicious attachment opened by user
2. **Malware:** LockBit 3.0 ransomware variant
3. **Lateral Movement:** SMB to 2 additional hosts before encryption
4. **C2:** 185.141.27.99 (Cobalt Strike beacon)
5. **Persistence:** Registry Run key (survives reboot)
6. **Data Loss:** 15 workstations encrypted, 3 servers affected

### IOCs
```
SHA-256: a1b2c3d4e5f6... (ransomware binary)
IP: 185.141.27.99 (C2 server)
Domain: update-service.evil.com (C2 domain)
Mutex: Global\LockBot_Mutex_v3
JA3: a0e9f5d64349fb13191bc781f81f42e1
```

---

## Case Study 2: Insider Data Exfiltration

### Scenario
A company suspects an employee (John Smith, IT Administrator) is stealing intellectual property. The employee submitted his resignation two weeks ago and has been accessing unusual files.

### Evidence Collected
1. Full disk image from employee's workstation (E01)
2. Email server logs (EVTX)
3. DLP alerts (CSV)
4. USB device history (from Registry)

### Analysis

**USB Device History (Registry - USBSTOR):**
```
HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Enum
  Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\04055D21600C1A81
    First connected: 2024-08-15 09:30:00
    Last connected: 2024-09-01 16:45:00
    
  Disk&Ven_WD&Prod_MyPassport&Rev_1.04\575836314134344D303536
    First connected: 2024-08-20 14:20:00
    Last connected: 2024-09-01 17:30:00
```

**LNK File Analysis:**
```
E:\PROJECT_ALPHA\design_specifications.docx.lnk
  Target: E:\PROJECT_ALPHA\design_specifications.docx
  Volume: E:\ (SanDisk Ultra)
  Last accessed: 2024-08-28 15:20:00
  
E:\BACKUP\source_code.zip.lnk
  Target: E:\BACKUP\source_code.zip
  Volume: E:\ (WD MyPassport)
  Last accessed: 2024-09-01 16:50:00
```

**ShellBags Analysis:**
```
HKCU\Software\Microsoft\Windows\Shell\BagMRU
  E:\TOP_SECRET\Project_Alpha\
  E:\TOP_SECRET\Project_Beta\
  E:\BACKUP\source_code\
  Last accessed: 2024-09-01 17:25:00
```

**Email Analysis:**
```
From: john.smith@company.com
To: personal_email@protonmail.com
Subject: Backup files
Attachment: source_code_backup.zip (45MB)
Date: 2024-09-01 17:35:00
```

### Findings
1. **Data Staging:** Employee staged IP on external drives (SanDisk, WD)
2. **File Access:** Accessed top-secret project files from USB drives
3. **Exfiltration:** Sent 45MB zip to personal Protonmail account
4. **Timeline:** 3-week exfiltration period before resignation
5. **Device History:** 2 unauthorized USB devices connected

---

## Case Study 3: APT Investigation

### Scenario
A financial institution detects beaconing from a critical server (DB-PROD-01). The beacon has been active for 3 months.

### Evidence Collected
1. 90 days of firewall logs
2. 30 days of DNS logs
3. Memory dump from DB-PROD-01
4. Disk image from DB-PROD-01
5. SIEM alerts

### Analysis

**Beaconing Detection (RITA):**
```
Beacon Analysis:
  Source: 10.0.0.100 (DB-PROD-01)
  Destination: 185.141.27.99:443
  Interval: 60 seconds (±30% jitter)
  Duration: 92 days
  Score: 0.95 (high confidence beacon)
```

**JA3 Fingerprinting:**
```
JA3 Hash: 72a589da586844d7f0818ce684948eea
  Matches: Cobalt Strike 4.x
  JA3S: ae4edc6faf64d08308082ad26be60767
```

**Lateral Movement Timeline:**
```
Day 1 (June 1): Initial access via phishing
  - Email with malicious Excel macro
  - PowerShell executed → downloaded Cobalt Strike beacon
  
Day 2 (June 2): Reconnaissance
  - ARP scan of 10.0.0.0/24
  - LDAP enumeration of domain
  - Bloodhound collection
  
Day 30 (June 30): Privilege escalation
  - Kerberoasting attack
  - Cracked service account hash
  - Domain admin compromise
  
Day 45 (July 15): Database access
  - Lateral movement to DB-PROD-01
  - Installed persistent beacon
  - Began data exfiltration
  
Day 92 (Sept 1): Detection
  - Anomalous beaconing detected by RITA
  - Investigation initiated
```

### Findings
1. **Initial Access:** Phishing email with macro
2. **Dwell Time:** 92 days before detection
3. **Persistence:** Cobalt Strike beacon with 60-second interval
4. **Lateral Movement:** From workstation → domain controller → database server
5. **Data Exfiltration:** Database records exfiltrated via HTTPS
6. **Scope:** 15 systems compromised, 2 service accounts abused

---

## Case Study 4: Cloud Account Compromise

### Scenario
An AWS account shows suspicious activity: multiple IAM users created, S3 buckets made public, and unusual API calls.

### Evidence Collected
1. CloudTrail logs (90 days)
2. VPC flow logs (30 days)
3. IAM policy documents
4. S3 access logs

### Analysis

**CloudTrail Analysis:**
```
Timeline:
  14:22:00 - ConsoleLogin (source: 185.141.27.99, MFA: No)
  14:23:00 - CreateUser (backdoor-admin)
  14:24:00 - AttachUserPolicy (AdministratorAccess to backdoor-admin)
  14:25:00 - CreateAccessKey (for backdoor-admin)
  14:26:00 - PutBucketPolicy (made bucket "sensitive-data" public)
  14:27:00 - GetObject (downloaded 500 objects from sensitive-data bucket)
  14:28:00 - DeleteBucket (deleted logging bucket)
```

**VPC Flow Logs:**
```
14:22:00 - 185.141.27.99 → 10.0.1.50:443 (EC2 console)
14:25:00 - 185.141.27.99 → 10.0.1.50:443 (S3 API)
14:27:00 - 10.0.1.50 → 185.141.27.99:443 (data exfiltration: 2.3GB)
```

### Findings
1. **Initial Access:** Compromised user credentials (no MFA)
2. **Privilege Escalation:** Created new admin user
3. **Persistence:** Access key for backdoor-admin
4. **Data Exfiltration:** 2.3GB downloaded from public S3 bucket
5. **Anti-Forensics:** Deleted logging bucket (CloudTrail)
6. **Root Cause:** Missing MFA, overprivileged IAM policy

---

## Case Study 5: Mobile Device Forensics

### Scenario
A suspect is investigated for drug trafficking. Their smartphone was seized during arrest.

### Evidence Collected
1. Android filesystem extraction (Cellebrite)
2. SIM card image
3. SD card image

### Analysis

**SMS Database:**
```
SELECT address, body, date FROM sms 
WHERE body LIKE '%delivery%' OR body LIKE '%package%' OR body LIKE '%meet%';

Results:
  +1-555-0123: "Package ready for delivery Tuesday" (2024-08-28 14:30:00)
  +1-555-0123: "Meet at warehouse 5, dock 3" (2024-08-29 09:15:00)
  +1-555-0123: "Payment received, next batch Thursday" (2024-09-01 11:20:00)
```

**Location History:**
```
Google Timeline:
  2024-08-29 09:10:00 - GPS: 40.7128, -74.0060 (route to warehouse)
  2024-08-29 09:15:00 - GPS: 40.7282, -73.9942 (warehouse location)
  2024-08-29 09:30:00 - GPS: 40.7282, -73.9942 (still at warehouse)
  2024-08-29 09:45:00 - GPS: 40.7128, -74.0060 (returned home)
```

**WhatsApp Messages:**
```
Chat with "+1-555-0456":
  "Got the supply, quality is good"
  "Need more for next week"
  "Wire transfer sent, check account"
```

### Findings
1. **Communication:** Encrypted messaging apps used for coordination
2. **Location:** Physical presence at warehouse confirmed by GPS
3. **Timeline:** Pattern of meetings correlating with message timestamps
4. **Financial:** Wire transfers mentioned in messages
5. **Network:** Phone contacts identified as potential accomplices

---

## Case Study Lessons

| Case | Key Lesson | Prevention |
|------|-----------|-----------|
| **Ransomware** | Email filtering and user training | Email sandboxing, MFA |
| **Insider** | DLP and USB controls | Device control policies |
| **APT** | Network monitoring and threat hunting | JA3/Beaconing detection |
| **Cloud** | IAM hardening and MFA | Least privilege, MFA everywhere |
| **Mobile** | Complete extraction and analysis | Mobile device management (MDM) |
