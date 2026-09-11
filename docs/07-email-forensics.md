# Email Forensics

## Overview

Email forensics is the analysis of email content, headers, and metadata to investigate phishing, business email compromise (BEC), malware delivery, and data exfiltration.

---

## 1. Email Header Analysis

### WHAT It Is
Email headers contain routing information, authentication results, and metadata about how a message traveled from sender to recipient.

### WHERE It Is Located
- **EML files:** Full headers in the raw email file
- **PST/OST files:** Outlook archive format
- **MBOX files:** Unix mailbox format
- **MSG files:** Outlook message format

### Key Header Fields

| Header Field | What It Reveals |
|-------------|----------------|
| **From** | Displayed sender (can be spoofed) |
| **Reply-To** | Where replies go (may differ from From) |
| **Return-Path** | Actual return address for bounces |
| **Received** | Server hop-by-hop routing (most reliable) |
| **Message-ID** | Unique identifier |
| **Date/Time** | When sent |
| **X-Mailer** | Client software used |
| **MIME-Version** | Message format version |
| **Content-Type** | Attachment/body type |

### SPF/DKIM/DMARC Authentication

| Check | Purpose | Result Interpretation |
|-------|---------|---------------------|
| **SPF** | Verifies sender IP is authorized | pass/fail/softfail |
| **DKIM** | Cryptographic signature verification | pass/fail |
| **DMARC** | Policy alignment check | pass/fail/quarantine/reject |

### Investigation Scenario: Phishing Email
**Scenario:** A user receives a suspicious email claiming to be from their bank.

**Header analysis:**
```
From: "Bank Security" <security@bankofamerica-secure.com>
Reply-To: <attacker@protonmail.com>
Return-Path: <attacker@protonmail.com>
Received: from mail.attacker-server.ru (185.141.27.99)
    by mx.bankofamerica.com with ESMTP id x12345
X-Mailer: PHPMailer 6.1.4
Authentication-Results: mx.bankofamerica.com;
    spf=fail (domain bankofamerica-secure.com does not designate 185.141.27.99 as permitted sender)
    dkim=fail (signature verification failed)
    dmarc=fail (policy=reject)
```
**Findings:**
1. SPF fails — the sending IP is not authorized for the bank's domain
2. DKIM fails — no valid cryptographic signature
3. DMARC fails — the domain does not align with the bank's domain
4. Reply-To differs from From — replies go to attacker's Protonmail
5. Sending server is in Russia — not a bank infrastructure

---

## 2. Email Attachments

### WHAT They Reveal
- **Malicious macros** in Office documents (maldocs)
- **Embedded links** to phishing sites
- **Weaponized PDFs** with JavaScript
- **RAR/ZIP archives** containing malware
- **Disk images** (ISO, IMG) used for bypassing Mark of the Web

### Attachment Analysis Workflow

```
1. Extract attachment from email
2. Compute hash (SHA-256)
3. Check hash against VirusTotal/MalwareBazaar
4. Static analysis (strings, PE headers, embedded objects)
5. Dynamic analysis (sandbox detonation)
6. Extract IOCs (URLs, IPs, domains, hashes)
```

### Investigation Scenario: Ransomware Delivery via Phishing
**Scenario:** An employee reports receiving a suspicious email with a PDF attachment.

**Email evidence:**
```
From: invoices@realcompany-supply.com
Subject: Urgent: Overdue Invoice #INV-2024-891
Attachment: Invoice_INV-2024-891.pdf.exe (284,000 bytes)
Content-Type: application/x-msdownload (despite .pdf.exe naming)

PDF analysis:
  - PE executable disguised as PDF
  - Imports: URLDownloadToFile, CreateProcess, RegSetValue
  - Embedded URL: http://185.141.27.99/download/payload.exe
  - C2 server: 185.141.27.99:443
  - Persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
```
**Analysis:** The "PDF" is actually an executable. The user double-clicked it, which downloaded and executed the ransomware payload from the attacker's server.

---

## 3. PST/OST Forensics

### WHAT They Are
PST (Personal Storage Table) and OST (Offline Storage Table) files are Outlook data files that store emails, calendar entries, contacts, and tasks.

### WHERE They Are Located

| File | Location | Content |
|------|----------|---------|
| **PST** | `C:\Users\<user>\Documents\Outlook Files\` | Archived emails |
| **OST** | `C:\Users\<user>\AppData\Local\Microsoft\Outlook\` | Offline cache |
| **NK2** | `C:\Users\<user>\AppData\Roaming\Microsoft\Outlook\` | AutoComplete cache |

### WHAT Evidence PST Contains
- All emails (sent, received, deleted)
- Calendar entries (meetings, appointments)
- Contacts (names, emails, phone numbers)
- Tasks and notes
- Deleted items (recoverable until compaction)

### HOW an Investigator Analyzes It
```python
# Using pypff (libpff) Python bindings
import pypff

pst = pypff.file()
pst.open('evidence.pst')

# Iterate folders
for folder in pst.get_root_folder().get_sub_folders():
    for message in folder.get_messages():
        print(f"From: {message.get_sender_name()}")
        print(f"Subject: {message.get_subject()}")
        print(f"Date: {message.get_delivery_time()}")
```

---

## 4. Email Evidence Quick Reference

| Artifact | Location | Key Evidence |
|----------|----------|-------------|
| **EML files** | Email exports | Full headers, body, attachments |
| **PST/OST** | Outlook data files | Complete mailbox archive |
| **MSG files** | Outlook message exports | Individual email with metadata |
| **MBOX** | Unix/Linux mail spools | All emails in a mailbox |
| **IMAP cache** | Client-side cache | Synced email data |
| **Exchange logs** | Server-side | Mail flow, delivery status |
| **SMTP logs** | Mail server | Sending activity |
