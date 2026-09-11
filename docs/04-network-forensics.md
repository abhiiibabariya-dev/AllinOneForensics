# Network Forensics

## Overview

Network forensics is the capture, recording, and analysis of network traffic to investigate security incidents, reconstruct events, and identify malicious activity. It provides evidence of what data entered or left a network, when communication occurred, and which hosts were involved.

---

## 1. Packet Capture (PCAP) Analysis

### WHAT It Is
A packet capture (PCAP) file records raw network traffic passing through a network interface. Each packet contains headers (Ethernet, IP, TCP/UDP) and payload data.

### WHERE It Is Located
- Network TAP orSPAN port output
- Wireshark/tcpdump captures
- IDS/IPS alert captures
- AllinOneForensics ingests `.pcap` and `.pcapng` files from `evidence/network/`

### WHAT Evidence It Contains
- **Source and destination IP addresses** and MAC addresses
- **Source and destination ports** (service identification)
- **Protocol information** (TCP flags, DNS queries, HTTP headers)
- **Payload data** (file transfers, email content, HTTP POST data)
- **Timestamps** for every packet
- **Packet size** and frequency patterns

### WHY It Matters
Network traffic is extremely difficult to erase completely. Even if an attacker clears local logs, network monitoring systems, firewall logs, and packet captures may retain evidence of C2 communication, data exfiltration, or lateral movement.

### HOW an Investigator Analyzes It

```bash
# AllinOneForensics parses pcap files automatically
aiof parse CASE-001 --module network

# Using tshark (command-line Wireshark)
tshark -r evidence.pcap -Y "http" -T fields -e http.host -e http.request.uri

# Extract DNS queries
tshark -r evidence.pcap -Y "dns" -T fields -e dns.qry.name

# Extract TCP conversations
tshark -r evidence.pcap -q -z conv,tcp

# Extract HTTP objects (files transferred)
tshark -r evidence.pcap --export-objects http,exported_files/

# Using Scapy (Python)
from scapy.all import rdpcap
packets = rdpcap('evidence.pcap')
for pkt in packets:
    if pkt.haslayer('IP'):
        print(pkt['IP'].src, pkt['IP'].dst)
```

### Investigation Scenario: Data Exfiltration via DNS
**Scenario:** An attacker exfiltrates data by encoding it in DNS queries to their controlled domain.

**Network evidence:**
```
DNS Queries (from pcap):
  2024-09-01 14:22:00 - aGVsbG8gd29ybGQ.evil.com  (base64: "hello world")
  2024-09-01 14:22:01 - cGFzc3dvcmQxMjM.evil.com  (base64: "password123")
  2024-09-01 14:22:02 - aQlVRElUQ0FSRC0wMDE.evil.com  (base64: "IDCARD-001")
  ... (1,247 queries in 30 minutes)
```
**Analysis:** The DNS queries contain base64-encoded data. The subdomain labels are too long and structured for normal DNS usage. The high volume of queries to a single unusual domain confirms DNS exfiltration.

---

## 2. DNS Traffic Analysis

### WHAT It Is
DNS (Domain Name System) translates domain names to IP addresses. DNS traffic analysis examines resolution requests to identify malicious domains, C2 infrastructure, and data exfiltration.

### WHERE DNS Evidence Is Found
- **Packet captures** (UDP/TCP port 53)
- **DNS server logs** (BIND, Windows DNS, Unbound)
- **Passive DNS databases** (Farsight DNSDB, VirusTotal)
- **Endpoint DNS cache** (`ipconfig /displaydns` on Windows)
- **Sysmon Event ID 22** (DNS query logging)

### WHAT Evidence DNS Contains
- **Queried domain names** — what the endpoint tried to resolve
- **Query timestamps** — when resolution was attempted
- **Resolved IP addresses** — what the domain pointed to
- **Query types** — A, AAAA, MX, TXT, CNAME (TXT used for C2)
- **Response codes** — NOERROR, NXDOMAIN (DGA detection)

### WHY It Matters
DNS is one of the most reliable indicators of malicious activity because:
- Almost all C2 communication begins with a DNS resolution
- DNS queries are rarely blocked or logged as suspicious by default
- DNS analysis can reveal attacker infrastructure even if the actual traffic is encrypted

### Attack Patterns Detectable via DNS

| Pattern | Detection Method | Indicator |
|---------|-----------------|-----------|
| **Beaconing** | Regular DNS query intervals | Fixed timing to same domain |
| **DGA** (Domain Generation Algorithm) | High NXDOMAIN rate, random-looking domains | 100+ NXDOMAIN in short period |
| **DNS tunneling** | Unusually long subdomain labels | Subdomains > 50 characters |
| **Fast flux** | Rapid IP changes for same domain | IP changes every few minutes |
| **Domain fronting** | SNI mismatch with Host header | CDN abuse pattern |
| **Subdomain encoding** | Base32/hex in subdomains | Encoded data in query |

### Investigation Scenario: DGA Malware Detection
**Scenario:** A host is generating massive DNS traffic to random-looking domains.

**Evidence:**
```
DNS Query Log:
  14:22:01 - xkqrzmvb.info → NXDOMAIN
  14:22:02 - bwtjkpla.net → NXDOMAIN
  14:22:03 - mjnqtwrz.com → 185.141.27.99
  14:22:04 - rxfhknbm.org → NXDOMAIN
  14:22:05 - dqjmkvnp.info → NXDOMAIN
  14:22:06 - gxtwmljk.com → 185.141.27.99
  ... (350 queries in 10 minutes, 347 NXDOMAIN, 3 successful to same IP)
```
**Analysis:** The random-looking domains with high NXDOMAIN rate indicate DGA. The 3 successful resolutions to `185.141.27.99` identify the active C2 server. Blocking this IP stops the malware's check-in.

---

## 3. HTTP/HTTPS Traffic Analysis

### WHAT It Is
HTTP/HTTPS analysis examines web traffic for malicious communication, data exfiltration, and web-based attacks.

### WHERE HTTP Evidence Is Found
- **PCAP files** (port 80, 443, 8080)
- **Proxy logs** (Squid, Bluecoat, Zscaler)
- **Web server access logs** (Apache, Nginx, IIS)
- **Browser history** (correlated with timestamps)

### WHAT Evidence HTTP Contains

| Field | Forensic Value |
|-------|---------------|
| **Host header** | Target domain (may differ from DNS) |
| **URI/Path** | Specific resource accessed |
| **User-Agent** | Browser/app identification (may be spoofed) |
| **Referer** | Where the request originated |
| **POST data** | Data sent to server (credentials, uploads) |
| **Response code** | 200=OK, 302=redirect, 404=not found |
| **Content-Type** | File type being transferred |
| **Set-Cookie** | Session tracking |

### HOW an Investigator Analyzes It

```bash
# Extract HTTP requests
tshark -r traffic.pcap -Y "http.request" -T fields \
  -e frame.time -e ip.src -e http.host -e http.request.uri -e http.request.method

# Extract HTTP POST data (may contain credentials)
tshark -r traffic.pcap -Y "http.request.method==POST" -T fields \
  -e http.host -e http.request.uri -e http.file_data

# Extract HTTP objects (downloaded files)
tshark -r traffic.pcap --export-objects http,exported/

# Extract HTTP headers
tshark -r traffic.pcap -Y "http" -T fields \
  -e http.user_agent -e http.referer -e http.content_type
```

### Investigation Scenario: C2 Over HTTPS
**Scenario:** Malware communicates with C2 via HTTPS. While content is encrypted, metadata reveals the pattern.

**Evidence:**
```
HTTPS Connections:
  14:22:00 - 10.0.0.5:49832 → 185.141.27.99:443 (SNI: api.update-service.com)
    JA3 Hash: a0e9f5d64349fb13191bc781f81f42e1 (unique to malware)
    Bytes sent: 256 (small, beaconing)
    Bytes received: 1024 (C2 commands)
    
  14:22:30 - 10.0.0.5:49833 → 185.141.27.99:443 (SNI: api.update-service.com)
    JA3 Hash: a0e9f5d64349fb13191bc781f81f42e1
    Bytes sent: 512 (status update)
    Bytes received: 1024
```
**Analysis:** Regular 30-second intervals, consistent JA3 fingerprint, and small fixed-size responses indicate automated C2 beaconing. JA3 hash can be searched across the enterprise for other infected hosts.

---

## 4. Beaconing Detection

### WHAT It Is
Beaconing is the periodic communication between a compromised host and its C2 server. Detecting beaconing patterns is one of the most valuable network forensics techniques.

### HOW to Detect Beaconing

| Method | Description | Tools |
|--------|-------------|-------|
| **Interval analysis** | Regular time gaps between connections | RITA, A.R.Gus |
| **Jitter analysis** | Calculate deviation from expected interval | Zeek, RITA |
| **Flow analysis** | NetFlow/IPFIX volume patterns | Argus, nfdump |
| **DNS frequency** | Regular DNS queries to same domain | Zeek DNS logs |
| **JA3/JA3S** | TLS fingerprinting for unique clients | Zeek, Suricata |

### Detection Algorithm
```
1. Extract all connections to each destination IP/domain
2. Calculate time delta between consecutive connections
3. Compute coefficient of variation (std dev / mean)
4. Low CV (< 0.3) = regular beaconing pattern
5. Score: regularity + duration + unique destination = threat score
```

### Investigation Scenario: Cobalt Strike Beacon
**Scenario:** Red team deploys Cobalt Strike beacon with 60-second sleep time and 30% jitter.

**Evidence:**
```
Connection Pattern (to 10.0.1.100:443):
  14:00:00 - SYN (256 bytes)
  14:00:58 - SYN (256 bytes)    # 58s gap (within jitter)
  14:01:55 - SYN (256 bytes)    # 57s gap
  14:02:52 - SYN (256 bytes)    # 57s gap
  ...

JA3 Hash: 72a589da586844d7f0818ce684948eea (Cobalt Strike default)
JA3S: ae4edc6faf64d08308082ad26be60767
```
**Analysis:** The ~60-second interval with slight variation matches Cobalt Strike's default beacon configuration. The JA3 hash confirms Cobalt Strike. The consistent pattern across hours proves active C2 channel.

---

## 5. Network Flow Analysis

### WHAT It Is
Network flow data (NetFlow, IPFIX, sFlow) records metadata about network conversations without capturing full packet contents. It is lighter weight than packet capture and can be retained for longer periods.

### WHERE It Is Found
- **Router/switch exports** (NetFlow v5/v9, IPFIX)
- **Network monitoring** (PRTG, Plixer, Kentik)
- **Zeek flow logs**

### WHAT Evidence Flows Contain

| Field | Forensic Value |
|-------|---------------|
| **Source IP** | Origin of communication |
| **Destination IP** | Target of communication |
| **Source port** | Ephemeral port (identifies connection) |
| **Destination port** | Service being accessed |
| **Protocol** | TCP/UDP/ICMP |
| **Start time** | Connection initiation |
| **End time** | Connection termination |
| **Byte count** | Data volume transferred |
| **Packet count** | Number of packets |
| **Flags** | TCP flags (SYN, FIN, RST) |

### Investigation Scenario: Data Exfiltration via Large Upload
**Scenario:** An insider uploads 2GB of data to a cloud storage service over 3 hours.

**Flow evidence:**
```
Flow Record:
  2024-09-01 12:00:00 - 2024-09-01 12:03:00
  10.0.0.5:54321 → 104.16.133.229:443 (upload.box.com)
  Bytes sent: 45,234,128 (45MB in 3 minutes)
  
  2024-09-01 12:05:00 - 2024-09-01 12:08:00
  10.0.0.5:54322 → 104.16.133.229:443
  Bytes sent: 52,100,456 (52MB in 3 minutes)
  
  ... (40 similar flows over 3 hours, total: 2.1GB uploaded)
```
**Analysis:** Flow data shows sustained upload to cloud storage. Normal user traffic to this service averages 5MB/day. The 400x spike in upload volume combined with the time pattern (during work hours) indicates data exfiltration.

---

## 6. TLS/SSL Certificate Analysis

### WHAT It Is
TLS certificates provide identity information about encrypted connections. Analyzing certificates can identify C2 infrastructure, phishing sites, and attacker-controlled domains.

### WHAT Evidence TLS Contains

| Field | Forensic Value |
|-------|---------------|
| **Subject CN** | Domain name on certificate |
| **Issuer** | Certificate authority |
| **Valid dates** | Certificate validity period |
| **SAN** | Additional domain names |
| **Serial number** | Unique certificate identifier |
| **SHA-256 thumbprint** | Certificate hash (track reuse) |
| **Self-signed** | Red flag for attacker infrastructure |

### HOW an Investigator Analyzes It

```bash
# Extract TLS certificates from pcap
tshark -r traffic.pcap -Y "tls.handshake.type==11" -T fields \
  -e tls.handshake.certificate

# Extract JA3 hashes (TLS fingerprinting)
tshark -r traffic.pcap -Y "tls.handshake.type==1" -T fields \
  -e tls.handshake.ja3

# View TLS certificate details
tshark -r traffic.pcap -Y "x509sat.utf8String" -T fields \
  -e x509sat.utf8String
```

### Investigation Scenario: JA3 Fingerprinting Malware
**Scenario:** Multiple hosts show connections to different IPs but the same JA3 hash.

**Evidence:**
```
Host A: 10.0.0.5 → 185.141.27.99:443  JA3: a0e9f5d64349fb13191bc781f81f42e1
Host B: 10.0.0.12 → 192.168.5.32:443   JA3: a0e9f5d64349fb13191bc781f81f42e1
Host C: 10.0.0.27 → 45.77.65.211:443   JA3: a0e9f5d64349fb13191bc781f81f42e1
```
**Analysis:** The same JA3 hash across three hosts connecting to different IPs indicates the same malware variant. Blocking all three IPs and searching for the JA3 hash identifies 12 additional infected hosts across the enterprise.

---

## 7. Network Evidence Quick Reference

| Artifact | Location | Key Evidence | Analysis Tool |
|----------|----------|-------------|--------------|
| **PCAP** | Network captures | Full packet data | Wireshark, tshark |
| **NetFlow** | Router/switch exports | Conversation metadata | RITA, Argus |
| **DNS logs** | DNS server / Zeek | Domain queries | Custom scripts, RITA |
| **Proxy logs** | Web proxy server | HTTP/HTTPS requests | Squid logs, Splunk |
| **Firewall logs** | Firewall appliance | Allowed/blocked connections | Splunk, ELK |
| **IDS/IPS alerts** | Security appliance | Matched signatures | Snort, Suricata |
| **Flow data** | Network TAP | Packet metadata | Zeek, nfdump |

---

## Network Forensics Investigation Workflow

```
1. CAPTURE    → Obtain pcap, flow data, logs
2. FILTER     → Narrow to time window and scope
3. RESOLVE    → Identify source/destination hosts
4. PROTOCOLS  → Identify services and applications
5. DNS        → Map domain-to-IP relationships
6. HTTP/TLS   → Analyze web traffic and certificates
7. BEACONING  → Detect periodic C2 communication
8. FLOWS      → Volume analysis for exfiltration
9. CORRELATE  → Cross-reference with endpoint artifacts
10. REPORT    → Document network evidence and IOCs
```
