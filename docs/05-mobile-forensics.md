# Mobile Forensics

## Overview

Mobile forensics involves the recovery and analysis of data from mobile devices including smartphones, tablets, and wearables. Mobile devices contain rich personal and business data including messages, call logs, location history, photos, app data, and browser activity.

---

## 1. Android Forensics

### Artifact Locations

| Artifact | Path | Content |
|----------|------|---------|
| **SMS/MMS database** | `/data/data/com.android.providers.telephony/databases/mmssms.db` | All text and multimedia messages |
| **Call logs** | `/data/data/com.android.providers.contacts/databases/contacts2.db` | Call history (calls table) |
| **Chrome history** | `/data/data/com.android.chrome/app_chromium/Default/History` | Browsing history |
| **WiFi configs** | `/data/misc/wifi/WifiConfigStore.xml` | Saved WiFi networks and passwords |
| **Packages** | `/data/system/packages.xml` | Installed apps with install/update times |
| **Accounts** | `/data/system/users/0/accounts_ce.db` | Google and other accounts |
| **Location** | `/data/data/com.google.android.gms/databases/location.db` | Location history |
| **Telegram** | `/data/data/org.telegram.messenger/databases/` | Encrypted chat database |
| **WhatsApp** | `/data/data/com.whatsapp/databases/msgstore.db` | Message database |

### Android Acquisition Methods

| Method | Description | Root Required? | Completeness |
|--------|-------------|---------------|-------------|
| **ADB backup** | `adb backup` | No | Limited (excludes protected data) |
| **ADB pull** | Pull specific directories | Partial | Moderate |
| **Filesystem image** | Full `/data` partition image | Yes | High |
| **Chip-off** | Physical desoldering of NAND | N/A | Complete |
| **JTAG** | Joint Test Access Group interface | N/A | Complete |
| **Logical extraction** | MTP/PTP + ADB | No | Limited |

### Android Forensic Investigation

**Package Analysis (packages.xml):**
```xml
<!-- Third-party app from unknown source -->
<package name="com.suspicious.app" codePath="/data/app/com.suspicious.app"
         installer="com.android.vending" firstInstallTime="1693500000000"
         lastUpdateTime="1693500100000" />
```
**Finding:** The `installer` field reveals the source. Apps installed from outside Google Play, Samsung Store, or Amazon are flagged as potential sideloaded malware.

**Logcat Security Events:**
```
FATAL EXCEPTION: main
  java.lang.SecurityException: Permission denied
    at com.android.server.am.ActivityManagerService.checkPermission
  
  SELinux: avc: denied { read } for pid=12345 comm="malware" 
    scontext=u:r:untrusted_app:s0 tcontext=u:object_r:system_data_file:s0
```
**Finding:** SELinux denials and permission exceptions in logcat reveal unauthorized access attempts.

**SMS Database Analysis:**
```sql
SELECT address, body, date, type FROM sms 
WHERE body LIKE '%password%' OR body LIKE '%bank%' OR body LIKE '%verify%'
ORDER BY date DESC;
```
**Finding:** Messages containing passwords, bank references, or verification codes may indicate credential theft or 2FA interception.

---

## 2. iOS Forensics

### Artifact Locations

| Artifact | Path | Content |
|----------|------|---------|
| **SMS/iMessage** | `Manifest.db → SMS.db` | All messages |
| **Call logs** | `Manifest.db → call_history.db` | Call history |
| **Safari history** | `Manifest.db → History.db` | Browsing history |
| **Notes** | `Manifest.db → note.sqlite` | Apple Notes content |
| **Calendar** | `Manifest.db → Calendar.sqlitedb` | Calendar entries |
| **Photos** | `DCIM/` folder + `Photos.sqlite` | Photos and metadata |
| **WhatsApp** | `AppGroup → msgstore.db` | Messages |
| **Keychain** | `Keychain.sqlite` | Passwords, tokens |
| **WiFi** | `com.apple.wifi.plist` | Saved networks |
| **Location** | `Consolidated.db` | Location history |

### iOS Acquisition Methods

| Method | Description | Jailbreak Required? | Completeness |
|--------|-------------|-------------------|-------------|
| **iTunes backup** | Encrypted/unencrypted backup | No | Moderate |
| **Checkm8/checkra1n** | Bootrom exploit | Semi-tethered | High |
| **GrayKey** | Commercial tool (GrayShift) | No | High |
| **Cellebrite UFED** | Commercial extraction | Varies | High |
| **UFED Premium** | Filesystem extraction | No (newer devices) | High |

### iOS Forensic Investigation

**iMessage Analysis:**
```sql
SELECT T1.ROWID, T1.text, T1.date, T1.is_from_me, T2.id AS contact
FROM message T1 
LEFT JOIN chat_message_join T3 ON T1.ROWID = T3.message_id
LEFT JOIN chat T2 ON T3.chat_id = T2.ROWID
WHERE T1.text LIKE '%confidential%' OR T1.text LIKE '%leak%'
ORDER BY T1.date DESC;
```
**Finding:** Messages referencing confidential data or leaks may indicate insider threats or data exfiltration via iMessage.

**Keychain Extraction:**
```
Service: com.apple.account.google
  Account: victim@gmail.com
  Password: [encrypted_keychain_data]

Service: com.wifi.local
  Account: GuestWiFi
  Password: GuestPass123
```
**Finding:** Keychain contains stored passwords for WiFi, email, and cloud accounts that may be reused by the suspect.

---

## 3. Cross-Platform Artifacts

### Location Data

| Platform | Source | Evidence |
|----------|--------|----------|
| **Android** | `location.db`, Google Timeline | GPS coordinates, timestamps |
| **iOS** | `Consolidated.db`, Significant Locations | GPS, WiFi-based location |
| **Both** | WiFi connection history | Location via connected networks |

### Communication Metadata

| Platform | Source | Evidence |
|----------|--------|----------|
| **Android** | `mmssms.db`, `contacts2.db` | Call logs, SMS, contacts |
| **iOS** | `SMS.db`, `call_history.db` | iMessage, calls, contacts |
| **Both** | WhatsApp, Telegram, Signal | Third-party messaging |

### Investigation Scenario: Alibi Verification
**Scenario:** A suspect claims they were 50 miles away during a crime.

**Mobile evidence:**
```
Android Location (Google Location History):
  14:00:00 - GPS: 40.7128, -74.0060 (New York City) ✓
  14:15:00 - WiFi: connected to "CorpOfficeWiFi" (suspect's office) ✓
  14:30:00 - GPS: 40.7128, -74.0060 (still at office) ✓
  
  BUT:
  WiFi connection event at 13:58:00 to "CorpOfficeWiFi"
  AND cellular tower handoff at 13:55:00 from tower serving office area

  Meanwhile, a photo taken at 14:35:00 has GPS metadata:
  GPS: 40.7580, -73.9855 (Times Square, 3 miles from office)
```
**Analysis:** While WiFi connection suggests presence at the office, the photo GPS coordinates show the suspect was actually at Times Square during the alleged crime window. Location data proves the alibi is false.

---

## Mobile Forensics Quick Reference

| Question | Android Source | iOS Source |
|----------|---------------|-----------|
| What messages were sent? | `mmssms.db` | `SMS.db` |
| What calls were made? | `contacts2.db` calls table | `call_history.db` |
| What websites were visited? | Chrome `History` | Safari `History.db` |
| What apps are installed? | `packages.xml` | `Manifest.db` apps table |
| Where has the device been? | `location.db` | `Consolidated.db` |
| What WiFi networks were used? | `WifiConfigStore.xml` | `com.apple.wifi.plist` |
| What photos were taken? | DCIM + `media.db` | DCIM + `Photos.sqlite` |
| What files were downloaded? | `Download/` directory | `Downloads/` in Files app |
