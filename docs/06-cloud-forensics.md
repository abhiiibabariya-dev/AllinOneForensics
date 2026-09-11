# Cloud Forensics

## Overview

Cloud forensics is the investigation of incidents involving cloud computing environments. Unlike traditional forensics, cloud environments lack physical evidence, requiring reliance on API logs, metadata, and provider-specific forensic tools.

---

## 1. AWS CloudTrail

### WHAT It Is
CloudTrail records API calls made against AWS services, providing an audit trail of all account activity.

### WHERE It Is Located
- S3 bucket configured for CloudTrail logs
- CloudTrail console → Event history (last 90 days)
- Logs stored as JSON in `AWSLogs/<account-id>/CloudTrail/<region>/<date>/`

### WHAT Evidence It Contains

| Field | Forensic Value |
|-------|---------------|
| **eventTime** | When the API call was made |
| **eventName** | What action was performed |
| **userIdentity** | Who performed the action |
| **sourceIPAddress** | Source IP of the caller |
| **requestParameters** | Parameters passed to the API |
| **responseElements** | Response from the API |
| **awsRegion** | Region where action occurred |
| **eventType** | Type of event (console, API, etc.) |

### Critical CloudTrail Events

| Event Name | Severity | Investigation Value |
|-----------|----------|-------------------|
| ConsoleLogin | High | Account access, location |
| CreateAccessKey | High | Credential creation for persistence |
| CreateUser | High | Backdoor account creation |
| AttachUserPolicy | High | Privilege escalation |
| PutBucketPolicy | High | S3 exposure |
| AuthorizeSecurityGroupIngress | High | Opening network access |
| CreateSnapshot | High | Potential data exfiltration |
| StopLogging | Critical | Anti-forensics attempt |

### Investigation Scenario: Compromised AWS Credentials
**Scenario:** An attacker obtains access keys and creates persistence.

**CloudTrail evidence:**
```
Event 1: CreateAccessKey
  Time: 2024-09-01 14:22:00 UTC
  User: victim-user
  Source IP: 185.141.27.99 (unknown external IP)
  Result: Access key created (AKIA...XXXX)

Event 2: AttachUserPolicy
  Time: 2024-09-01 14:23:00 UTC
  User: victim-user (via new access key)
  Source IP: 185.141.27.99
  Policy: AdministratorAccess

Event 3: CreateAccessKey
  Time: 2024-09-01 14:25:00 UTC
  User: admin-backdoor (new user)
  Source IP: 185.141.27.99
  Result: New access key created for persistence
```
**Analysis:** The attacker used compromised credentials to attach Admin policy, created a backdoor user, and established persistence via new access keys. The external IP identifies the attacker infrastructure.

---

## 2. Azure Activity Logs

### WHAT It Is
Azure Activity Logs capture all control-plane operations in an Azure subscription.

### WHERE It Is Located
- Azure Monitor → Activity Log
- Log Analytics Workspace (if configured)
- Exported to Storage Account or Event Hub

### WHAT Evidence It Contains

| Field | Forensic Value |
|-------|---------------|
| **operationName** | What action was performed |
| **eventTimestamp** | When the action occurred |
| **callerIpAddress** | Source IP of the caller |
| **identity** | Authenticated user/app details |
| **resultType** | Success/Failure |
| **resourceId** | Which resource was affected |
| **properties** | Additional event-specific data |

### Critical Azure Events

| Operation | Severity | Investigation Value |
|-----------|----------|-------------------|
| Microsoft.Authorization/roleAssignments/write | High | Privilege escalation |
| Microsoft.Storage/storageAccounts/write | Medium | Storage modification |
| Microsoft.Compute/virtualMachines/delete | High | Anti-forensics |
| Microsoft.KeyVault/vaults/delete | Critical | Key deletion |
| Microsoft.Network/networkSecurityGroups/write | High | Firewall rule changes |

---

## 3. GCP Audit Logs

### WHAT It Is
Google Cloud Platform audit logs record administrative and data access activities.

### WHERE It Is Located
- Cloud Logging → Logs Explorer
- Exported to Cloud Storage or BigQuery
- Organizational audit logs (all projects)

### WHAT Evidence It Contains

| Log Type | Content |
|----------|---------|
| **Admin Activity** | Resource creation/deletion/modification |
| **Data Access** | Data read/write operations (must be enabled) |
| **System Event** | Google-initiated system events |
| **Policy Denied** | Failed requests due to IAM policies |

### Investigation Scenario: GCP Data Exfiltration
**Scenario:** An attacker accesses Cloud Storage and downloads sensitive data.

**GCP audit log evidence:**
```
Admin Activity Log:
  14:22:00 - storage.buckets.get (project-prod-data, user: service-account@project.iam)
  14:22:30 - storage.objects.list (project-prod-data-backups)
  14:23:00 - storage.objects.get (project-prod-data-backups/customer-db.sql.gz, 2.3GB)

Data Access Log (if enabled):
  14:22:00 - storage.objects.list (user: service-account@project.iam)
  14:22:30 - storage.objects.get (customer-db.sql.gz)
```
**Analysis:** The service account was compromised and used to access and download a database backup. The IP address and user-agent in the full log entry identify the attacker's access point.

---

## 4. Cloud Forensics Quick Reference

| Platform | Primary Log | Location | Retention |
|----------|------------|----------|-----------|
| **AWS** | CloudTrail | S3 bucket | 90 days (default) |
| **Azure** | Activity Log | Azure Monitor | 90 days |
| **GCP** | Audit Logs | Cloud Logging | 30-400 days |

| Artifact | What It Shows | Investigation Use |
|----------|--------------|------------------|
| **IAM policies** | Who can access what | Privilege escalation detection |
| **Access keys** | API credentials | Credential theft detection |
| **Security groups** | Firewall rules | Network exposure |
| **S3/blob policies** | Storage permissions | Data exposure |
| **VPC flow logs** | Network traffic | Lateral movement |
| **CloudTrail/GCP logs** | API activity | Attack reconstruction |
