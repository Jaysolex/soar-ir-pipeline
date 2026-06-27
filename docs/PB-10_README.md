# PB-10 | Cloud Misconfiguration Triage & Auto-Remediation

**Playbook ID:** PB-10  
**Severity:** High / Critical  
**MITRE ATT&CK:** T1190 (Exploit Public-Facing App) · T1578 (Modify Cloud Infra) · T1548 (Privilege Escalation) · T1530 (Data from Cloud Storage) · T1136.003 (Create Cloud Account)  
**Stack:** Wazuh · AWS CloudTrail · AWS GuardDuty · Azure Defender · AWS Config · AWS IAM · Azure Resource Manager · Shuffle · Jira · TheHive · Slack

---

## Engineering Impact

Cloud misconfigurations are the leading cause of cloud data breaches — not sophisticated exploits. A misconfigured S3 bucket, an overly permissive security group, or a root account used without MFA are the actual attack vectors attackers exploit. The challenge is that cloud environments generate thousands of configuration events per day, and not all misconfigurations are equal — a public S3 bucket tagged `DataClassification: PII` in production is a P0 incident. The same bucket tagged `Environment: dev` with no data is a Jira ticket.

PB-10 makes that distinction automatically by reading AWS resource tags to gate the response. Resource tags are the ground truth of what a cloud resource contains and what environment it serves — they drive both the exposure score and the remediation path.

| Metric | Before | After |
|---|---|---|
| S3 ACL remediation time | 30–60 min (manual CloudTrail review + console fix) | < 5 seconds (fast-track auto-remediation) |
| Security group remediation | 20–45 min (manual) | < 5 seconds (automated SG rule revoke) |
| Systemic misconfiguration detection | None | AWS Config / Azure Policy scope scan |
| Resource sensitivity context | Not available in alert | Read directly from AWS resource tags |

---

## Architecture

```
[ AWS CloudTrail + GuardDuty + Azure Defender ]
Rule IDs: 100090–100095
          │
          ▼ (JSON webhook POST via Wazuh)
    [ Shuffle SOAR ]
    webhook_prod_cloud_10
          │
    [ Fast-Track Gate ]
    is_root == true → immediate key delete
    is_public S3 == true → immediate ACL lock
          │
    ┌─────┴──────────────────┐
    ▼                        ▼
[ AWS Config / ARM ]    [ IAM Context ]
Resource tags            Actor identity
DataClassification       MFA status
Environment (prod?)      Attached policies
Owner tag
    │                        │
    └──────────┬─────────────┘
               │
    [ Exposure Assessment ]
    Production (30) + Sensitive data (25)
    + Misconfig type (10-20) + No MFA (10)
    + GuardDuty severity (8-15)
               │
    [ Similar Misconfig Scan ]
    AWS Config Rules / Azure Policy
    Systemic spread detection
               │
    [ Composite Risk Score ]
    Exposure + systemic(15) + GD severity(10)
               │
    ┌──────────┴──────────┐
 Score >= 65          Score < 65
    │                     │
    ▼              [ Jira Ticket Only ]
[ Auto-Remediate ]   Full context + owner
S3 → set private     Remediation steps
SG → revoke 0.0.0.0  Similar misconfigs
IAM → detach policy  SLA deadline
Root → delete key
    │
[ Jira Ticket + TheHive (Critical Only) ]
[ Slack Cloud Security Channel ]
```

---

## File Structure

```
├── wazuh/
│   └── rules/
│       └── pb10_cloud_rules.xml          # Detection rules (IDs 100090–100095)
├── shuffle/
│   └── pb10_cloud_playbook.json          # Full Shuffle workflow export
└── docs/
    └── PB-10_README.md                   # This file
```

---

## Detection Rules

| Rule ID | Level | Trigger | Description |
|---|---|---|---|
| 100090 | 14 | CloudTrail PutBucketAcl + AllUsers grant | S3 bucket ACL set to public |
| 100091 | 13 | CloudTrail AuthorizeSecurityGroupIngress + 0.0.0.0/0 + sensitive port | Security group opened to internet on SSH/RDP/DB ports |
| 100092 | 15 | CloudTrail userIdentity.type = Root | AWS root account used for non-MFA operation |
| 100093 | 13 | Azure Activity Log NSG write + * source + 22/3389 | Azure NSG rule allowing internet access to RDP/SSH |
| 100094 | 14 | GuardDuty finding severity >= 7.0 | AWS GuardDuty high-severity finding |
| 100095 | 14 | CloudTrail AttachUserPolicy + AdministratorAccess | Admin IAM policy attached directly to user |

---

## Workflow Nodes

| Node | Type | Action |
|---|---|---|
| node_01_webhook | Trigger | Receives Wazuh cloud alert payload |
| node_02_extract | Parse | Normalizes fields, classifies misconfig type, flags fast-track |
| node_03_fast_track_gate | Condition | Root account and public S3 bypass enrichment |
| node_04_resource_context | Enrichment | AWS Config / Azure ARM — resource tags, env, data classification |
| node_05_iam_context | Enrichment | IAM / Azure AD — actor identity, MFA, attached policies |
| node_06_exposure_assessment | Calculate | Exposure score based on production status and sensitivity |
| node_07_similar_misconfigs | Enrichment | AWS Config Rules / Azure Policy — scope scan for systemic issues |
| node_08_score | Calculate | Composite risk score (0–100) |
| node_09_decision | Condition | Routes on score >= 65 |
| node_10_auto_remediate | Containment | AWS/Azure API call to revert misconfiguration |
| node_11_create_jira | Action | Jira cloud security ticket with context + remediation steps |
| node_12_thehive | Conditional Action | TheHive case for critical exposure and GuardDuty high-severity only |
| node_13_notify | Notify | Slack cloud security channel alert |

---

## Alert Payload Schema

```json
{
  "alert_id": "cloud-010-d9e1f3",
  "timestamp": "2026-06-26T11:02:44Z",
  "rule_id": "100090",
  "rule_name": "AWS S3 bucket ACL set to public — data exposure risk",
  "source": "AWS_CloudTrail",
  "artifacts": {
    "cloud_provider": "AWS",
    "account_id": "123456789012",
    "region": "ca-central-1",
    "resource_type": "AWS::S3::Bucket",
    "resource_id": "corp-hr-documents-prod",
    "resource_arn": "arn:aws:s3:::corp-hr-documents-prod",
    "event_name": "PutBucketAcl",
    "actor_arn": "arn:aws:iam::123456789012:user/mbrown",
    "actor_type": "IAMUser",
    "actor_username": "mbrown",
    "source_ip": "76.68.22.155",
    "finding_severity": 0,
    "bucket_name": "corp-hr-documents-prod",
    "is_public": true,
    "is_root": false
  }
}
```

---

## Exposure Score Formula

```
exposure_score =
  (is_production == true ? 30 : 10)
  + (is_sensitive_data == true ? 25 : 0)
  + (misconfig_type == 'PUBLIC_S3' ? 20
     : misconfig_type == 'ROOT_ACCOUNT' ? 20
     : misconfig_type == 'OPEN_SECURITY_GROUP' ? 15
     : misconfig_type == 'IAM_ESCALATION' ? 15
     : 10)
  + (actor_no_mfa == true ? 10 : 0)
  + (finding_severity >= 7.0 ? 15
     : finding_severity >= 4.0 ? 8
     : 0)
```

**Composite score:** `exposure_score + (is_systemic ? 15 : 0) + (finding_severity >= 9.0 ? 10 : 0)`

**Threshold:** Score >= 65 → auto-remediation. Score < 65 → Jira ticket only.

---

## Auto-Remediation Actions

| Misconfig Type | AWS/Azure API Action |
|---|---|
| `PUBLIC_S3` | `PutBucketAcl` — set bucket to private, remove AllUsers grant |
| `OPEN_SECURITY_GROUP` | `RevokeSecurityGroupIngress` — remove 0.0.0.0/0 rule on affected port |
| `ROOT_ACCOUNT` | `DeleteAccessKey` — revoke root access keys, alert on MFA status |
| `IAM_ESCALATION` | `DetachUserPolicy` — remove AdministratorAccess from user, enforce role boundary |
| `AZURE_NSG_OPEN` | Azure REST API — delete overly permissive NSG inbound rule |
| `GUARDDUTY_FINDING` | Jira ticket only — GuardDuty findings need analyst-driven remediation |

---

## Key Design Decisions

**Why resource tags drive severity rather than misconfiguration type alone?**  
A public S3 bucket is always a misconfiguration. But `corp-dev-test-bucket-01` exposed publicly is a Jira ticket. `corp-hr-documents-prod` exposed publicly with a `DataClassification: PII` tag is a P0 incident requiring immediate auto-remediation. The resource tags are the ground truth for what's at risk — CVSS-style severity scores on misconfiguration types alone don't capture that context.

**Why auto-remediate cloud misconfigurations when we don't auto-remediate vulnerability findings?**  
Cloud misconfigurations are stateless, reversible, and have a direct API call to fix. Revoking a security group rule or setting an S3 bucket to private takes one API call and has no operational impact — the resource still exists and functions normally, it just stops being exposed. Compare this to vulnerability remediation (PB-07), which requires a patch cycle, testing, and maintenance windows. The reversibility and low operational risk justify auto-remediation for cloud configurations.

**Why scan for similar misconfigurations before creating the ticket?**  
A single misconfigured security group is likely a human error. Ten misconfigured security groups across an account suggest a systematic process failure — perhaps a Terraform template is wrong, or a CI/CD pipeline is applying bad default configurations. Surfacing the count in both the Slack alert and the Jira ticket signals to the owner whether this needs a one-off fix or a systemic process review.

**Why TheHive only for critical exposure and GuardDuty high-severity?**  
Cloud misconfiguration findings are high-volume. AWS Config and Azure Policy generate dozens of compliance findings per day across a busy cloud account. Creating a TheHive case for every finding drowns the incident queue. Reserving TheHive for production resources with sensitive data, root account usage, and GuardDuty active threat findings ensures the incident queue contains only genuine security incidents requiring IR-level investigation.

---

## AWS Setup — Required IAM Permissions

The Shuffle service account needs the following AWS IAM permissions for auto-remediation:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutBucketAcl",
        "s3:GetBucketAcl",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:DescribeSecurityGroups",
        "iam:DetachUserPolicy",
        "iam:DeleteAccessKey",
        "iam:GetUser",
        "config:GetResourceConfigHistory",
        "config:DescribeConfigRuleEvaluationStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Deployment

### Environment Variables

```bash
AWS_ACCESS_KEY_ID=your_shuffle_service_account_key
AWS_SECRET_ACCESS_KEY=your_shuffle_service_account_secret
AWS_REGION=ca-central-1
AZURE_TENANT_ID=your_tenant_id
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
AZURE_SUBSCRIPTION_ID=your_subscription_id
JIRA_URL=https://yourorg.atlassian.net
JIRA_API_TOKEN=your_jira_api_token
JIRA_CLOUD_PROJECT_KEY=CLOUD
THEHIVE_API_KEY=your_key_here
THEHIVE_URL=http://thehive:9000
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_CLOUD_CHANNEL=#cloud-security
```

### Add Wazuh Integration Block

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://shuffle-backend:5001/api/v1/hooks/webhook_prod_cloud_10</hook_url>
  <alert_format>json</alert_format>
  <level>13</level>
  <group>cloud,pb10</group>
</integration>
```

### AWS CloudTrail → Wazuh Integration

Configure CloudTrail to deliver to an S3 bucket monitored by Wazuh, or use AWS EventBridge to forward CloudTrail events to the Wazuh webhook directly:

```json
{
  "source": ["aws.s3", "aws.ec2", "aws.iam", "aws.guardduty"],
  "detail-type": ["AWS API Call via CloudTrail", "GuardDuty Finding"],
  "detail": {
    "eventName": ["PutBucketAcl", "AuthorizeSecurityGroupIngress", "AttachUserPolicy", "PutUserPolicy"]
  }
}
```

---

## Testing

```bash
curl -X POST http://localhost:5001/api/v1/hooks/webhook_prod_cloud_10 \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-pb10-001",
    "timestamp": "2026-06-26T11:02:44Z",
    "rule_id": "100090",
    "rule_name": "AWS S3 bucket ACL set to public",
    "source": "AWS_CloudTrail",
    "artifacts": {
      "cloud_provider": "AWS",
      "account_id": "123456789012",
      "region": "ca-central-1",
      "resource_type": "AWS::S3::Bucket",
      "resource_id": "test-bucket-pb10",
      "resource_arn": "arn:aws:s3:::test-bucket-pb10",
      "event_name": "PutBucketAcl",
      "actor_arn": "arn:aws:iam::123456789012:user/testuser",
      "actor_type": "IAMUser",
      "actor_username": "testuser",
      "source_ip": "76.68.22.155",
      "bucket_name": "test-bucket-pb10",
      "is_public": true,
      "is_root": false
    }
  }'
```

---

## Interview Talking Points

> "PB-10 closes out the suite with cloud misconfiguration triage for AWS and Azure. The key architectural decision is using AWS resource tags to gate the auto-remediation response — a public S3 bucket tagged as dev environment with no data classification gets a Jira ticket. The same bucket tagged as production with a PII data classification tag gets auto-remediated in under 5 seconds via the AWS S3 PutBucketAcl API. The tag is the ground truth for what's actually at risk. I also built a scope scan step using AWS Config Rules that runs before ticket creation — it checks how many other resources in the account have the same misconfiguration. A single open security group is a human error. Ten open security groups means the Terraform template or deployment pipeline has a bug and the Jira ticket needs to reflect that systemic scope, not just one resource. For GuardDuty findings I deliberately didn't auto-remediate — GuardDuty active threat findings like EC2 instance communicating with known C2 need analyst investigation, not a configuration rollback. So those route to TheHive directly."

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Subtechnique | Name |
|---|---|---|---|
| Initial Access | T1190 | — | Exploit Public-Facing Application |
| Defense Evasion | T1578 | — | Modify Cloud Compute Infrastructure |
| Privilege Escalation | T1548 | — | Abuse Elevation Control Mechanism |
| Exfiltration | T1530 | — | Data from Cloud Storage |
| Persistence | T1136 | T1136.003 | Create Account: Cloud Account |

---

*Final playbook in the Autonomous IR Pipeline — 10-playbook production SOAR project.*  
*Previous: [PB-09 — Insider Threat Privileged Anomaly](../pb09/)*

---

# Autonomous IR Pipeline — Complete Suite

| # | Playbook | Severity | MITRE Tactics |
|---|---|---|---|
| PB-01 | Phishing Triage & Containment | Critical | Initial Access (T1566) |
| PB-02 | Brute Force & Account Lockout | Critical | Credential Access (T1110) |
| PB-03 | Ransomware Detection & Host Isolation | Critical P1 | Impact (T1486, T1490) |
| PB-04 | Malware Hash Enrichment & Quarantine | High | Execution (T1059, T1204) |
| PB-05 | Impossible Travel & Suspicious Login | High | Initial Access (T1078) |
| PB-06 | Data Exfiltration Alert Triage | High/Critical | Exfiltration (T1048, T1567) |
| PB-07 | Critical CVE Detection & Patch Ticketing | High/Critical | Initial Access (T1190) |
| PB-08 | C2 Beaconing & Outbound Block | Critical P1 | C2 (T1071, T1573) |
| PB-09 | Insider Threat Privileged Anomaly | High/Critical | Defense Evasion (T1070) |
| PB-10 | Cloud Misconfiguration Triage | High/Critical | Exfiltration (T1530) |
