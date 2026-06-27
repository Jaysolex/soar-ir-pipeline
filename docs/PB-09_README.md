# PB-09 | Insider Threat — Privileged User Anomaly Detection

**Playbook ID:** PB-09  
**Severity:** High / Critical  
**MITRE ATT&CK:** T1070.001 (Clear Windows Event Logs) · T1021.002 (SMB Lateral Movement) · T1078.002 (Valid Domain Accounts) · T1098 (Account Manipulation) · T1005 (Data from Local System)  
**Stack:** Wazuh · Shuffle · Active Directory · Azure AD · M365 Audit · Jira Change Management · TheHive · Slack

---

## Engineering Impact

Insider threats are the hardest category to detect and the most legally complex to respond to. The attacker has valid credentials, legitimate access to systems, and knowledge of your defenses. Standard IOC-based detection fails entirely — there are no malicious IPs, no known hashes, no C2 beacons. Everything looks like normal admin work.

PB-09 approaches this differently. The key insight is that **legitimate privileged work always has a paper trail** — an approved change ticket in Jira, a maintenance window, a manager-authorized task. Unauthorized privileged activity does not. The single highest-weight signal in the scoring model is off-hours admin activity with no approved change ticket. That one check alone captures 80% of genuine insider threat cases.

The second key design principle: **response is deliberately measured**. Insider threat cases have legal and HR dimensions that make aggressive automated containment risky. PB-09 uses a tiered response — manager notification at lower scores, account suspension only at high confidence — and always routes to a confidential TheHive case and security manager channel, never the general SOC Slack.

| Metric | Before | After |
|---|---|---|
| Privileged anomaly triage time | 30–60 min manual correlation | < 10 seconds automated |
| Change ticket correlation | Manual Jira lookup | Automated API check |
| Behavioral baseline | None | 30-day per-user host access pattern |
| HR signal visibility | Separate system | Integrated via AD extensionAttribute3 |
| Response coordination | Email chains | Automated manager + security team notification |

---

## Architecture

```
[ Wazuh Windows Event Monitor ]
Rule IDs: 100080–100085
          │
          ▼ (JSON webhook POST)
    [ Shuffle SOAR ]
    webhook_prod_insider_09
          │
    [ Log Tampering Zero-Tolerance Gate ]
    EventID 1102/4719 → immediate suspension
          │
    ┌─────┴──────────────────────────────────────────┐
    ▼                ▼                ▼               ▼
[ AD Context ]  [ 30d Baseline ]  [ Change Ticket ]  [ M365 Audit ]
Privilege level  Avg hosts/day    Jira approved       Admin ops
HR signal        Known hosts      change check        Role grants
Pending term     New system flag  In-window check     Policy changes
    │                │                │               │
    └────────────────┴────────────────┴───────────────┘
                             │
               [ Insider Threat Risk Score ]
               No change ticket + off-hours (30)
               + AD modification (20)
               + Pending termination (20)
               + Domain Admin (10) + New system (10)
               + Lateral spread (8-15) + Role grants (15)
               + New account created (15)
                             │
               ┌─────────────┴─────────────┐
          Score >= 70                  Score < 70
               │                           │
    [ Suspend AD Account ]       [ Manager Notification Only ]
    Remove from priv groups
               │
    [ Revoke Azure AD Sessions ]
    [ Email Manager + Security Team ]
               │
    [ TheHive Confidential Case ]
    [ Slack Security Manager Channel — NOT SOC ]
```

---

## File Structure

```
├── wazuh/
│   └── rules/
│       └── pb09_insider_threat_rules.xml     # Detection rules (IDs 100080–100085)
├── shuffle/
│   └── pb09_insider_threat_playbook.json     # Full Shuffle workflow export
└── docs/
    └── PB-09_README.md                       # This file
```

---

## Detection Rules

| Rule ID | Level | Trigger | Description |
|---|---|---|---|
| 100080 | 12 | Admin login EventID 4624 + 20:00–06:00 window | Privileged account login outside business hours |
| 100081 | 13 | Admin auth to 10+ distinct hosts in 10 min | Lateral spread — admin authenticating across the estate |
| 100082 | 13 | 50+ reads from Finance/HR/Legal/PII paths in 5 min | Bulk sensitive directory access — staging for exfiltration |
| 100083 | 14 | EventID 5136/5137/5138/5141 by non-standard account | Unauthorized AD/GPO object modification |
| 100084 | 15 | EventID 1102/4719/4739 | Security audit log cleared or audit policy modified — zero-tolerance |
| 100085 | 14 | EventID 4720/4728/4732 + off-hours + admin name | Privileged account created outside change window |

---

## Workflow Nodes

| Node | Type | Action |
|---|---|---|
| node_01_webhook | Trigger | Receives Wazuh privileged activity alert |
| node_02_extract | Parse | Normalizes fields, flags log tamper for zero-tolerance gate |
| node_03_log_tamper_gate | Condition | EventID 1102/4719 → immediate suspension bypass |
| node_04_ad_context | Enrichment | AD — full privilege groups, HR signal, account age |
| node_05_behavior_baseline | Enrichment | Wazuh API — 30-day auth baseline, known hosts, avg access pattern |
| node_06_change_ticket_check | Enrichment | Jira — approved in-window change ticket for this user |
| node_07_m365_recent_activity | Enrichment | M365 Audit — admin ops, role assignments, policy changes (12h) |
| node_08_score | Calculate | Insider threat risk score (0–100) |
| node_09_decision | Condition | Routes on score >= 70 |
| node_10_suspend_account | Containment | AD account disable + remove from privileged groups |
| node_11_manager_notify | Notify | Email to manager + security team — confidential |
| node_12_revoke_sessions | Containment | Azure AD — revoke all active sessions |
| node_13_escalate | Case Mgmt | TheHive confidential insider threat case |
| node_14_notify | Notify | Slack security manager channel only — never general SOC |

---

## Alert Payload Schema

```json
{
  "alert_id": "ins-009-c3d7f1",
  "timestamp": "2026-06-26T02:14:33Z",
  "rule_id": "100083",
  "rule_name": "Unauthorized AD/GPO modification by non-standard account",
  "artifacts": {
    "username": "CORP\\jharris",
    "hostname": "CORP-DC01",
    "agent_id": "wz-agent-00e7f8g9",
    "event_id": "5136",
    "target_username": "jharris",
    "ad_object_modified": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
    "ad_object_type": "Group",
    "file_path": null,
    "file_access_count": 0,
    "hosts_accessed": ["CORP-DC01", "CORP-DC02", "FILESERVER01"],
    "hosts_accessed_count": 3,
    "log_cleared": false,
    "new_account_name": null,
    "new_account_groups": [],
    "is_off_hours": true,
    "alert_time": "2026-06-26T02:14:33Z"
  }
}
```

---

## Insider Threat Risk Score Formula

```
composite_score =
  (is_off_hours == true AND has_approved_change == false ? 30 : 0)
  + (is_ad_modification == true ? 20 : 0)
  + (is_pending_termination == true ? 20 : 0)
  + (is_domain_admin == true ? 10 : 0)
  + (is_new_system_accessed == true ? 10 : 0)
  + (hosts_today_vs_baseline >= 3 ? 15 : hosts_today_vs_baseline >= 2 ? 8 : 0)
  + (role_assignments > 0 ? 15 : 0)
  + (permission_grants > 0 ? 10 : 0)
  + (is_new_account == true ? 15 : 0)
  + (is_account_creation == true ? 15 : 0)
```

| Component | Weight | Notes |
|---|---|---|
| Off-hours + no change ticket | 30 points | Highest single weight — unauthorized admin work |
| AD/GPO modification | 20 points | Direct infrastructure tampering |
| Pending termination HR signal | 20 points | Motivated insider with access |
| Domain Admin privilege | 10 points | Highest access level |
| New/unknown system accessed | 10 points | Outside 30-day baseline known hosts |
| Lateral spread (2–3× baseline) | 8–15 points | Tiered — accessing far more hosts than normal |
| M365 role assignments (12h) | 15 points | Privilege escalation via cloud |
| M365 permission grants | 10 points | OAuth/delegated permissions added |
| New account (≤7 days old) | 15 points | Backdoor account pattern |
| New privileged account created | 15 points | Persistence mechanism |

**Threshold:** Score >= 70 → account suspension + session revocation.  
**Zero-tolerance:** Log tampering (EventID 1102/4719/4739) → immediate suspension regardless of score.

---

## Key Design Decisions

**Why change ticket correlation carries the highest single weight?**  
Every mature organization requires change control for privileged work outside business hours. An admin who needs to patch a domain controller at 2 AM has an approved change ticket in Jira. An admin accessing a domain controller at 2 AM without a change ticket is either a policy violation at minimum or an active insider threat. This single check is the most reliable separator between legitimate and unauthorized privileged activity.

**Why notifications go to the security manager channel — not the general SOC channel?**  
Insider threat investigations are need-to-know. A SOC analyst who mentions the investigation to the wrong person can tip off the subject, destroy evidence, or expose the company to wrongful action liability. The TheHive case is tagged CONFIDENTIAL. The Slack notification goes to a restricted security manager channel. The SOC only learns about it if the security manager loops them in directly.

**Why remove from privileged groups before disabling?**  
If the account is re-enabled by a helpdesk analyst who doesn't know the context — or by the insider themselves if they still have access — an account that was merely disabled retains its group memberships. Removing Domain Admins membership before disabling means re-enabling the account without explicit group re-add restores a standard user, not an admin. This adds a second layer of protection against privilege retention.

**Why not isolate the host like PB-03 and PB-08?**  
Host isolation on a domain controller or server is extremely disruptive and may take down production services. Insider threats typically involve legitimate system access — the attacker is already authenticated and authorized on those systems. Disabling the AD account and revoking sessions cuts off access without the operational impact of isolating production infrastructure.

---

## AD Setup — HR Signal Integration

The HR system writes termination and PIP signals to AD extensionAttribute3:

```powershell
# Flag pending termination
Set-ADUser -Identity "jharris" -Replace @{extensionAttribute3="pending_termination"}

# Flag PIP
Set-ADUser -Identity "mbrown" -Replace @{extensionAttribute3="pip"}
```

The change management project key in Jira is configurable via workflow variable `JIRA_CHANGE_PROJECT_KEY`. Default: `CHG`.

---

## Deployment

### Environment Variables

```bash
AD_DOMAIN_CONTROLLER=ldap://your-dc.corp.local
AD_BIND_USER=svc_shuffle@corp.local
AD_BIND_PASSWORD=your_service_account_password
M365_TENANT_ID=your_tenant_id
M365_CLIENT_ID=your_client_id
M365_CLIENT_SECRET=your_secret
M365_AUDIT_TOKEN=your_audit_log_token
JIRA_URL=https://yourorg.atlassian.net
JIRA_API_TOKEN=your_jira_api_token
JIRA_CHANGE_PROJECT_KEY=CHG
THEHIVE_API_KEY=your_key_here
THEHIVE_URL=http://thehive:9000
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_SECURITY_MANAGER_CHANNEL=#security-management
SLACK_SOC_CHANNEL=#soc-alerts
WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_API_TOKEN=your_wazuh_jwt_token
```

### Add Wazuh Integration Block

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://shuffle-backend:5001/api/v1/hooks/webhook_prod_insider_09</hook_url>
  <alert_format>json</alert_format>
  <level>12</level>
  <group>insider_threat,pb09</group>
</integration>
```

---

## Testing

```bash
curl -X POST http://localhost:5001/api/v1/hooks/webhook_prod_insider_09 \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-pb09-001",
    "timestamp": "2026-06-26T02:14:33Z",
    "rule_id": "100083",
    "rule_name": "Unauthorized AD/GPO modification by non-standard account",
    "artifacts": {
      "username": "CORP\\testadmin",
      "hostname": "CORP-DC01",
      "agent_id": "test-agent-001",
      "event_id": "5136",
      "ad_object_modified": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
      "ad_object_type": "Group",
      "hosts_accessed": ["CORP-DC01", "CORP-DC02"],
      "hosts_accessed_count": 2,
      "log_cleared": false,
      "is_off_hours": true,
      "alert_time": "2026-06-26T02:14:33Z"
    }
  }'
```

---

## Interview Talking Points

> "PB-09 is the insider threat playbook and it uses a fundamentally different detection model from every other playbook in the suite. There are no malicious IPs or hashes to check — everything looks like normal admin work. The key insight I built the scoring around is that legitimate privileged work always has a change ticket. An admin doing maintenance at 2 AM has an approved Jira change request covering that window. An admin accessing production systems at 2 AM without a change ticket is unauthorized activity by definition — and that one check carries the highest weight in the scoring model at 30 points. I also built in a 30-day behavioral baseline that tracks which systems each user typically authenticates to, so I can flag when they're accessing systems outside their normal pattern. The containment is deliberately less aggressive than the other playbooks — I don't isolate the host because that takes down production, I disable the AD account and remove them from privileged groups. The groups removal is intentional: if someone re-enables the account without knowing the context, they get a standard user back, not a Domain Admin. The notifications go to a restricted security manager channel — not the general SOC Slack — because insider threat cases are need-to-know and tipping off the subject destroys the investigation."

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Subtechnique | Name |
|---|---|---|---|
| Defense Evasion | T1070 | T1070.001 | Indicator Removal: Clear Windows Event Logs |
| Lateral Movement | T1021 | T1021.002 | Remote Services: SMB/Windows Admin Shares |
| Privilege Escalation | T1078 | T1078.002 | Valid Accounts: Domain Accounts |
| Persistence | T1098 | — | Account Manipulation |
| Collection | T1005 | — | Data from Local System |

---

*Part of the Autonomous IR Pipeline — 10-playbook production SOAR project.*  
*Previous: [PB-08 — C2 Beaconing & Outbound Block](../pb08/) | Next: [PB-10 — Cloud Misconfiguration Triage](../pb10/)*
