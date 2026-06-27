# PB-06 | Data Exfiltration Alert Triage

**Playbook ID:** PB-06  
**Severity:** High / Critical  
**MITRE ATT&CK:** T1048 (Exfil Over Alt Protocol) · T1567.002 (Exfil to Cloud Storage) · T1052.001 (USB) · T1071.004 (DNS Tunneling) · T1114.003 (Email Forwarding Rule)  
**Stack:** Wazuh · Shuffle · VirusTotal · MaxMind GeoIP · AbuseIPDB · Active Directory · Microsoft 365 Audit · CrowdStrike · Firewall API · TheHive · Slack

---

## Engineering Impact

Data exfiltration is the highest-consequence alert category in the suite — the data leaving the network is the damage, not just the risk of damage. The challenge is that DLP alert volumes are high and false positive rates are significant: large file transfers, cloud sync operations, and developer package downloads all look like exfiltration to a naive rule.

PB-06 solves this with two mechanisms that differentiate it from every other playbook: **HR signal integration** and **30-day behavioral baseline comparison**. An employee transferring 200MB to Dropbox is a DLP event. An employee transferring 200MB to an anonymous file host three days before their termination date, after accessing 150 documents in the past hour, is a confirmed insider threat. The scoring engine treats those two events completely differently.

| Metric | Before | After |
|---|---|---|
| Triage time per DLP alert | 25–45 min manual investigation | < 10 seconds automated enrichment |
| HR signal visibility | Separate HR system — analyst doesn't see it | Integrated via AD extensionAttribute3 |
| Behavioral context | No baseline — every transfer is equal | 30-day rolling baseline — anomalous volume flagged |
| False positive escalation | High — all large transfers paged out | Score-gated — clean destination + no HR signal = low score |

---

## Architecture

```
[ Wazuh + Proxy / DLP Agent / Email Gateway ]
Rule IDs: 100050–100055
          │
          ▼ (JSON webhook POST)
    [ Shuffle SOAR ]
    webhook_prod_exfiltration_06
          │
    [ Artifact Extraction ]
    Method classification (network / cloud /
    email / USB / DNS tunnel)
    Convert bytes → MB
          │
    ┌─────┴──────────┬──────────────┬─────────────────┬──────────────────┐
    ▼                ▼              ▼                  ▼                  ▼
[ VT Dest Rep ]  [ GeoIP Dest ]  [ AD User ]   [ Wazuh Baseline ]  [ M365 Audit ]
Malicious flag   Country + ASN   HR signals    30-day transfer     File downloads
VT categories    High-risk       Pending term  avg/max volume      Email forwards
                 country flag    Account exp   Anomaly flag        External shares
    │                │              │                  │                  │
    └────────────────┴──────────────┴──────────────────┴──────────────────┘
                                    │
                    [ Composite Exfiltration Risk Score ]
                    Pending termination (30) + Classified data (20)
                    + Malicious dest (20) + Anomalous volume (15)
                    + High-risk country (10) + Unapproved cloud (10)
                    + Account expiring (10) + Email forwarding (10)
                                    │
               ┌────────────────────┴────────────────────┐
          Score >= 70                               Score < 70
          OR (classified + malicious dest)               │
               │                               [ Escalate to Analyst ]
    [ Block Destination (72hr TTL) ]
    [ Isolate Host if score >= 85 ]
    [ Revoke M365 Sessions ]
               │
    [ TheHive DLP Case + Legal/HR Checklist ]
    [ Slack — Insider Threat Channel if HR signal ]
```

---

## File Structure

```
├── wazuh/
│   └── rules/
│       └── pb06_exfiltration_rules.xml     # Detection rules (IDs 100050–100055)
├── shuffle/
│   └── pb06_exfiltration_playbook.json     # Full Shuffle workflow export
└── docs/
    └── PB-06_README.md                     # This file
```

---

## Detection Rules

| Rule ID | Level | Trigger | Description |
|---|---|---|---|
| 100050 | 13 | Outbound bytes >= 50MB | Large outbound network transfer |
| 100051 | 13 | Proxy log — unapproved upload domains | Upload to Mega, WeTransfer, AnonFiles, etc. |
| 100052 | 12 | 30+ file opens in 5 min, same user | Mass document access — staging for exfiltration |
| 100053 | 13 | Email DLP — large attachment to personal email | Attachment 1MB+ sent to Gmail/Yahoo/ProtonMail |
| 100054 | 12 | DLP agent — classified data to USB | Confidential/PII/PHI/PCI copied to removable storage |
| 100055 | 14 | DNS TXT/NULL/CNAME queries > 60 chars | DNS tunneling exfiltration pattern |

---

## Workflow Nodes

| Node | Type | Action |
|---|---|---|
| node_01_webhook | Trigger | Receives DLP/network/proxy alert payload |
| node_02_extract | Parse | Normalizes fields, classifies exfil method, converts bytes to MB |
| node_03_dest_reputation | Enrichment | VirusTotal — destination domain/IP reputation |
| node_04_dest_geoip | Enrichment | MaxMind — destination country, ASN, high-risk country flag |
| node_05_user_context | Enrichment | AD — privilege level, HR signal, account expiry |
| node_06_activity_baseline | Enrichment | Wazuh API — 30-day transfer volume baseline |
| node_07_m365_audit | Enrichment | M365 Audit Log — downloads, forwarding rules, external shares (24h) |
| node_08_score | Calculate | Composite exfiltration risk score (0–100) |
| node_09_decision | Condition | Routes on score >= 70 OR classified + malicious dest |
| node_10_block_destination | Containment | Firewall block destination IP + domain (72hr TTL) |
| node_11_isolate_host | Containment | CrowdStrike isolation — score >= 85 only |
| node_12_revoke_m365 | Containment | Azure AD — revoke M365 sessions |
| node_13_escalate | Case Mgmt | TheHive DLP case with Legal/HR checklist |
| node_14_notify | Notify | Slack — insider threat channel if HR signal present |

---

## Alert Payload Schema

```json
{
  "alert_id": "dlp-006-a2f9c1",
  "timestamp": "2026-06-25T16:44:03Z",
  "rule_id": "100051",
  "rule_name": "Bulk upload to unapproved file sharing service",
  "source": "ProxyLog",
  "artifacts": {
    "hostname": "LAPTOP-HR-007",
    "agent_id": "wz-agent-00c4d5e6",
    "username": "CORP\\swright",
    "source_ip": "10.10.2.45",
    "destination_ip": "185.231.154.120",
    "destination_domain": "mega.nz",
    "destination_country": "NZ",
    "bytes_sent": 314572800,
    "protocol": "HTTPS",
    "port": 443,
    "file_names": ["employee_records_2026.xlsx", "payroll_q1_q2.csv", "hr_performance_reviews.docx"],
    "data_classification": "Confidential/PII",
    "attachment_size_bytes": 0,
    "recipient_email": null,
    "exfil_method": "cloud_upload",
    "session_duration_seconds": 847
  }
}
```

---

## Threat Score Formula

```
composite_score =
  (is_pending_termination == true ? 30 : 0)
  + (is_classified_data == true ? 20 : 0)
  + (dest_is_malicious == true ? 20 : 0)
  + (is_anomalous_volume == true ? 15 : 0)
  + (dest_high_risk_country == true ? 10 : 0)
  + (is_unapproved_cloud == true ? 10 : 0)
  + (account_expires_soon == true ? 10 : 0)
  + (m365_email_forwards > 0 ? 10 : 0)
  - (dest_is_malicious == false and dest_high_risk_country == false ? 5 : 0)
```

| Component | Weight | Notes |
|---|---|---|
| Pending termination HR signal | 30 points | Highest single weight in the suite |
| Classified data confirmed | 20 points | PII/PHI/PCI/Confidential/Restricted |
| Malicious destination (VT) | 20 points | Any VT malicious hit on destination |
| Anomalous volume (3× baseline) | 15 points | 3× the user's 30-day average |
| High-risk country destination | 10 points | CN/RU/KP/IR |
| Unapproved cloud service | 10 points | Not in approved domain list |
| Account expiring within 30 days | 10 points | Correlates with offboarding risk |
| Email forwarding rule created | 10 points | M365 audit log signal |
| Clean destination + low-risk country | -5 points | Reduces false positives |

**Threshold:** Score >= 70 → firewall block + M365 revocation.  
**Host isolation threshold:** Score >= 85 OR classified + malicious destination.

---

## Key Design Decisions

**Why HR signals carry the highest weight (30 points)?**  
The most dangerous insider threat is always the one who knows they are leaving. An employee on a PIP, under notice, or with a pending termination date has motivation, deadline pressure, and knowledge of what data is valuable. A 200MB transfer to Dropbox from a satisfied long-term employee is almost certainly a false positive. The same transfer from someone whose account expires in 5 days is a genuine emergency. The HR signal — stored in AD extensionAttribute3 by the HR system — is the single most predictive variable in the model.

**Why a 30-day behavioral baseline?**  
Transfer volume alone is meaningless without context. A data engineer who regularly exports 500MB datasets for analysis is normal. A sales coordinator who has never transferred more than 2MB suddenly sending 300MB is anomalous. The 3× threshold flags anything more than three times the user's own 30-day rolling average — personalizing the detection rather than applying a flat threshold to everyone.

**Why a separate host isolation threshold (85) vs. destination block (70)?**  
Isolating a laptop is disruptive — the user loses network access entirely, which affects productivity and may alert a malicious insider before the investigation is ready. Blocking the destination at the firewall is silent and reversible. The tiered threshold allows containment to start at 70 (quiet firewall block) and escalate to full isolation only when the evidence is high confidence (85+), giving the investigation team time to build a case before tipping off the subject.

**Why notify HR and Legal via Slack for insider threat signals?**  
Insider threat cases have legal and HR dimensions that pure security incidents do not. Confronting an employee about data theft without HR and Legal present creates employment law liability. The Slack notification to the HR liaison channel triggers that coordination immediately, before any analyst contacts the subject.

---

## AD Setup — HR Signal Integration

The HR system should write status flags to AD extensionAttribute3 for at-risk employees:

```powershell
# Flag pending termination
Set-ADUser -Identity "swright" -Replace @{extensionAttribute3="pending_termination"}

# Flag PIP (Performance Improvement Plan)
Set-ADUser -Identity "jdoe" -Replace @{extensionAttribute3="pip"}

# Flag resignation received
Set-ADUser -Identity "mbrown" -Replace @{extensionAttribute3="resignation"}
```

Approved cloud domains (whitelist) are configured in the Shuffle workflow variables:

```json
"APPROVED_CLOUD_DOMAINS": ["sharepoint.com", "onedrive.com", "drive.google.com", "box.com"]
```

---

## Deployment

### Environment Variables

Add to `.env`:

```bash
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
MAXMIND_LICENSE_KEY=your_accountid:your_licensekey
M365_TENANT_ID=your_tenant_id
M365_CLIENT_ID=your_client_id
M365_CLIENT_SECRET=your_secret
M365_AUDIT_TOKEN=your_audit_log_token
AD_DOMAIN_CONTROLLER=ldap://your-dc.corp.local
AD_BIND_USER=svc_shuffle@corp.local
AD_BIND_PASSWORD=your_service_account_password
CROWDSTRIKE_CLIENT_ID=your_client_id
CROWDSTRIKE_CLIENT_SECRET=your_client_secret
THEHIVE_API_KEY=your_key_here
THEHIVE_URL=http://thehive:9000
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
FIREWALL_API_URL=http://your-firewall-api
FIREWALL_API_KEY=your_key_here
WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_API_TOKEN=your_wazuh_jwt_token
```

### Add Wazuh Integration Block

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://shuffle-backend:5001/api/v1/hooks/webhook_prod_exfiltration_06</hook_url>
  <alert_format>json</alert_format>
  <level>12</level>
  <group>data_exfiltration,pb06</group>
</integration>
```

---

## Testing

```bash
curl -X POST http://localhost:5001/api/v1/hooks/webhook_prod_exfiltration_06 \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-pb06-001",
    "timestamp": "2026-06-25T16:44:03Z",
    "rule_id": "100051",
    "rule_name": "Bulk upload to unapproved file sharing service",
    "source": "ProxyLog",
    "artifacts": {
      "hostname": "TEST-HOST-01",
      "agent_id": "test-agent-001",
      "username": "CORP\\testuser",
      "source_ip": "10.10.2.45",
      "destination_ip": "185.231.154.120",
      "destination_domain": "mega.nz",
      "bytes_sent": 314572800,
      "protocol": "HTTPS",
      "port": 443,
      "file_names": ["employee_records.xlsx", "payroll.csv"],
      "data_classification": "Confidential/PII",
      "exfil_method": "cloud_upload",
      "session_duration_seconds": 847
    }
  }'
```

---

## Interview Talking Points

> "PB-06 handles data exfiltration and it's where the insider threat detection lives. The key architectural decision was integrating HR signals directly into the scoring model via an AD extensionAttribute that the HR system writes to for employees under a PIP, on notice, or pending termination. Pending termination carries 30 points — the highest single weight in the entire scoring formula — because a motivated insider with a deadline is a fundamentally different risk profile than an accidental policy violation. I also built a 30-day behavioral baseline query against the Wazuh API that computes each user's own average and maximum transfer volumes, so the anomaly threshold is personalized rather than flat. A data engineer who moves 500MB a day is normal — the same 500MB from a sales coordinator is a 3× anomaly. The containment uses a tiered approach: destination block at the firewall fires at score 70, which is silent and reversible, but host isolation is reserved for score 85 or confirmed classified data to a malicious destination — because isolating a laptop before Legal and HR are ready tips off the subject and creates employment law exposure."

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Subtechnique | Name |
|---|---|---|---|
| Exfiltration | T1048 | — | Exfiltration Over Alternative Protocol |
| Exfiltration | T1041 | — | Exfiltration Over C2 Channel |
| Exfiltration | T1567 | T1567.002 | Exfiltration to Cloud Storage |
| Exfiltration | T1052 | T1052.001 | Exfiltration Over Physical Medium: USB |
| Exfiltration | T1071 | T1071.004 | Application Layer Protocol: DNS |
| Collection | T1114 | T1114.003 | Email Collection: Email Forwarding Rule |

---

*Part of the Autonomous IR Pipeline — 10-playbook production SOAR project.*  
*Previous: [PB-05 — Impossible Travel](../pb05/) | Next: [PB-07 — Critical CVE Detection & Patch Ticketing](../pb07/)*
