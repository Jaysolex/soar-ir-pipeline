# PB-07 | Critical CVE Detection & Automated Patch Ticketing

**Playbook ID:** PB-07  
**Severity:** High / Critical  
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application) · T1068 (Exploitation for Privilege Escalation) · T1210 (Exploitation of Remote Services)  
**Stack:** Wazuh · Tenable.io · Shuffle · NVD API · CISA KEV API · Jira · TheHive · Slack

---

## Engineering Impact

Vulnerability management is where most security programs fail at scale. Scanners produce thousands of findings per week. Without automated triage and prioritization, teams default to chasing CVSS score order — which means fixing a CVSS 9.8 vulnerability on an internal developer laptop before a CVSS 7.2 vulnerability on an internet-facing web server that's already in the CISA Known Exploited Vulnerabilities catalog. That is the wrong order.

PB-07 solves this by building a **Vulnerability Priority Rating (VPR)** that combines CVSS score, CISA KEV confirmation, network exposure, host criticality (Tenable ACR score), and ransomware use flags into a single 0–100 score. The Jira ticket is created automatically with full context, correct SLA deadline, and the right assignee — without an analyst spending 30 minutes copying data between systems.

| Metric | Before | After |
|---|---|---|
| Time from scan finding to Jira ticket | 30–60 min manual triage | < 10 seconds automated |
| CVSS-only prioritization | Blind to exploitability context | VPR combines 6 signals |
| CISA KEV visibility | Separate manual lookup | Real-time API check |
| Duplicate ticket prevention | None — scan cycles create duplicates | Jira search before creation |
| TheHive case for KEV CVEs | Manual | Automatic — only for KEV + critical exposure |

---

## Architecture

```
[ Tenable / Nessus / OpenVAS + WSUS/SCCM ]
Rule IDs: 100060–100065
          │
          ▼ (JSON webhook POST)
    [ Shuffle SOAR ]
    webhook_prod_cve_07
          │
    [ Artifact Extraction ]
    CVSS score → initial priority
    SLA deadline calculation
          │
    ┌─────┴──────────────┬─────────────────┐
    ▼                    ▼                 ▼
[ NVD API ]        [ CISA KEV API ]  [ Tenable Asset ]
Full CVE detail    KEV confirmation   Host ACR score
CVSS v3 vector     Ransomware use     Open vuln count
CWE classification Required action    Asset tags
          │                │                 │
          └────────────────┴─────────────────┘
                           │
               [ Exposure Assessment ]
               Internet-facing + network
               exploitable + critical infra
                           │
               [ VPR Score Calculation ]
               CVSS(×5) + KEV(25) + internet(20)
               + critical infra(15) + network(10)
               + ransomware(10) + SLA breach(10)
                           │
               [ Jira Duplicate Check ]
               Search open tickets first
                           │
               ┌───────────┴───────────┐
          No duplicate            Duplicate exists
               │                       │
    [ Create Jira Ticket ]    [ Update Existing Ticket ]
    Full CVE context           Add scan update comment
    SLA due date               Re-evaluate priority
    Correct assignee
               │
    [ TheHive Case — KEV + Critical Exposure Only ]
    [ Slack Vuln Channel Alert ]
```

---

## File Structure

```
├── wazuh/
│   └── rules/
│       └── pb07_cve_rules.xml          # Detection rules (IDs 100060–100065)
├── shuffle/
│   └── pb07_cve_playbook.json          # Full Shuffle workflow export
└── docs/
    └── PB-07_README.md                 # This file
```

---

## Detection Rules

| Rule ID | Level | Trigger | Description |
|---|---|---|---|
| 100060 | 13 | Scanner + CVSS 9.0–10.0 | Critical severity vulnerability detected |
| 100061 | 12 | Scanner + CVSS 7.0–8.9 + critical host | High severity on internet-facing or DC/DB server |
| 100062 | 15 | CVE ID + `in_cisa_kev == true` | CISA KEV confirmed — active exploitation in the wild |
| 100063 | 12 | Scanner + CVSS 7.0+ + 30+ days unpatched | SLA breach risk — high/critical unpatched for 30+ days |
| 100064 | 14 | RCE/privesc/auth bypass/SQLi + CVSS 7.0+ | High-impact vulnerability class |
| 100065 | 11 | WSUS/SCCM — patch missing or failed | Critical/Important Windows patch not applied |

---

## Workflow Nodes

| Node | Type | Action |
|---|---|---|
| node_01_webhook | Trigger | Receives scanner or patch management alert |
| node_02_extract | Parse | Normalizes fields, calculates initial priority and SLA |
| node_03_nvd_lookup | Enrichment | NVD API — full CVE description, CVSS v3.1 vector, CWE |
| node_04_cisa_kev | Enrichment | CISA KEV API — active exploitation confirmation + ransomware flag |
| node_05_host_context | Enrichment | Tenable API — asset criticality score, open vuln count |
| node_06_exposure_check | Calculate | Internet-facing + network exploitable + critical infra flags |
| node_07_priority_score | Calculate | VPR score (0–100) + final priority tier + SLA deadline |
| node_08_duplicate_check | Query | Jira JQL search — existing open ticket for this CVE + host |
| node_09_ticket_decision | Condition | Create new vs. update existing |
| node_10_create_jira | Action | Jira — create ticket with full context, SLA, assignee |
| node_10b_update_jira | Action | Jira — add comment to existing ticket with updated scan data |
| node_11_thehive_kev | Conditional Action | TheHive — case for KEV CVEs and CVSS 9.0+ internet-facing only |
| node_12_notify | Notify | Slack vuln channel — priority-colored alert |

---

## Alert Payload Schema

```json
{
  "alert_id": "vuln-007-b1c3e5",
  "timestamp": "2026-06-25T08:15:00Z",
  "rule_id": "100062",
  "rule_name": "CVE in CISA Known Exploited Vulnerabilities catalog",
  "source": "Tenable",
  "artifacts": {
    "cve_id": "CVE-2024-21413",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "vulnerability_name": "Microsoft Outlook Remote Code Execution Vulnerability",
    "vulnerability_type": "Remote Code Execution",
    "affected_hostname": "MAIL-SERVER-01",
    "affected_ip": "10.0.1.25",
    "affected_os": "Windows Server 2019",
    "affected_software": "Microsoft Outlook",
    "affected_version": "16.0.17126.20132",
    "host_classification": "internet_facing",
    "days_since_discovery": 0,
    "in_cisa_kev": true,
    "patch_available": true,
    "patch_kb": "KB5034765",
    "plugin_id": "210847"
  }
}
```

---

## VPR Score Formula

```
vpr_score =
  (cvss_score × 5)
  + (kev_confirmed == true ? 25 : 0)
  + (is_internet_facing == true ? 20 : 0)
  + (is_critical_infrastructure == true ? 15 : 0)
  + (is_network_exploitable == true ? 10 : 0)
  + (kev_ransomware_use == 'Known' ? 10 : 0)
  + (days_since_discovery >= 30 ? 10 : 0)
```

| Component | Weight | Notes |
|---|---|---|
| CVSS base score | ×5 (max 50) | Foundation of the score |
| CISA KEV confirmed | +25 | Active exploitation confirmed in the wild |
| Internet-facing host | +20 | Direct network reachability from internet |
| Critical infrastructure | +15 | DC, DB server, backup server |
| Network exploitable (no auth) | +10 | AV:N + PR:N in CVSS vector |
| Known ransomware campaign use | +10 | CISA KEV ransomware flag |
| 30+ days unpatched | +10 | SLA breach risk escalation |

**Priority tiers and SLA deadlines:**

| VPR Score | Priority | SLA (Days) | Notes |
|---|---|---|---|
| 90–100 | P1-Critical | 3 days | CISA KEV + internet-facing = emergency |
| 70–89 | P2-High | 7 days | Critical CVSS or KEV on internal host |
| 50–69 | P3-Medium | 30 days | High CVSS, standard exposure |
| < 50 | P4-Low | 90 days | Low exploitability, internal only |

---

## Key Design Decisions

**Why VPR instead of CVSS alone?**  
CVSS measures the intrinsic severity of a vulnerability in isolation — it does not account for whether the affected host is internet-facing, whether the CVE is actively being exploited in ransomware campaigns, or whether the host is a domain controller vs. a developer workstation. A CVSS 9.8 vulnerability on an air-gapped internal test server is less urgent than a CVSS 7.5 vulnerability on an internet-facing web application that appears in the CISA KEV catalog. VPR incorporates all of those signals.

**Why the CISA KEV API instead of just using the scanner's KEV flag?**  
Scanner KEV flags lag behind the CISA catalog by days to weeks depending on plugin update cycles. Querying the live CISA KEV JSON feed directly gives you the most current catalog, the exact required action text, the CISA-mandated due date, and the ransomware use flag — none of which appear in the scanner's KEV checkbox.

**Why check for duplicate Jira tickets before creating?**  
Vulnerability scanners run on cycles — daily, weekly, or continuous. Without a duplicate check, every scan cycle that finds the same unpatched CVE creates a new Jira ticket. A host with 50 open vulnerabilities scanned weekly generates 200+ tickets per month. The Jira JQL search before creation ensures each CVE-host combination has exactly one active ticket, with scan updates added as comments.

**Why only create TheHive cases for KEV CVEs and critical-exposure CVEs?**  
TheHive is the incident response platform — it is for events that require active investigation and remediation coordination. A CVSS 8.0 vulnerability on an internal workstation is a vulnerability management task, not an incident. Reserving TheHive for KEV confirmations and CVSS 9.0+ on internet-facing hosts keeps the incident queue clean and ensures those critical cases get IR-level attention rather than getting lost in a backlog of routine patch tickets.

---

## Deployment

### Environment Variables

Add to `.env`:

```bash
NVD_API_KEY=your_nvd_api_key
TENABLE_ACCESS_KEY=your_tenable_access_key
TENABLE_SECRET_KEY=your_tenable_secret_key
JIRA_URL=https://yourorg.atlassian.net
JIRA_API_TOKEN=your_jira_api_token
JIRA_PROJECT_KEY=VULN
JIRA_VULN_ASSIGNEE_CRITICAL=jira_accountid_for_critical
JIRA_VULN_ASSIGNEE_HIGH=jira_accountid_for_high
THEHIVE_API_KEY=your_key_here
THEHIVE_URL=http://thehive:9000
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_VULN_CHANNEL=#vuln-management
AD_DOMAIN_CONTROLLER=ldap://your-dc.corp.local
AD_BIND_USER=svc_shuffle@corp.local
AD_BIND_PASSWORD=your_service_account_password
```

### Add Wazuh Integration Block

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://shuffle-backend:5001/api/v1/hooks/webhook_prod_cve_07</hook_url>
  <alert_format>json</alert_format>
  <level>11</level>
  <group>vulnerability,pb07</group>
</integration>
```

### Configure Tenable Webhook

In Tenable.io, navigate to **Settings → Integrations → Webhooks** and add:

```
URL: http://shuffle-backend:5001/api/v1/hooks/webhook_prod_cve_07
Events: plugin_fired, scan_completed
Filter: severity = Critical OR (severity = High AND asset_tag = internet_facing)
```

---

## Testing

```bash
curl -X POST http://localhost:5001/api/v1/hooks/webhook_prod_cve_07 \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-pb07-001",
    "timestamp": "2026-06-25T08:15:00Z",
    "rule_id": "100062",
    "rule_name": "CVE in CISA Known Exploited Vulnerabilities catalog",
    "source": "Tenable",
    "artifacts": {
      "cve_id": "CVE-2024-21413",
      "cvss_score": 9.8,
      "vulnerability_name": "Microsoft Outlook RCE",
      "vulnerability_type": "Remote Code Execution",
      "affected_hostname": "MAIL-SERVER-01",
      "affected_ip": "10.0.1.25",
      "affected_os": "Windows Server 2019",
      "affected_software": "Microsoft Outlook",
      "affected_version": "16.0.17126.20132",
      "host_classification": "internet_facing",
      "days_since_discovery": 0,
      "in_cisa_kev": true,
      "patch_available": true,
      "patch_kb": "KB5034765"
    }
  }'
```

**Expected behavior:** NVD API pulls full CVE description and CVSS vector. CISA KEV API confirms active exploitation + ransomware flag. Tenable asset API returns ACR score. VPR calculated — CVSS 9.8(49) + KEV(25) + internet-facing(20) = VPR 94 → P1-Critical, 3-day SLA. Jira duplicate check runs. New ticket created with full context and assigned to critical queue. TheHive case created. Slack vuln channel alerted in red.

---

## Interview Talking Points

> "PB-07 is the vulnerability management playbook and it's where I built a custom Vulnerability Priority Rating score that goes beyond raw CVSS. The core insight is that CVSS measures intrinsic severity — it doesn't know whether the host is internet-facing, whether the CVE is actively being used in ransomware campaigns, or whether the host is a domain controller. So I pull three parallel enrichment sources: the NVD API for full CVE technical detail including the CVSS v3.1 attack vector components, the live CISA KEV JSON feed for active exploitation confirmation and the ransomware use flag, and the Tenable asset API for the host's Asset Criticality Rating score. Those signals combine into a VPR that drives both the Jira ticket priority and the SLA deadline — CISA KEV CVEs on internet-facing hosts get a 3-day SLA, not the standard 7-day critical window. I also built a Jira duplicate check that runs before every ticket creation — without it, a daily scanner cycle creates a new ticket every 24 hours for the same unpatched CVE and the queue becomes unmanageable."

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Name |
|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation |
| Lateral Movement | T1210 | Exploitation of Remote Services |

---

*Part of the Autonomous IR Pipeline — 10-playbook production SOAR project.*  
*Previous: [PB-06 — Data Exfiltration Triage](../pb06/) | Next: [PB-08 — C2 Beaconing & Outbound Block](../pb08/)*
