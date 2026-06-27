# PB-02 | Brute Force Detection & Automated Account Lockout

**Playbook ID:** PB-02  
**Severity:** Critical  
**MITRE ATT&CK:** T1110.001 (Password Guessing) · T1110.003 (Password Spraying) · T1110.004 (Credential Stuffing) · T1078 (Valid Accounts)  
**Stack:** Wazuh · Shuffle · AbuseIPDB · MaxMind GeoIP · Active Directory · Azure AD · Firewall API · TheHive · Slack

---

## Engineering Impact

Brute force and credential stuffing attacks are high-volume, low-signal events that create alert fatigue at the Tier 1 level. The challenge is not detection — Wazuh fires reliably on failed login counts — the challenge is triage speed and false positive suppression. An analyst manually checking whether a lockout is a real attack or a user mistyping their password wastes 15–30 minutes per event.

This playbook eliminates that triage window by enriching every alert with IP abuse reputation, geographic anomaly scoring, and AD privilege context before a human ever sees it. High-confidence attacks get contained automatically — account disabled, sessions revoked, IP blocked — in under 5 seconds.

| Metric | Before | After |
|---|---|---|
| Mean Time to Detect (MTTD) | 5–10 min (analyst queue) | < 3 seconds (async webhook) |
| Mean Time to Contain (MTTC) | 20–45 min (manual AD disable) | < 5 seconds (automated lockout) |
| False positive escalations | High (every lockout paged out) | Suppressed below score threshold |
| Analyst re-enable required | N/A | Always — no auto-unlock |

---

## Architecture

```
[ Windows Domain Controller / VPN / Web App ]
          │
          ▼ (Windows Event IDs 4625, 4624, 4740)
    [ Wazuh SIEM ]
    Rule IDs: 100010–100015
    Level >= 10 → fires integration block
          │
          ▼ (JSON webhook POST)
    [ Shuffle SOAR ]
    webhook_prod_bruteforce_02
          │
    ┌─────┴──────────────────────┐─────────────────────┐
    ▼                            ▼                     ▼
[ AbuseIPDB ]            [ MaxMind GeoIP ]     [ Active Directory ]
IP abuse score           Country resolution     Account privilege context
    │                            │                     │
    └────────────────────────────┴─────────────────────┘
                                 │
                    [ Composite Score Engine ]
             (IP abuse × 0.35) + (geo anomaly × 25)
             + (fail count weight) + (privilege bonus)
             + (success after fail bonus)
                                 │
               ┌─────────────────┴─────────────────┐
          Score >= 70 OR                       Score < 70
          success_after_fail == true                │
               │                         [ Escalate to Analyst ]
    [ Automated Containment ]             TheHive case created
    ├── Disable AD account                Full enrichment attached
    ├── Block source IP (24hr TTL)        Slack notification sent
    └── Revoke Azure AD sessions
```

---

## File Structure

```
├── wazuh/
│   └── rules/
│       └── pb02_bruteforce_rules.xml    # Detection rules (IDs 100010–100015)
├── shuffle/
│   └── pb02_bruteforce_playbook.json    # Full Shuffle workflow export
└── docs/
    └── PB-02_README.md                  # This file
```

---

## Detection Rules

| Rule ID | Level | Trigger | Description |
|---|---|---|---|
| 100010 | 10 | 5 failures / 60s same IP | Classic brute force from single source |
| 100011 | 12 | 10 failures / 120s same account | Password spray — multiple sources, one target |
| 100012 | 14 | Brute force + EventID 4624 | Credential stuffing — failure then success |
| 100013 | 13 | 4624 + non-home country GeoIP | Successful login from anomalous geography |
| 100014 | 15 | 3 failures / 60s admin account | Privileged account targeted |
| 100015 | 10 | EventID 4740 | Windows account lockout fired |

---

## Workflow Nodes

| Node | Type | Action |
|---|---|---|
| node_01_webhook | Trigger | Receives Wazuh JSON payload |
| node_02_extract | Parse | Normalizes alert fields to pipeline variables |
| node_03_abuseipdb | Enrichment | Source IP abuse confidence score |
| node_04_geoip | Enrichment | MaxMind country resolution + anomaly flag |
| node_05_ad_lookup | Enrichment | AD account privilege and group context |
| node_06_score | Calculate | Composite threat score (0–100) |
| node_07_decision | Condition | Routes on score >= 70 OR credential stuffing confirmed |
| node_08_lockout_account | Containment | AD account disable — preserves audit trail |
| node_09_block_ip | Containment | Firewall block source IP (24hr TTL) |
| node_10_revoke_sessions | Containment | Azure AD — revoke all active OAuth tokens |
| node_11_escalate | Case Mgmt | TheHive enriched case — both branches |
| node_12_notify | Notify | Slack SOC channel alert card |

---

## Alert Payload Schema

```json
{
  "alert_id": "bf-002-a91c3d",
  "timestamp": "2026-06-25T03:14:22Z",
  "rule_id": "100012",
  "rule_name": "Credential stuffing suspected — brute force immediately followed by successful login",
  "severity": "High",
  "artifacts": {
    "source_ip": "45.142.212.100",
    "target_username": "jsmith",
    "target_hostname": "CORP-DC01",
    "failed_count": 47,
    "success_after_fail": true,
    "event_id": "4624",
    "country_code": "RU"
  }
}
```

---

## Threat Score Formula

```
composite_score =
  (ip_abuse_score × 0.35)
  + (geo_is_anomalous == true ? 25 : 0)
  + (failed_count >= 20 ? 20 : failed_count >= 10 ? 12 : 6)
  + (is_privileged == true ? 15 : 0)
  + (success_after_fail == true ? 20 : 0)
```

| Component | Weight | Notes |
|---|---|---|
| AbuseIPDB confidence score | 35% | Raw 0–100 score |
| Geographic anomaly | 25 points | Binary — non-home country = +25 |
| Failed login count | 6–20 points | Tiered: 5+ = 6, 10+ = 12, 20+ = 20 |
| Privileged account target | 15 points | Domain Admins, Enterprise Admins |
| Success after brute force | 20 points | Credential stuffing confirmation |

**Threshold:** Score >= 70 → automated containment. Always triggered if `success_after_fail == true` regardless of score.

**Important:** Account re-enable is never automated. Analyst sign-off required before account is restored — prevents attacker from relying on the automation to cycle lockouts.

---

## Key Design Decisions

**Why disable instead of just lock?**  
Windows account lockout (4740) resets automatically after the lockout duration. An attacker running a slow spray at threshold pace can wait it out. AD `disable` requires manual re-enable — harder to bypass.

**Why 24-hour TTL on IP block instead of permanent?**  
Attacker IPs rotate. A permanent block on a Tor exit node or cloud VPS has diminishing returns and creates management overhead. 24 hours disrupts the active campaign; analyst reviews and extends if needed.

**Why revoke Azure AD sessions?**  
If credential stuffing succeeded and the attacker already has a valid session token, disabling the AD account alone does not terminate the active session. Revoking OAuth tokens closes that persistence gap.

---

## Deployment

### Prerequisites
- Docker Engine v20.10+
- Docker Compose v2.20+
- Minimum 8GB RAM
- API keys: AbuseIPDB, MaxMind GeoIP (license key), Active Directory bind credentials, Azure AD app registration, TheHive, Slack, Firewall API

### Environment Variables

Add to `.env`:

```bash
ABUSEIPDB_API_KEY=your_key_here
MAXMIND_LICENSE_KEY=your_accountid:your_licensekey
AD_DOMAIN_CONTROLLER=ldap://your-dc.corp.local
AD_BIND_USER=svc_shuffle@corp.local
AD_BIND_PASSWORD=your_service_account_password
M365_TENANT_ID=your_tenant_id
M365_CLIENT_ID=your_client_id
M365_CLIENT_SECRET=your_secret
THEHIVE_API_KEY=your_key_here
THEHIVE_URL=http://thehive:9000
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
FIREWALL_API_URL=http://your-firewall-api
FIREWALL_API_KEY=your_key_here
```

### Import Playbook

1. Access Shuffle at `http://localhost:5001`
2. Navigate to **Workflows → Import**
3. Upload `shuffle/pb02_bruteforce_playbook.json`
4. Map secrets in the workflow variable panel
5. Activate the webhook trigger

### Add Wazuh Integration Block

Append to your production `ossec.conf`:

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://shuffle-backend:5001/api/v1/hooks/webhook_prod_bruteforce_02</hook_url>
  <alert_format>json</alert_format>
  <level>10</level>
  <group>brute_force,pb02</group>
</integration>
```

---

## Testing

### Simulate brute force alert:

```bash
curl -X POST http://localhost:5001/api/v1/hooks/webhook_prod_bruteforce_02 \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-pb02-001",
    "timestamp": "2026-06-25T03:14:22Z",
    "rule_id": "100012",
    "rule_name": "Credential stuffing suspected",
    "severity": "High",
    "artifacts": {
      "source_ip": "45.142.212.100",
      "target_username": "testuser",
      "target_hostname": "CORP-DC01",
      "failed_count": 47,
      "success_after_fail": true,
      "event_id": "4624",
      "country_code": "RU"
    }
  }'
```

**Expected behavior:** AbuseIPDB and GeoIP enrichment fires in parallel. AD lookup returns account context. Score calculated. Because `success_after_fail == true`, containment triggers regardless of score. Account disabled, IP blocked, sessions revoked. TheHive case created. Slack alert delivered.

---

## Interview Talking Points

> "PB-02 handles brute force and credential stuffing. The key engineering decision was the dual routing condition — the playbook contains automatically if the composite score clears 70, but it also hard-routes to containment if it detects a successful login immediately after a brute force sequence, regardless of score. That pattern is the signature of credential stuffing — automated tooling that found a valid password. I also built in a geo-anomaly check using MaxMind GeoIP against a home country variable, which adds 25 points to the score if the source IP resolves outside Canada. One important design decision: account re-enable is never automated. The AD disable requires analyst sign-off before the account comes back — if an attacker is running a slow spray at just below the lockout threshold, you don't want the automation unlocking the account on a timer."

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Subtechnique | Name |
|---|---|---|---|
| Credential Access | T1110 | T1110.001 | Brute Force: Password Guessing |
| Credential Access | T1110 | T1110.003 | Brute Force: Password Spraying |
| Credential Access | T1110 | T1110.004 | Brute Force: Credential Stuffing |
| Defense Evasion | T1078 | — | Valid Accounts |

---

*Part of the Autonomous IR Pipeline — 10-playbook production SOAR project.*  
*Previous: [PB-01 — Phishing Triage & Containment](../pb01/) | Next: [PB-03 — Ransomware Detection & Host Isolation](../pb03/)*
