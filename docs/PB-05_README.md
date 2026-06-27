# PB-05 | Impossible Travel & Suspicious Login Detection

**Playbook ID:** PB-05  
**Severity:** High  
**MITRE ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts) · T1090.003 (Multi-hop Proxy: Tor) · T1110.004 (Credential Stuffing) · T1078 (Valid Accounts)  
**Stack:** Wazuh · Azure AD Identity Protection · Shuffle · MaxMind GeoIP · AbuseIPDB · Active Directory · Microsoft Graph API · TheHive · Slack

---

## Engineering Impact

Impossible travel is one of the highest-fidelity identity compromise signals available — if an account authenticates from Toronto at 9:00 AM and from Singapore at 10:30 AM, either the user is on a commercial aircraft traveling at 7,400 km/h or the account is compromised. The challenge is not the logic — it is building the enrichment pipeline that calculates travel velocity reliably and suppresses false positives for legitimate frequent travelers.

This playbook uses the **haversine formula** to calculate geodesic distance between sequential login coordinates, divides by the time delta to get required travel speed in km/h, and flags anything above 900 km/h (commercial aircraft cruising speed) as physically impossible. It also pulls a `frequent_traveler` flag from AD extensionAttributes to subtract score for known business travelers.

| Metric | Before | After |
|---|---|---|
| Triage time per impossible travel alert | 20–30 min manual geo-lookup | < 5 seconds automated |
| Session revocation on confirmed compromise | 15–45 min (helpdesk ticket) | < 5 seconds (Graph API) |
| False positive rate for frequent travelers | High (all travel flagged) | Reduced — frequent traveler flag subtracts 15 score points |
| User notification | Manual (analyst calls user) | Automated out-of-band email — doubles as compromise confirmation |

---

## Architecture

```
[ Wazuh Auth Monitor + Azure AD Identity Protection ]
Rule IDs: 100040–100045
          │
          ▼ (JSON webhook POST)
    [ Shuffle SOAR ]
    webhook_prod_impossible_travel_05
          │
    [ Tor / Anonymizer Zero-Tolerance Gate ]
    is_tor == true → immediate session revocation
          │
    ┌─────┴────────────────────────────────────────────┐
    ▼                  ▼               ▼                ▼
[ GeoIP Current ]  [ GeoIP Prev ]  [ AbuseIPDB ]  [ AD Context ]
Coordinates +      Coordinates of  IP reputation   Privilege level
ASN + hosting      previous login  + usage type    + traveler flag
    │                  │
    └──────────────────┘
              │
    [ Haversine Velocity Calc ]
    distance_km / time_delta_hours = required_speed_kmh
    > 900 km/h = impossible
              │
    [ Composite Score Engine ]
    impossible travel (35) + IP abuse (×0.25)
    + hosting provider (10) + anon VPN (10)
    + new device (10) + privileged (10)
    + Azure AD risk level (10-20)
    - frequent traveler (-15)
              │
    ┌─────────┴─────────┐
 Score >= 65         Score < 65
    │                    │
    ▼              [ Escalate to Analyst ]
[ Revoke All Sessions ]
    │
    ├── MFA Step-Up Enforced
    └── User Notified via Email
              │
    [ TheHive Case + Analyst Checklist ]
    [ Slack SOC Alert ]
```

---

## File Structure

```
├── wazuh/
│   └── rules/
│       └── pb05_impossible_travel_rules.xml   # Detection rules (IDs 100040–100045)
├── shuffle/
│   └── pb05_impossible_travel_playbook.json   # Full Shuffle workflow export
└── docs/
    └── PB-05_README.md                        # This file
```

---

## Detection Rules

| Rule ID | Level | Trigger | Description |
|---|---|---|---|
| 100040 | 14 | Same account, different country, within 2 hours | Classic impossible travel — two-country auth within window |
| 100041 | 12 | 4624 + non-home country + 00:00–06:00 | Off-hours foreign login — outside business hours anomaly |
| 100042 | 14 | 4624 + `is_tor == true` | Successful login via Tor exit node |
| 100043 | 13 | Azure AD risky sign-in event type | Identity Protection risky sign-in forwarded to Wazuh |
| 100044 | 11 | `event_subtype == newDevice` | First-time device ID for this user account |
| 100045 | 12 | VPN auth success + non-home country | VPN authentication from unexpected geography |

---

## Workflow Nodes

| Node | Type | Action |
|---|---|---|
| node_01_webhook | Trigger | Receives Wazuh/Azure AD auth anomaly payload |
| node_02_extract | Parse | Normalizes fields, flags Tor for fast-track |
| node_03_tor_gate | Condition | Tor logins bypass enrichment → immediate revocation |
| node_04_geoip_current | Enrichment | MaxMind — current IP coordinates + ASN + hosting flag |
| node_05_geoip_previous | Enrichment | MaxMind — previous IP coordinates for velocity calc |
| node_06_abuseipdb | Enrichment | AbuseIPDB — source IP reputation + usage type |
| node_07_ad_context | Enrichment | AD user privilege, VIP flag, frequent traveler attribute |
| node_08_velocity_calc | Calculate | Haversine distance + time delta → required speed km/h |
| node_08b_score | Calculate | Composite threat score (0–100) |
| node_08c_decision | Condition | Routes on score >= 65 |
| node_09_revoke_sessions | Containment | Azure AD — revoke all active sessions and refresh tokens |
| node_10_require_mfa | Containment | Azure AD — force MFA on next sign-in attempt |
| node_11_notify_user | Notify | M365 — out-of-band email to account owner |
| node_12_escalate | Case Mgmt | TheHive identity incident case with velocity analysis |
| node_13_notify | Notify | Slack SOC alert — impossible travel flag |

---

## Alert Payload Schema

```json
{
  "alert_id": "geo-005-f3a1c8",
  "timestamp": "2026-06-25T10:32:00Z",
  "rule_id": "100040",
  "rule_name": "Impossible travel — same account from two countries within 2 hours",
  "source": "AzureAD",
  "artifacts": {
    "username": "jdoe",
    "upn": "jdoe@yourorg.com",
    "source_ip": "202.94.1.48",
    "previous_ip": "76.68.132.22",
    "current_login_time": "2026-06-25T10:32:00Z",
    "previous_login_time": "2026-06-25T09:01:00Z",
    "device_id": "device-unknown-9f3b2a",
    "is_new_device": true,
    "is_tor": false,
    "risk_level": "high",
    "risk_detail": "unfamiliarFeatures",
    "application": "Microsoft Teams",
    "country_code": "SG"
  }
}
```

---

## Threat Score Formula

```
composite_score =
  (is_impossible_travel == true ? 35 : 0)
  + (ip_abuse_score × 0.25)
  + (current_is_hosting == true ? 10 : 0)
  + (current_is_vpn == true ? 10 : 0)
  + (is_new_device == true ? 10 : 0)
  + (is_privileged == true ? 10 : 0)
  + (risk_level == 'high' ? 20 : risk_level == 'medium' ? 10 : 0)
  - (is_frequent_traveler == true ? 15 : 0)
```

| Component | Weight | Notes |
|---|---|---|
| Impossible travel confirmed | 35 points | Haversine calc > 900 km/h |
| IP abuse score | ×0.25 | AbuseIPDB 0–100 |
| Hosting provider IP | 10 points | VPS/cloud provider = likely attacker infra |
| Anonymous VPN IP | 10 points | MaxMind VPN flag |
| New/unrecognized device | 10 points | First-time device ID for this user |
| Privileged account | 10 points | Domain Admin / Global Admin |
| Azure AD risk level | 10–20 points | Microsoft Identity Protection signal |
| Frequent traveler (subtract) | -15 points | Known business traveler — reduces false positive rate |

**Threshold:** Score >= 65 → session revocation + MFA step-up.  
**Tor fast-track:** `is_tor == true` bypasses scoring → immediate revocation.

---

## Key Design Decisions

**Why the haversine formula instead of simple country mismatch?**  
Country mismatch alone creates too many false positives. A user who legitimately travels to the US for a day trip would trigger every time. The haversine calculation gives a precise km/h figure — 7,400 km/h between Toronto and Singapore in 90 minutes is definitively impossible. 850 km/h between Toronto and New York in 2 hours is plausible (it's a 1-hour flight). The velocity number also appears in the TheHive case and the Slack notification, which makes the alert immediately intuitive to the analyst.

**Why notify the user out-of-band?**  
The user email notification does two things. First, it respects the legitimate user experience — if this is a false positive, they get an immediate heads-up and can call the helpdesk. Second, it acts as a passive compromise confirmation: if the account owner calls the SOC to say "I didn't travel to Singapore," that confirms the compromise without the analyst having to track them down.

**Why the frequent traveler flag?**  
Executives and sales staff who travel internationally trigger impossible travel alerts constantly. Suppressing those alerts entirely creates blind spots. A -15 score adjustment means their alerts still fire and still get enriched, but they route to analyst review instead of automatic revocation unless a genuinely high-risk signal accompanies the travel (Tor exit node, high abuse score IP, privileged account).

**Why MFA step-up instead of account disable?**  
Unlike PB-02 (brute force) and PB-03 (ransomware) where disabling the account is appropriate, impossible travel might be a false positive. MFA step-up is a less disruptive containment action — the legitimate user can complete MFA and regain access immediately, while an attacker who stole credentials cannot.

---

## Deployment

### Environment Variables

Add to `.env`:

```bash
ABUSEIPDB_API_KEY=your_key_here
MAXMIND_LICENSE_KEY=your_accountid:your_licensekey
M365_TENANT_ID=your_tenant_id
M365_CLIENT_ID=your_client_id
M365_CLIENT_SECRET=your_secret
AD_DOMAIN_CONTROLLER=ldap://your-dc.corp.local
AD_BIND_USER=svc_shuffle@corp.local
AD_BIND_PASSWORD=your_service_account_password
THEHIVE_API_KEY=your_key_here
THEHIVE_URL=http://thehive:9000
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

### Mark Frequent Travelers in Active Directory

Set extensionAttribute2 for known business travelers to prevent false positive revocations:

```powershell
Set-ADUser -Identity "jdoe" -Replace @{extensionAttribute2="frequent_traveler"}
```

### Add Wazuh Integration Block

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://shuffle-backend:5001/api/v1/hooks/webhook_prod_impossible_travel_05</hook_url>
  <alert_format>json</alert_format>
  <level>11</level>
  <group>impossible_travel,pb05</group>
</integration>
```

---

## Testing

```bash
curl -X POST http://localhost:5001/api/v1/hooks/webhook_prod_impossible_travel_05 \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-pb05-001",
    "timestamp": "2026-06-25T10:32:00Z",
    "rule_id": "100040",
    "rule_name": "Impossible travel detected",
    "source": "AzureAD",
    "artifacts": {
      "username": "testuser",
      "upn": "testuser@yourorg.com",
      "source_ip": "202.94.1.48",
      "previous_ip": "76.68.132.22",
      "current_login_time": "2026-06-25T10:32:00Z",
      "previous_login_time": "2026-06-25T09:01:00Z",
      "device_id": "device-unknown-9f3b2a",
      "is_new_device": true,
      "is_tor": false,
      "risk_level": "high",
      "risk_detail": "unfamiliarFeatures",
      "application": "Microsoft Teams",
      "country_code": "SG"
    }
  }'
```

**Expected behavior:** GeoIP resolves both IPs. Velocity calc fires — Toronto to Singapore in 91 minutes = ~8,100 km/h, flagged as impossible. Score calculated. Sessions revoked. MFA enforced. User notified via email. TheHive case created with full velocity analysis.

---

## Interview Talking Points

> "PB-05 is the identity playbook — it handles impossible travel and geo-anomaly logins. The core of it is a haversine calculation that computes the geodesic distance between the previous login coordinates and the current login coordinates, divides by the time delta between logins, and flags it as impossible if the required speed exceeds 900 km/h — commercial aircraft cruising speed. That gives you a precise number in the Slack alert and the TheHive case: 'this account would have needed to travel at 7,400 km/h to make this login legitimate.' I also built in a frequent traveler flag in AD extensionAttribute2 that subtracts 15 points from the composite score — that way executives and sales staff who travel internationally still get their logins enriched and reviewed, but they don't trigger automatic session revocation every time they land in a new country. The containment is MFA step-up rather than account disable, which is a deliberate decision — impossible travel has a higher false positive rate than ransomware or brute force, so the less disruptive containment makes more sense. The user notification email also doubles as a passive compromise confirmation: if the account owner calls to say they didn't travel, you've confirmed the compromise without hunting them down."

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Subtechnique | Name |
|---|---|---|---|
| Initial Access | T1078 | T1078.004 | Valid Accounts: Cloud Accounts |
| Defense Evasion | T1090 | T1090.003 | Proxy: Multi-hop Proxy (Tor) |
| Credential Access | T1110 | T1110.004 | Brute Force: Credential Stuffing |
| Persistence | T1078 | — | Valid Accounts |

---

*Part of the Autonomous IR Pipeline — 10-playbook production SOAR project.*  
*Previous: [PB-04 — Malware Hash Enrichment & Quarantine](../pb04/) | Next: [PB-06 — Data Exfiltration Alert Triage](../pb06/)*
