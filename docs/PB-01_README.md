# PB-01 | Phishing Triage & Automated Containment

**Playbook ID:** PB-01  
**Severity:** Critical  
**MITRE ATT&CK:** T1566.001 (Spearphishing Attachment) · T1566.002 (Spearphishing Link)  
**Stack:** Wazuh · Shuffle · VirusTotal · AbuseIPDB · CrowdStrike Falcon · Microsoft 365 · TheHive · Slack

---

## Engineering Impact

Manual phishing triage scales linearly with headcount — every reported email requires an analyst to extract headers, query threat intel, check AD, and decide on containment. At enterprise scale this creates a backlog that widens the window of exposure.

This playbook eliminates the Tier 1 triage layer entirely for high-confidence phishing by automating the full pipeline: from alert ingestion through enrichment, blast radius assessment, and containment — in under 3 seconds.

| Metric | Before | After |
|---|---|---|
| Mean Time to Detect (MTTD) | 5–15 min (manual review) | < 3 seconds (async webhook) |
| Mean Time to Remediate (MTTR) | 30–90 min (analyst-driven) | < 60 seconds (automated containment) |
| Analyst touchpoint required | Every alert | Only when score < 75 |

---

## Architecture

```
[ Endpoint / Email Gateway ]
          │
          ▼
    [ Wazuh SIEM ]
    Rule IDs: 100001–100005
    Level >= 10 → fires integration block
          │
          ▼ (JSON webhook POST)
    [ Shuffle SOAR ]
    webhook_prod_phish_01
          │
    ┌─────┴──────────────────┐
    ▼                        ▼                        ▼
[ VirusTotal ]        [ AbuseIPDB ]         [ Active Directory ]
SHA256 hash lookup    Source IP score        Blast radius / VIP check
    │                        │                        │
    └─────────────────────────┴────────────────────────┘
                             │
                    [ Composite Score Engine ]
                    Score = (VT% × 0.5) + (IP score × 0.3) + (VIP bonus 20)
                             │
               ┌─────────────┴─────────────┐
          Score >= 75                  Score < 75
               │                            │
    [ Automated Containment ]      [ Escalate to Analyst ]
    ├── Purge M365 mailboxes        TheHive case created
    ├── Block IP + domain           Full enrichment attached
    └── Isolate host (EDR)          Slack notification sent
```

---

## File Structure

```
├── wazuh/
│   ├── ossec.conf                    # SOAR integration block
│   └── rules/
│       └── pb01_phishing_rules.xml   # Detection rules (IDs 100001–100005)
├── shuffle/
│   └── pb01_phishing_playbook.json   # Full Shuffle workflow export
└── docs/
    └── PB-01_README.md               # This file
```

---

## Detection Rules

Five Wazuh rules cover the phishing attack surface:

| Rule ID | Level | Trigger | Description |
|---|---|---|---|
| 100001 | 12 | `rule_name` field match | User-reported phishing or gateway block |
| 100002 | 14 | Attachment regex `.exe,.bat,.ps1,.vbs` | Executable attachment in email |
| 100003 | 14 | Double-extension regex `pdf.exe, docx.vbs` | Masquerading document attachment |
| 100004 | 10 | Subject keyword match | High-urgency social engineering phrases |
| 100005 | 15 | Source IP CIDR match | Email from known Tor exit / malicious range |

---

## Workflow Nodes

| Node | Type | Action |
|---|---|---|
| node_01_webhook | Trigger | Receives JSON payload from Wazuh |
| node_02_extract | Parse | Normalizes artifacts into pipeline variables |
| node_03_vt_hash | Enrichment | VirusTotal SHA256 hash reputation |
| node_04_abuseipdb | Enrichment | AbuseIPDB source IP confidence score |
| node_05_blast_radius | Enrichment | AD query — recipient privilege level |
| node_06_score | Calculate | Composite threat score (0–100) |
| node_07_decision | Condition | Routes on score >= 75 threshold |
| node_08_purge_mailbox | Containment | M365 Graph API hard-delete across all mailboxes |
| node_09_block_indicators | Containment | Firewall API — block IP + domain (30-day TTL) |
| node_10_isolate_host | Containment | CrowdStrike — network isolate endpoint if hash executed |
| node_11_escalate | Case Mgmt | TheHive — create enriched incident case |
| node_12_notify | Notify | Slack — structured alert card to SOC channel |

---

## Alert Payload Schema

Wazuh pushes the following JSON to the Shuffle webhook on rule trigger:

```json
{
  "alert_id": "99b3a41e-5f12-4cf3-a620-80fa2a9121a2",
  "timestamp": "2026-06-25T11:15:00Z",
  "rule_name": "Suspicious External Phishing Email Reported",
  "severity": "High",
  "artifacts": {
    "sender": "attacker@compromised-vendor.com",
    "recipient": "sjames@enterprise.com",
    "source_ip": "185.220.101.5",
    "subject": "URGENT: Update Your Banking Details Immediately",
    "attachment_name": "invoice_9912.pdf.exe",
    "attachment_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
}
```

Every `artifacts.*` field maps directly to a Shuffle variable via `{{ $exec.artifacts.<field> }}`.

---

## Threat Score Formula

```
composite_score = (vt_detection_ratio × 0.5) + (ip_abuse_score × 0.3) + (is_vip == true ? 20 : 0)
```

| Component | Weight | Source |
|---|---|---|
| VirusTotal detection ratio | 50% | `malicious / total_engines × 100` |
| AbuseIPDB confidence score | 30% | Raw score 0–100 |
| VIP/Privileged target bonus | 20% | AD group membership check |

**Threshold:** Score >= 75 → automated containment. Score < 75 → analyst queue.

---

## Deployment

### Prerequisites

- Docker Engine v20.10+
- Docker Compose v2.20+
- Minimum 8GB RAM
- API keys: VirusTotal, AbuseIPDB, CrowdStrike, Microsoft Graph (M365), TheHive, Slack

### Environment Variables

Copy `.env.example` to `.env` and populate:

```bash
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
M365_TENANT_ID=your_tenant_id
M365_CLIENT_ID=your_client_id
M365_CLIENT_SECRET=your_secret
THEHIVE_API_KEY=your_key_here
THEHIVE_URL=http://thehive:9000
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
FIREWALL_API_URL=http://your-firewall-api
FIREWALL_API_KEY=your_key_here
```

### Deploy Stack

```bash
git clone https://github.com/yourusername/soar-ir-pipeline.git
cd soar-ir-pipeline
docker-compose -f docker/docker-compose.yml up -d
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Import Playbook

1. Access Shuffle at `http://localhost:5001`
2. Navigate to **Workflows → Import**
3. Upload `shuffle/pb01_phishing_playbook.json`
4. Map secrets in the workflow variable panel
5. Activate the webhook trigger

### Configure Wazuh

1. Copy `wazuh/rules/pb01_phishing_rules.xml` to `/var/ossec/etc/rules/`
2. Merge the integration block from `wazuh/ossec.conf` into your production `ossec.conf`
3. Restart Wazuh manager:

```bash
docker exec wazuh-manager-production /var/ossec/bin/wazuh-control restart
```

---

## Testing

Simulate a phishing alert by POSTing the sample payload directly to the Shuffle webhook:

```bash
curl -X POST http://localhost:5001/api/v1/hooks/webhook_prod_phish_01 \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-001",
    "timestamp": "2026-06-25T12:00:00Z",
    "rule_name": "Suspicious External Phishing Email Reported",
    "severity": "High",
    "artifacts": {
      "sender": "attacker@test-malicious.com",
      "recipient": "analyst@yourorg.com",
      "source_ip": "185.220.101.5",
      "subject": "URGENT: Verify Your Account",
      "attachment_name": "invoice.pdf.exe",
      "attachment_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  }'
```

Expected output: VirusTotal and AbuseIPDB enrichment results visible in Shuffle execution log. TheHive case created. Slack notification delivered to SOC channel.

---

## Interview Talking Points

> "I built PB-01 as the first playbook in a 10-playbook automated IR pipeline. It ingests phishing alerts from Wazuh via asynchronous JSON webhook, runs parallel enrichment across VirusTotal for hash reputation, AbuseIPDB for source IP scoring, and Active Directory for blast radius context. I built a weighted composite scoring engine inside Shuffle that combines those three signals — VT detection ratio at 50%, IP abuse confidence at 30%, and a VIP privilege bonus at 20% — and routes automatically to containment if the score clears 75. Containment triggers three actions in parallel: a hard-delete purge across all M365 mailboxes via the Graph API, an IP and domain block pushed to the firewall via REST, and conditional host isolation through CrowdStrike if EDR confirms the attachment executed. Below the threshold it creates an enriched TheHive case with every artifact and score attached and pings the SOC Slack channel. This eliminated the Tier 1 triage layer entirely for high-confidence phishing."

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Subtechnique | Name |
|---|---|---|---|
| Initial Access | T1566 | T1566.001 | Phishing: Spearphishing Attachment |
| Initial Access | T1566 | T1566.002 | Phishing: Spearphishing Link |

---

*Part of the Autonomous IR Pipeline — 10-playbook production SOAR project.*  
*Next: [PB-02 — Brute Force & Account Lockout](../pb02/)*
