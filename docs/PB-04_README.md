# PB-04 | Malware Hash Enrichment & Endpoint Quarantine

**Playbook ID:** PB-04  
**Severity:** High  
**MITRE ATT&CK:** T1059.001 (PowerShell) · T1204.002 (Malicious File Execution) · T1036 (Masquerading) · T1027 (Obfuscation) · T1071 (C2 Application Layer)  
**Stack:** Wazuh · Shuffle · VirusTotal · Hybrid Analysis · MalwareBazaar · CrowdStrike Falcon · Firewall API · TheHive · Slack

---

## Engineering Impact

PB-04 is the most enrichment-heavy playbook in the suite. Where PB-03 (ransomware) prioritizes speed above everything, PB-04 prioritizes intelligence depth. Malware detections span a wide confidence range — from a novel dropper with zero VT hits to a well-documented commodity RAT in every threat intel feed. A single containment threshold does not serve both ends of that range.

The key architectural decision here is **four parallel enrichment sources** — VirusTotal, Hybrid Analysis, MalwareBazaar, and a Wazuh estate-wide prevalence check — combined into a weighted composite score. This gives the analyst a richer picture than any single source provides, and the estate prevalence query specifically answers the question that matters most operationally: is this isolated or is this a campaign?

The second key decision: **estate-wide quarantine**. CrowdStrike's `quarantine_file` action with `apply_to_all_hosts: true` removes the file from every enrolled endpoint simultaneously — not just the alerting machine.

| Metric | Before | After |
|---|---|---|
| Enrichment time per alert | 15–25 min (analyst manually queries 3+ sources) | < 8 seconds (4 parallel API calls) |
| Scope of containment | Single host (analyst remediates manually) | Estate-wide (all enrolled endpoints) |
| Campaign detection | Manual log correlation | Automated 7-day estate prevalence query |
| False positive rate | High for new/unknown files | Score-gated — low VT + no MalwareBazaar = analyst review |

---

## Architecture

```
[ Wazuh Process Monitor + EDR Forwarding ]
Rule IDs: 100030–100035
          │
          ▼ (JSON webhook POST)
    [ Shuffle SOAR ]
    webhook_prod_malware_04
          │
          ▼
    [ Artifact Extraction ]
    SHA256 + SHA1 + MD5 normalized
    High-risk path flag
    Unsigned binary flag
          │
    ┌─────┴───────────┬──────────────────┬──────────────────┐
    ▼                 ▼                  ▼                   ▼
[ VirusTotal ]  [ Hybrid Analysis ]  [ MalwareBazaar ]  [ Wazuh Estate ]
Detection ratio  Sandbox verdict +    Community intel    7-day hash
+ family ID      MITRE TTPs + C2      delivery method    prevalence scan
    │                 │                  │                   │
    └─────────────────┴──────────────────┴───────────────────┘
                                │
                    [ Composite Score Engine ]
                    (VT × 0.35) + (HA × 0.25) + MalwareBazaar(20)
                    + high-risk path(10) + unsigned(5) + campaign(10)
                                │
               ┌────────────────┴────────────────┐
          Score >= 60                        Score < 60
          OR VT hits >= 5                        │
               │                      [ Escalate to Analyst ]
    [ Estate-Wide Quarantine ]         TheHive case + full
    ├── CrowdStrike quarantine          enrichment attached
    │   (all enrolled endpoints)
    ├── Add SHA256+MD5 to IOC
    │   blocklist (prevent forever)
    └── Block C2 IPs/domains
        at perimeter firewall
```

---

## File Structure

```
├── wazuh/
│   └── rules/
│       └── pb04_malware_rules.xml        # Detection rules (IDs 100030–100035)
├── shuffle/
│   └── pb04_malware_playbook.json        # Full Shuffle workflow export
└── docs/
    └── PB-04_README.md                   # This file
```

---

## Detection Rules

| Rule ID | Level | Trigger | Description |
|---|---|---|---|
| 100030 | 12 | EventID 4688 from Temp/Downloads/AppData/ProgramData | Execution from high-risk non-standard directory |
| 100031 | 11 | EventID 4688 with Untrusted/Low integrity label | Unsigned or low-integrity binary execution |
| 100032 | 13 | `-EncodedCommand`, `-Exec Bypass`, `-WindowStyle Hidden` | Encoded/hidden PowerShell — dropper/stager pattern |
| 100033 | 13 | File write to temp + immediate execution | File drop-and-execute — dropper pattern |
| 100034 | 14 | CrowdStrike/Defender detection event forwarded | EDR platform detection forwarded to Wazuh |
| 100035 | 13 | Office process (Word/Excel) spawning cmd/powershell | Macro or exploit execution via Office document |

---

## Workflow Nodes

| Node | Type | Action |
|---|---|---|
| node_01_webhook | Trigger | Receives Wazuh/EDR detection payload |
| node_02_extract | Parse | Normalizes MD5/SHA1/SHA256, flags high-risk path and unsigned binary |
| node_03_vt_hash | Enrichment | VirusTotal — detection ratio, family, first/last seen |
| node_04_hybrid_analysis | Enrichment | Hybrid Analysis — sandbox verdict, MITRE TTPs, C2 indicators, mutexes |
| node_05_malwarebazaar | Enrichment | MalwareBazaar — community intel, delivery method, tags |
| node_06_estate_prevalence | Enrichment | Wazuh API — 7-day estate-wide hash prevalence scan |
| node_07_score | Calculate | Composite threat score (0–100) |
| node_08_decision | Condition | Routes on score >= 60 OR VT hits >= 5 |
| node_09_quarantine_file | Containment | CrowdStrike — estate-wide file quarantine by SHA256 |
| node_10_add_ioc | Containment | CrowdStrike IOC management — SHA256 + MD5 permanent block |
| node_11_block_c2 | Containment | Firewall — block Hybrid Analysis C2 indicators (90-day TTL) |
| node_12_escalate | Case Mgmt | TheHive enriched case with investigation checklist |
| node_13_notify | Notify | Slack SOC alert — campaign flag elevated |

---

## Alert Payload Schema

```json
{
  "alert_id": "mal-004-d8e3b2",
  "timestamp": "2026-06-25T14:22:07Z",
  "rule_id": "100032",
  "rule_name": "Encoded or hidden PowerShell execution — common malware dropper / stager",
  "severity": "High",
  "source": "Wazuh",
  "artifacts": {
    "hostname": "LAPTOP-SALES-019",
    "agent_id": "wz-agent-00b3c4d5",
    "username": "CORP\\mbrown",
    "process_name": "powershell.exe",
    "process_id": "6204",
    "parent_process": "WINWORD.EXE",
    "file_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "file_hash_md5": "a4b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "file_hash_sha1": "b5c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1",
    "file_hash_sha256": "c6d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    "command_line": "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand JABjAD0ATgBlAHcA...",
    "file_size_bytes": 442368,
    "file_signer": null,
    "is_signed": false
  }
}
```

---

## Threat Score Formula

```
composite_score =
  (vt_detection_ratio × 0.35)
  + (ha_threat_score × 0.25)
  + (mb_known_malware == true ? 20 : 0)
  + (high_risk_path == true ? 10 : 0)
  + (is_signed == false ? 5 : 0)
  + (estate_campaign_detected == true ? 10 : 0)
```

| Component | Weight | Notes |
|---|---|---|
| VirusTotal detection ratio | 35% | Broadest AV coverage |
| Hybrid Analysis threat score | 25% | Behavioral sandbox — catches evasive malware |
| MalwareBazaar confirmation | 20 points | Community-verified — strong signal |
| High-risk execution path | 10 points | Temp/Downloads/AppData/ProgramData |
| Unsigned binary | 5 points | Increases suspicion but not deterministic |
| Estate-wide campaign | 10 points | 3+ hosts = active campaign bonus |

**Threshold:** Score >= 60 OR VT malicious count >= 5 → automated quarantine.

---

## Key Design Decisions

**Why MalwareBazaar as a third source?**  
VirusTotal and Hybrid Analysis cover detection ratio and behavioral analysis. MalwareBazaar covers community threat intelligence — delivery method, reporter, campaign tags. A file that VT rates at 30% detection but MalwareBazaar has tagged as an active emotet campaign delivery mechanism should be treated differently than a 30% VT score on a generic PUA. MalwareBazaar confirmation adds 20 points to the score and surfaces in the TheHive case as context.

**Why estate-wide quarantine instead of single-host?**  
A malware hit on one endpoint often means the file already exists on others — delivered via the same phishing campaign, copied to a shared drive, or staged by an attacker who already has lateral access. CrowdStrike's `apply_to_all_hosts: true` removes the file everywhere in a single API call. The estate prevalence check then tells the analyst exactly how many hosts had the file in the past 7 days.

**Why is the score threshold lower (60) than other playbooks?**  
Malware quarantine is less disruptive than host isolation (PB-03) or account lockout (PB-02). A quarantined file can be restored if it turns out to be a false positive. The lower threshold accepts a slightly higher false positive rate in exchange for faster containment of genuinely malicious files.

---

## Deployment

### Environment Variables

Add to `.env`:

```bash
VIRUSTOTAL_API_KEY=your_key_here
HYBRID_ANALYSIS_API_KEY=your_key_here
MALWAREBAZAAR_API_KEY=your_key_here
CROWDSTRIKE_CLIENT_ID=your_client_id
CROWDSTRIKE_CLIENT_SECRET=your_client_secret
WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_API_TOKEN=your_wazuh_jwt_token
THEHIVE_API_KEY=your_key_here
THEHIVE_URL=http://thehive:9000
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
FIREWALL_API_URL=http://your-firewall-api
FIREWALL_API_KEY=your_key_here
```

### Add Wazuh Integration Block

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://shuffle-backend:5001/api/v1/hooks/webhook_prod_malware_04</hook_url>
  <alert_format>json</alert_format>
  <level>11</level>
  <group>malware,pb04</group>
</integration>
```

---

## Testing

```bash
curl -X POST http://localhost:5001/api/v1/hooks/webhook_prod_malware_04 \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-pb04-001",
    "timestamp": "2026-06-25T14:22:07Z",
    "rule_id": "100032",
    "rule_name": "Encoded PowerShell execution detected",
    "severity": "High",
    "source": "Wazuh",
    "artifacts": {
      "hostname": "TEST-HOST-01",
      "agent_id": "test-agent-001",
      "username": "CORP\\testuser",
      "process_name": "powershell.exe",
      "process_id": "6204",
      "parent_process": "WINWORD.EXE",
      "file_path": "C:\\Users\\testuser\\AppData\\Local\\Temp\\payload.exe",
      "file_hash_md5": "a4b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
      "file_hash_sha1": "b5c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
      "file_hash_sha256": "c6d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
      "command_line": "powershell.exe -WindowStyle Hidden -EncodedCommand JABj...",
      "file_size_bytes": 442368,
      "file_signer": null,
      "is_signed": false
    }
  }'
```

---

## Interview Talking Points

> "PB-04 is the deepest enrichment playbook in the suite — four parallel sources firing simultaneously: VirusTotal for AV detection ratio and family identification, Hybrid Analysis for sandbox behavioral verdict and MITRE ATT&CK TTP mapping, MalwareBazaar for community threat intel and delivery method context, and a Wazuh API estate-wide prevalence query that scans 7 days of process execution logs to answer whether this is an isolated infection or an active campaign. The containment action is estate-wide quarantine via CrowdStrike — one API call removes the file from every enrolled endpoint, not just the alerting machine. I also set a lower score threshold than the other playbooks at 60, because file quarantine is reversible — a false positive can be restored, but a missed malware execution can't be undone."

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Subtechnique | Name |
|---|---|---|---|
| Execution | T1059 | T1059.001 | Command and Scripting Interpreter: PowerShell |
| Execution | T1204 | T1204.002 | User Execution: Malicious File |
| Defense Evasion | T1036 | — | Masquerading |
| Defense Evasion | T1027 | — | Obfuscated Files or Information |
| Command and Control | T1071 | — | Application Layer Protocol |

---

*Part of the Autonomous IR Pipeline — 10-playbook production SOAR project.*  
*Previous: [PB-03 — Ransomware Detection & Host Isolation](../pb03/) | Next: [PB-05 — Impossible Travel / Suspicious Login](../pb05/)*
