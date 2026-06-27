# PB-03 | Ransomware Detection & Host Isolation

**Playbook ID:** PB-03  
**Severity:** Critical — P1  
**MITRE ATT&CK:** T1486 (Data Encrypted for Impact) · T1490 (Inhibit System Recovery) · T1021.002 (SMB Lateral Movement) · T1562.001 (Impair Defenses)  
**Stack:** Wazuh FIM · Shuffle · VirusTotal · Hybrid Analysis · CrowdStrike Falcon · Active Directory · Firewall API · TheHive · Slack

---

## Engineering Impact

Ransomware has a narrow containment window. From first file encryption to full domain compromise, active ransomware families like LockBit 3.0 and BlackCat move in under 4 hours. Manual triage at this speed is not viable — by the time an analyst reviews the alert, the blast radius has already expanded to network shares and backup systems.

This playbook closes that window with two design decisions that differ from every other playbook in this suite: a **zero-tolerance pre-check** that bypasses the full enrichment pipeline for the two indicators that have no legitimate use cases (shadow copy deletion, known ransomware binary execution), and a **blast radius enumeration** step that maps network share exposure before containment fires.

| Metric | Before | After |
|---|---|---|
| Time to host isolation | 20–60 min (analyst-driven) | < 5 seconds (zero-tolerance path) |
| Time to isolation (scored path) | 30–90 min | < 15 seconds (enrichment + decision) |
| Blast radius awareness | Manual (analyst reviews logs) | Automated — affected host count in TheHive case |
| C2 communication blocked | Manual firewall ticket | Automated — Hybrid Analysis C2 IPs pushed to firewall |

---

## Architecture

```
[ Wazuh FIM + Process Monitor ]
Rule IDs: 100020–100025
          │
          ▼ (JSON webhook POST)
    [ Shuffle SOAR ]
    webhook_prod_ransomware_03
          │
    [ Zero-Tolerance Pre-Check ]
    Rule 100022 (shadow copy delete) OR
    Rule 100024 (known ransomware binary)
          │
    ┌─────┴─────────────────────────┐
  YES (zero-tolerance)          NO (behavioral signal)
    │                               │
    │                    ┌──────────┴──────────────────┐
    │                    ▼                             ▼                    ▼
    │             [ VirusTotal ]            [ Hybrid Analysis ]   [ Blast Radius ]
    │             SHA256 hash lookup        Sandbox verdict        Network share scope
    │                    │                             │                    │
    │                    └──────────┬──────────────────┘                    │
    │                               ▼                                       │
    │                    [ Composite Score ]                                │
    │                    Score >= 65?                                       │
    │                    │              │                                   │
    │                   YES            NO                                   │
    │                    │             └──► [ Escalate to Analyst ]         │
    │                    │                                                  │
    └────────────────────┴──────────────────────────────────────────────────┘
                         │
              [ CrowdStrike — Isolate Host ]
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
    [ AD Account Disable ]   [ Block C2 IPs at Firewall ]
              │
    [ TheHive — Critical Case + IR Checklist ]
              │
    [ Slack — P1 Critical Channel Alert ]
```

---

## File Structure

```
├── wazuh/
│   └── rules/
│       └── pb03_ransomware_rules.xml     # Detection rules (IDs 100020–100025)
├── shuffle/
│   └── pb03_ransomware_playbook.json     # Full Shuffle workflow export
└── docs/
    └── PB-03_README.md                   # This file
```

---

## Detection Rules

| Rule ID | Level | Trigger | Description |
|---|---|---|---|
| 100020 | 15 | 20+ file renames in 30s with crypto extensions | Mass encryption — ransomware file modification pattern |
| 100021 | 14 | Ransom note filename creation | Ransom note dropped on filesystem |
| 100022 | 15 | `vssadmin delete shadows` / `bcdedit /set recoveryenabled no` | Shadow copy deletion — zero-tolerance trigger |
| 100023 | 13 | 50+ file writes in 60s | High-frequency write activity — encryption in progress |
| 100024 | 15 | Known binary names: WannaCry, Ryuk, LockBit, BlackCat, Conti | Known ransomware binary execution — zero-tolerance trigger |
| 100025 | 12 | EventID 5145 — network share enumeration | Pre-encryption lateral spread reconnaissance |

---

## Workflow Nodes

| Node | Type | Action |
|---|---|---|
| node_01_webhook | Trigger | Receives Wazuh FIM/process alert |
| node_02_extract | Parse | Normalizes fields, flags zero-tolerance indicators |
| node_03_zero_tolerance_gate | Condition | Bypasses enrichment for shadow copy delete and known binaries |
| node_04_vt_hash | Enrichment | VirusTotal SHA256 — family identification and detection ratio |
| node_05_hybrid_analysis | Enrichment | Hybrid Analysis sandbox verdict and C2 network indicators |
| node_06_blast_radius | Enrichment | Wazuh API — network shares accessed, affected host count |
| node_07_score | Calculate | Composite threat score (0–100) |
| node_07b_score_gate | Condition | Routes on score >= 65 |
| node_08_isolate_host | Containment | CrowdStrike Falcon — network isolate, EDR agent retained |
| node_09_disable_user | Containment | AD account disable for running user context |
| node_10_block_c2 | Containment | Firewall block for Hybrid Analysis C2 indicators (90-day TTL) |
| node_11_escalate | Case Mgmt | TheHive P1/P2 case with full IR checklist |
| node_12_notify | Notify | Slack critical channel — P1 all-hands alert |

---

## Alert Payload Schema

```json
{
  "alert_id": "rsm-003-c7f2a1",
  "timestamp": "2026-06-25T02:47:11Z",
  "rule_id": "100022",
  "rule_name": "Volume shadow copy deletion — ransomware pre-encryption step detected",
  "severity": "Critical",
  "artifacts": {
    "hostname": "WORKSTATION-042",
    "agent_id": "cs-agent-00a1b2c3",
    "file_path": "C:\\Windows\\System32\\vssadmin.exe",
    "file_hash_sha256": "a4b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "process_name": "vssadmin.exe",
    "process_id": "4812",
    "parent_process": "cmd.exe",
    "username": "CORP\\jsmith",
    "command_line": "vssadmin delete shadows /all /quiet",
    "file_rename_count": 0,
    "shadow_copy_deleted": true,
    "network_shares_accessed": ["\\\\FILESERVER01\\Finance", "\\\\FILESERVER01\\HR"]
  }
}
```

---

## Threat Score Formula

```
composite_score =
  (vt_detection_ratio × 0.4)
  + (ha_threat_score × 0.3)
  + (file_rename_count >= 50 ? 20 : file_rename_count >= 20 ? 12 : 5)
  + (blast_radius_critical == true ? 10 : 0)
```

| Component | Weight | Notes |
|---|---|---|
| VirusTotal detection ratio | 40% | Near 100% for known families |
| Hybrid Analysis threat score | 30% | 0–100 sandbox behavioral score |
| File rename velocity | 5–20 points | Tiered: 20+ renames = 12, 50+ = 20 |
| Blast radius critical | 10 points | >5 hosts accessed same shares |

**Zero-tolerance threshold:** Rule IDs 100022 and 100024 skip scoring entirely and trigger immediate isolation regardless of VT/HA results.

---

## Key Design Decisions

**Why a zero-tolerance pre-check?**  
Shadow copy deletion via `vssadmin delete shadows /all /quiet` has exactly one purpose in a production Windows environment: destroying recovery points before ransomware encrypts the disk. There is no legitimate administrative use case for this command running silently. Waiting for enrichment results costs seconds the organization does not have. Same logic applies to known ransomware binary names — if CrowdStrike's own threat intel has flagged the binary family, the enrichment pipeline is a delay, not a value-add.

**Why Hybrid Analysis in addition to VirusTotal?**  
VT tells you what AV engines think of the hash. Hybrid Analysis tells you what the binary *does* — file modifications, registry changes, network C2 connections. The C2 network indicators from HA are the input to `node_10_block_c2`, which prevents the ransomware from receiving the encryption key from the attacker's server. Blocking C2 can stop an in-progress encryption.

**Why include blast radius enumeration before isolation?**  
Isolating the patient zero host stops spread from that machine. But if the ransomware already traversed to network shares, other hosts may be encrypting files concurrently. The blast radius query gives the analyst a scoped list of potentially affected hosts in the TheHive case — they know exactly where to look next instead of scanning the entire domain.

**Why 90-day TTL on C2 blocks vs. 24-hour on brute force IPs?**  
Ransomware C2 infrastructure is purpose-built and persistent. The attacker paid for or compromised those servers specifically for this campaign. A 24-hour block is irrelevant — they will still be live in 24 hours. 90 days covers the typical C2 infrastructure lifecycle for ransomware campaigns.

---

## Deployment

### Environment Variables

Add to `.env`:

```bash
VIRUSTOTAL_API_KEY=your_key_here
HYBRID_ANALYSIS_API_KEY=your_key_here
CROWDSTRIKE_CLIENT_ID=your_client_id
CROWDSTRIKE_CLIENT_SECRET=your_client_secret
AD_DOMAIN_CONTROLLER=ldap://your-dc.corp.local
AD_BIND_USER=svc_shuffle@corp.local
AD_BIND_PASSWORD=your_service_account_password
THEHIVE_API_KEY=your_key_here
THEHIVE_URL=http://thehive:9000
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_CRITICAL_CHANNEL=#soc-critical-incidents
FIREWALL_API_URL=http://your-firewall-api
FIREWALL_API_KEY=your_key_here
WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_API_TOKEN=your_wazuh_jwt_token
```

### Add Wazuh Integration Block

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://shuffle-backend:5001/api/v1/hooks/webhook_prod_ransomware_03</hook_url>
  <alert_format>json</alert_format>
  <level>12</level>
  <group>ransomware,pb03</group>
</integration>
```

### Configure Wazuh FIM

Add monitored paths to `ossec.conf` for real-time file integrity monitoring:

```xml
<syscheck>
  <directories realtime="yes" check_all="yes" report_changes="yes">C:\Users</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">C:\Documents</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">\\FILESERVER01\Finance</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">\\FILESERVER01\HR</directories>
</syscheck>
```

---

## Testing

```bash
curl -X POST http://localhost:5001/api/v1/hooks/webhook_prod_ransomware_03 \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-pb03-001",
    "timestamp": "2026-06-25T02:47:11Z",
    "rule_id": "100022",
    "rule_name": "Volume shadow copy deletion detected",
    "severity": "Critical",
    "artifacts": {
      "hostname": "TEST-WORKSTATION-01",
      "agent_id": "test-agent-001",
      "file_path": "C:\\Windows\\System32\\vssadmin.exe",
      "file_hash_sha256": "a4b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
      "process_name": "vssadmin.exe",
      "process_id": "4812",
      "parent_process": "cmd.exe",
      "username": "CORP\\testuser",
      "command_line": "vssadmin delete shadows /all /quiet",
      "file_rename_count": 0,
      "shadow_copy_deleted": true,
      "network_shares_accessed": ["\\\\FILESERVER01\\Finance"]
    }
  }'
```

**Expected behavior:** Zero-tolerance gate fires immediately — enrichment skipped. CrowdStrike isolation triggered. AD account disabled. TheHive P1 case created with IR checklist. Slack critical channel alerted.

---

## Interview Talking Points

> "PB-03 is the most architecturally different playbook in the suite because ransomware demands a different decision model. Every other playbook scores first and acts second. PB-03 has a zero-tolerance pre-check that fires before enrichment runs — if Wazuh detects shadow copy deletion via vssadmin or a known ransomware binary executing, the host gets isolated immediately. No scoring, no API calls, no wait time. I made that decision because those two indicators have no legitimate use case in a production environment and the cost of a false positive — briefly isolating a host that turns out to be clean — is orders of magnitude lower than the cost of 30 seconds of additional ransomware runtime on a network with mapped drives. I also built in a blast radius query that checks the Wazuh API for other hosts that accessed the same network shares in the previous hour, so the analyst's TheHive case opens with a scoped list of potentially infected machines rather than a blank slate."

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Subtechnique | Name |
|---|---|---|---|
| Impact | T1486 | — | Data Encrypted for Impact |
| Impact | T1490 | — | Inhibit System Recovery |
| Lateral Movement | T1021 | T1021.002 | Remote Services: SMB/Windows Admin Shares |
| Defense Evasion | T1562 | T1562.001 | Impair Defenses: Disable or Modify Tools |

---

*Part of the Autonomous IR Pipeline — 10-playbook production SOAR project.*  
*Previous: [PB-02 — Brute Force & Account Lockout](../pb02/) | Next: [PB-04 — Malware Hash Enrichment & Quarantine](../pb04/)*
