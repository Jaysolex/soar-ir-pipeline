# PB-08 | C2 Beaconing Detection & Automated Outbound Block

**Playbook ID:** PB-08  
**Severity:** Critical — P1  
**MITRE ATT&CK:** T1071.001 (Web Protocols C2) · T1071.004 (DNS C2) · T1573.002 (Encrypted Channel) · T1105 (Ingress Tool Transfer) · T1218 (LOLBins)  
**Stack:** Wazuh · Shuffle · VirusTotal · AbuseIPDB · Shodan · URLhaus · CrowdStrike Falcon RTR · Firewall API · TheHive · Slack

---

## Engineering Impact

An active C2 channel means an adversary has interactive access to an endpoint inside your network. Every second the channel is live, the attacker can execute commands, pivot laterally, stage data for exfiltration, or deploy additional implants. Detection speed is everything — but the bigger challenge is **false positive suppression**. Legitimate software beacons constantly: monitoring agents, telemetry services, update checkers, heartbeat timers. Blocking all periodic outbound traffic breaks production.

PB-08 solves this with two mechanisms no other playbook in the suite uses: **statistical beacon interval analysis** using coefficient of variation to mathematically distinguish C2 beaconing from legitimate periodic traffic, and **Shodan port fingerprinting** to identify C2 infrastructure by its open port signature and SSL certificate subject — not just by reputation scores.

| Metric | Before | After |
|---|---|---|
| Time to sever C2 channel | 20–60 min (manual analysis) | < 5 seconds (Cobalt Strike zero-tolerance path) |
| False positive rate on beaconing | High — all periodic traffic flagged | Statistical CV analysis separates C2 from legitimate agents |
| C2 infrastructure identification | VT reputation only | Four parallel sources: VT + AbuseIPDB + Shodan fingerprint + URLhaus |
| Network-wide C2 block | Single host firewall rule | Firewall block applied to all hosts — preemptive coverage |

---

## Architecture

```
[ Wazuh Network Monitor + Firewall Logs ]
Rule IDs: 100070–100075
          │
          ▼ (JSON webhook POST)
    [ Shuffle SOAR ]
    webhook_prod_c2_08
          │
    [ Artifact Extraction + Beacon Pre-Analysis ]
    Interval array → mean, stddev, CV
    Known C2 port flag
    LOLBin process flag
          │
    [ Cobalt Strike Zero-Tolerance Gate ]
    Rule 100072 (CS beacon pattern) → immediate isolation
          │
    ┌─────┴──────────────────────────────────────┐
    ▼            ▼              ▼             ▼            ▼
[ VirusTotal ]  [ AbuseIPDB ]  [ Shodan ]  [ URLhaus ]  [ Beacon Analysis ]
IP reputation   Abuse score    Port finger  C2 URL intel  Statistical CV
C2 tags         Usage type     SSL cert CN  Malware tags  CONSISTENT/JITTER
    │            │              │             │             │
    └────────────┴──────────────┴─────────────┴─────────────┘
                                │
                    [ Composite C2 Score ]
                    VT C2 tags(20) + Shodan C2(20)
                    + URLhaus C2(20) + abuse score(×0.2)
                    + beacon type(10-15) + C2 port(10)
                    + LOLBin(10)
                                │
               ┌────────────────┴────────────────┐
          Score >= 65                        Score < 65
               │                        [ Escalate to Analyst ]
    [ CrowdStrike — Isolate Host ]
               │
    ┌──────────┴──────────┐
    ▼                     ▼
[ RTR Kill Process ]  [ Firewall Block ]
Kill PID via RTR      IP + domain, all hosts
                      90-day TTL
               │
    [ TheHive P1 Case + IR Checklist ]
    [ Slack Critical Channel — P1 Alert ]
```

---

## File Structure

```
├── wazuh/
│   └── rules/
│       └── pb08_c2_rules.xml             # Detection rules (IDs 100070–100075)
├── shuffle/
│   └── pb08_c2_playbook.json             # Full Shuffle workflow export
└── docs/
    └── PB-08_README.md                   # This file
```

---

## Detection Rules

| Rule ID | Level | Trigger | Description |
|---|---|---|---|
| 100070 | 13 | 5+ connections to same dest in 5 min | Periodic beaconing interval pattern |
| 100071 | 14 | Outbound to port 4444/8080/8443/9001/50050/31337 | Known C2 framework default ports |
| 100072 | 15 | Consistent small payload + jitter flag | Cobalt Strike beacon — zero-tolerance trigger |
| 100073 | 12 | HTTPS on non-standard port outbound | Encrypted C2 channel on non-443 port |
| 100074 | 13 | EventID 5156 — LOLBin making outbound connection | powershell/cmd/certutil/bitsadmin network egress |
| 100075 | 13 | 100+ small packets to same dest in 60s | High-frequency small packet — data staging over C2 |

---

## Workflow Nodes

| Node | Type | Action |
|---|---|---|
| node_01_webhook | Trigger | Receives Wazuh network alert payload |
| node_02_extract | Parse | Normalizes fields, calculates interval mean/stddev/CV |
| node_03_cobalt_strike_gate | Condition | Rule 100072 bypasses enrichment → immediate isolation |
| node_04_vt_dest | Enrichment | VirusTotal — destination IP reputation + C2 tags |
| node_05_abuseipdb | Enrichment | AbuseIPDB — abuse confidence score + usage type |
| node_06_shodan | Enrichment | Shodan — open ports, SSL cert CN, C2 infrastructure tags |
| node_07_urlhaus | Enrichment | URLhaus — C2 URL and malware distribution intelligence |
| node_08_beacon_analysis | Calculate | Statistical CV analysis → CONSISTENT/JITTER/IRREGULAR |
| node_09_score | Calculate | Composite C2 confidence score (0–100) |
| node_09b_decision | Condition | Routes on score >= 65 |
| node_10_isolate_host | Containment | CrowdStrike Falcon — network isolate, EDR retained |
| node_11_kill_process | Containment | CrowdStrike RTR — `kill <PID>` via real-time response |
| node_12_block_c2 | Containment | Firewall — block C2 IP + domain, all hosts, 90-day TTL |
| node_13_escalate | Case Mgmt | TheHive P1/P2 case with IR checklist |
| node_14_notify | Notify | Slack critical channel — P1 all-hands alert |

---

## Alert Payload Schema

```json
{
  "alert_id": "c2-008-e4f7a2",
  "timestamp": "2026-06-25T23:14:05Z",
  "rule_id": "100071",
  "rule_name": "Outbound connection to known C2 framework default port",
  "artifacts": {
    "source_hostname": "WORKSTATION-077",
    "source_ip": "10.10.5.22",
    "agent_id": "cs-agent-00d5e6f7",
    "destination_ip": "45.76.144.215",
    "destination_domain": "updates.cdn-delivery.net",
    "destination_port": 50050,
    "protocol": "HTTPS",
    "direction": "outbound",
    "bytes_sent": 4821,
    "bytes_received": 187432,
    "connection_count": 12,
    "interval_seconds": [60, 58, 61, 59, 62, 60, 57, 61, 60, 63, 59, 60],
    "process_name": "rundll32.exe",
    "process_id": "5532",
    "parent_process": "svchost.exe",
    "beacon_jitter": false,
    "payload_size_variance": 0.03,
    "username": "CORP\\bwilson",
    "session_start": "2026-06-25T21:00:00Z"
  }
}
```

---

## Beacon Interval Statistical Analysis

The beacon analysis node applies coefficient of variation (CV = stddev / mean) to the connection interval array:

```
interval_seconds = [60, 58, 61, 59, 62, 60, 57, 61, 60, 63, 59, 60]
mean = 60.2
stddev = 1.6
CV = 1.6 / 60.2 = 0.027
```

| CV Range | Classification | Interpretation |
|---|---|---|
| CV < 0.1 | `CONSISTENT_BEACON` | True C2 beaconing — highly regular intervals |
| 0.1 ≤ CV < 0.5 | `JITTER_BEACON` | Cobalt Strike / jitter-enabled C2 |
| CV ≥ 0.5 | `IRREGULAR` | Likely not beaconing — irregular access pattern |

**False positive suppression:** NTP syncs at exactly 64-second intervals (CV ≈ 0.001) — this gets flagged as CONSISTENT_BEACON but will have a clean AbuseIPDB score and known NTP ASN in Shodan, keeping the composite score low. Legitimate monitoring agents have consistent intervals but clean destination reputation. The CV alone does not trigger containment — it adds 10–15 points to the composite score, which still requires supporting evidence from the enrichment layer.

---

## Composite C2 Score Formula

```
composite_score =
  (vt_malicious_count >= 5 ? 25 : vt_malicious_count >= 1 ? 15 : 0)
  + (vt_is_c2 == true ? 20 : 0)
  + (abuse_score × 0.2)
  + (shodan_is_c2 == true ? 20 : 0)
  + (urlhaus_is_known_c2 == true ? 20 : 0)
  + (beacon_type == 'CONSISTENT_BEACON' ? 15 : beacon_type == 'JITTER_BEACON' ? 10 : 0)
  + (is_known_c2_port == true ? 10 : 0)
  + (is_lolbin == true ? 10 : 0)
```

| Component | Weight | Notes |
|---|---|---|
| VT malicious count | 15–25 | 1+ hit = 15, 5+ hits = 25 |
| VT C2 tags | +20 | `c2`, `cobalt-strike`, `metasploit`, `empire` |
| AbuseIPDB score | ×0.2 | Max contribution 20 |
| Shodan C2 tagged | +20 | Port 50050, CS default ports, C2 tags |
| URLhaus known C2 | +20 | Active malware campaign use confirmed |
| Beacon type | +10–15 | CONSISTENT = 15, JITTER = 10 |
| Known C2 port | +10 | 4444/8080/8443/9001/50050/31337 |
| LOLBin process | +10 | rundll32/certutil/bitsadmin/etc. |

**Threshold:** Score >= 65 → host isolation + process kill + firewall block.  
**Zero-tolerance:** Cobalt Strike beacon pattern (rule 100072) → immediate isolation regardless of score.

---

## Key Design Decisions

**Why Shodan in addition to VT and AbuseIPDB?**  
VirusTotal and AbuseIPDB score IP reputation reactively — they tell you what happened after the IP was reported as malicious. Shodan tells you what the server looks like *right now*. A server running on port 50050 with a self-signed certificate whose CN is `Major Cobalt Strike' (a common CS default) is identifiably C2 infrastructure regardless of whether it has been reported to VT yet. This is particularly valuable for newly deployed C2 infrastructure that hasn't yet accumulated VT reports.

**Why CrowdStrike RTR to kill the process?**  
Host isolation severs the network connection, which terminates the C2 channel. But the implant process is still running in memory — and if the network isolation is lifted (for analyst investigation), the implant will re-establish the C2 channel immediately. Killing the process via RTR before isolation means the C2 software itself is stopped. The attacker loses both the current session and the ability to re-establish on reconnect.

**Why 90-day TTL on the firewall block vs. 24-hour or 30-day?**  
C2 infrastructure has a different lifecycle than brute force source IPs (PB-02) or exfiltration destinations (PB-06). Attackers invest in C2 servers — they're configured, deployed, and used across multiple campaigns. A 24-hour block is irrelevant. A 90-day block covers the full operational lifespan of a typical C2 infrastructure deployment.

**Why apply the firewall block to all hosts, not just the infected endpoint?**  
The infected endpoint is the one you know about. C2 infrastructure is often used across multiple implants in a campaign. If the attacker has lateral movement and has deployed implants on other hosts that haven't beaconed yet, a network-wide block preemptively severs those unknown channels before they phone home.

---

## Deployment

### Environment Variables

```bash
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_shodan_api_key
CROWDSTRIKE_CLIENT_ID=your_client_id
CROWDSTRIKE_CLIENT_SECRET=your_client_secret
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
  <hook_url>http://shuffle-backend:5001/api/v1/hooks/webhook_prod_c2_08</hook_url>
  <alert_format>json</alert_format>
  <level>12</level>
  <group>c2,pb08</group>
</integration>
```

---

## Testing

```bash
curl -X POST http://localhost:5001/api/v1/hooks/webhook_prod_c2_08 \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-pb08-001",
    "timestamp": "2026-06-25T23:14:05Z",
    "rule_id": "100071",
    "rule_name": "Outbound connection to known C2 port",
    "artifacts": {
      "source_hostname": "TEST-HOST-01",
      "source_ip": "10.10.5.22",
      "agent_id": "test-agent-001",
      "destination_ip": "45.76.144.215",
      "destination_domain": "updates.cdn-delivery.net",
      "destination_port": 50050,
      "protocol": "HTTPS",
      "direction": "outbound",
      "bytes_sent": 4821,
      "bytes_received": 187432,
      "connection_count": 12,
      "interval_seconds": [60, 58, 61, 59, 62, 60, 57, 61, 60, 63, 59, 60],
      "process_name": "rundll32.exe",
      "process_id": "5532",
      "parent_process": "svchost.exe",
      "beacon_jitter": false,
      "username": "CORP\\testuser",
      "session_start": "2026-06-25T21:00:00Z"
    }
  }'
```

**Expected behavior:** Four enrichment sources fire in parallel. Beacon CV calculated — intervals at ~60s give CV ≈ 0.027 → CONSISTENT_BEACON. Port 50050 flags as known C2 port. Composite score calculated. If score >= 65, host isolated, process killed via RTR, firewall block applied to all hosts. TheHive P1 case created. Slack critical channel alerted.

---

## Interview Talking Points

> "PB-08 is the C2 beaconing playbook and it has two architectural features that go beyond what most teams build. The first is statistical beacon interval analysis — I pull the array of connection timestamps, calculate the mean interval, standard deviation, and coefficient of variation, and classify the beacon type as CONSISTENT, JITTER, or IRREGULAR. A legitimate NTP sync or monitoring heartbeat has near-zero variance. A Cobalt Strike beacon set to 60 seconds with 20% jitter has a coefficient of variation around 0.12. A human browsing the web has CV above 0.5. That classification adds confidence to the score but doesn't trigger containment alone — it needs corroborating evidence from the enrichment layer. The second feature is Shodan fingerprinting. VirusTotal and AbuseIPDB tell you what happened in the past. Shodan tells you what the server looks like right now — open ports, SSL certificate CN, infrastructure tags. A server with port 50050 open and a self-signed cert whose CN is a Cobalt Strike default is identifiably C2 infrastructure even if it was deployed 20 minutes ago and has zero VT reports. The containment fires two parallel actions: CrowdStrike RTR kills the PID directly, and the firewall block applies to all hosts — not just the infected endpoint — because if the attacker has other implants on the network, they get cut off preemptively."

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Subtechnique | Name |
|---|---|---|---|
| Command and Control | T1071 | T1071.001 | Application Layer Protocol: Web Protocols |
| Command and Control | T1071 | T1071.004 | Application Layer Protocol: DNS |
| Command and Control | T1573 | T1573.002 | Encrypted Channel: Asymmetric Cryptography |
| Command and Control | T1105 | — | Ingress Tool Transfer |
| Command and Control | T1568 | — | Dynamic Resolution |
| Defense Evasion | T1218 | — | System Binary Proxy Execution (LOLBins) |

---

*Part of the Autonomous IR Pipeline — 10-playbook production SOAR project.*  
*Previous: [PB-07 — Critical CVE Detection & Patch Ticketing](../pb07/) | Next: [PB-09 — Insider Threat Privileged Anomaly](../pb09/)*
