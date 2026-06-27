# Autonomous Incident Response Pipeline
## 10-Playbook Production SOAR Suite

**Stack:** Wazuh · Shuffle · CrowdStrike Falcon · Microsoft 365 · Active Directory · VirusTotal · AbuseIPDB · Hybrid Analysis · MalwareBazaar · Shodan · URLhaus · MaxMind GeoIP · Tenable · AWS GuardDuty / CloudTrail · Azure Defender · Jira · TheHive · Slack

---

## Executive Summary

This repository contains a production-ready, 10-playbook automated incident response pipeline built on open-source and enterprise tooling. The suite automates triage, enrichment, and containment across the full MITRE ATT&CK kill chain — from initial access through exfiltration and impact.

Each playbook ingests structured JSON alerts from Wazuh SIEM via webhook, runs parallel multi-source enrichment, calculates a weighted composite threat score, and routes to automated containment or structured analyst escalation — all within seconds of alert fire.

| Metric | Manual SOC | This Pipeline |
|---|---|---|
| Mean Time to Enrich (MTTE) | 15–30 min | < 10 seconds |
| Mean Time to Contain (MTTC) | 30–90 min | < 5 seconds (automated path) |
| Analyst touchpoint required | Every alert | High-confidence threats only |
| Threat intelligence sources | 1–2 per alert | 3–5 parallel per alert |

---

## Architecture

```
[ Enterprise Security Stack ]
Endpoints · Email Gateway · Network · Cloud · Identity
          │
          ▼ (Windows Events / Syslog / CloudTrail / DLP)
    [ Wazuh SIEM ]
    Custom Detection Rules (100001–100095)
    ossec.conf integration blocks
          │
          ▼ (Async JSON webhook POST per playbook)
    [ Shuffle SOAR ]
    10 webhook endpoints
    Parallel enrichment nodes
    Weighted composite scoring
    Conditional containment routing
          │
    ┌─────┼──────────────────────────────────────┐
    ▼     ▼              ▼              ▼         ▼
[ VT ] [ AbuseIPDB ] [ Shodan ]  [ AD/Azure ] [ AWS/Azure ]
[ HA ] [ MaxMind   ] [ URLhaus ] [ M365     ] [ Config   ]
[ MB ] [ NVD/CISA  ] [ Tenable] [ Jira     ] [ GuardDuty]
          │
    ┌─────┼─────────────────┐
    ▼     ▼                 ▼
[ CrowdStrike ] [ Firewall ] [ M365 Graph ]
  EDR contain    IP/domain    Mailbox purge
  RTR kill PID   block        Session revoke
  File quarantine all hosts   MFA enforce
          │
    [ TheHive ]    [ Jira ]    [ Slack ]
    IR cases       Vuln/cloud  SOC/mgr alerts
    CONFIDENTIAL   tickets     Critical channel
```

---

## Playbook Suite

| ID | Playbook | Severity | Auto-Contain | Key Enrichment | MITRE |
|---|---|---|---|---|---|
| PB-01 | Phishing Triage & Containment | Critical | Yes (score ≥ 75) | VT · AbuseIPDB · AD | T1566 |
| PB-02 | Brute Force & Account Lockout | Critical | Yes (score ≥ 70) | AbuseIPDB · MaxMind · AD | T1110 |
| PB-03 | Ransomware Detection & Isolation | Critical P1 | Yes + Zero-tolerance | VT · Hybrid Analysis · Wazuh API | T1486 · T1490 |
| PB-04 | Malware Hash Enrichment & Quarantine | High | Yes (score ≥ 60) | VT · HA · MalwareBazaar · Wazuh API | T1059 · T1204 |
| PB-05 | Impossible Travel & Suspicious Login | High | Yes (score ≥ 65) | MaxMind · AbuseIPDB · AD · Haversine | T1078 |
| PB-06 | Data Exfiltration Alert Triage | High/Critical | Yes (score ≥ 70) | VT · MaxMind · AD HR signals · M365 Audit | T1048 · T1567 |
| PB-07 | Critical CVE Detection & Patch Ticketing | High/Critical | Jira auto-ticket | NVD · CISA KEV · Tenable ACR | T1190 |
| PB-08 | C2 Beaconing & Outbound Block | Critical P1 | Yes + Zero-tolerance | VT · AbuseIPDB · Shodan · URLhaus | T1071 · T1573 |
| PB-09 | Insider Threat Privileged Anomaly | High/Critical | Yes (score ≥ 70) | AD · Wazuh baseline · Jira change mgmt · M365 | T1070 · T1078 |
| PB-10 | Cloud Misconfiguration Triage | High/Critical | Yes (score ≥ 65) | AWS Config · IAM · Azure ARM · GuardDuty | T1530 · T1578 |

---

## Repository Structure

```
soar-ir-pipeline/
├── .github/workflows/           # Optional CI/CD
├── docker/
│   └── docker-compose.yml       # Full stack orchestration
├── wazuh/
│   ├── ossec.conf               # All 10 SOAR integration blocks
│   └── rules/
│       ├── pb01_phishing_rules.xml
│       ├── pb02_bruteforce_rules.xml
│       ├── pb03_ransomware_rules.xml
│       ├── pb04_malware_rules.xml
│       ├── pb05_impossible_travel_rules.xml
│       ├── pb06_exfiltration_rules.xml
│       ├── pb07_cve_rules.xml
│       ├── pb08_c2_rules.xml
│       ├── pb09_insider_threat_rules.xml
│       └── pb10_cloud_rules.xml
├── shuffle/
│   ├── pb01_phishing_playbook.json
│   ├── pb02_bruteforce_playbook.json
│   ├── pb03_ransomware_playbook.json
│   ├── pb04_malware_playbook.json
│   ├── pb05_impossible_travel_playbook.json
│   ├── pb06_exfiltration_playbook.json
│   ├── pb07_cve_playbook.json
│   ├── pb08_c2_playbook.json
│   ├── pb09_insider_threat_playbook.json
│   └── pb10_cloud_playbook.json
└── docs/
    ├── PB-01_README.md
    ├── PB-02_README.md
    ├── PB-03_README.md
    ├── PB-04_README.md
    ├── PB-05_README.md
    ├── PB-06_README.md
    ├── PB-07_README.md
    ├── PB-08_README.md
    ├── PB-09_README.md
    └── PB-10_README.md
```

---

## Deployment

### Prerequisites

- Docker Engine v20.10+
- Docker Compose v2.20+
- 16GB RAM minimum (32GB recommended for full stack)
- API keys: VirusTotal, AbuseIPDB, Hybrid Analysis, MalwareBazaar, Shodan, MaxMind, NVD, CrowdStrike, Microsoft Graph, Active Directory service account, Tenable, Jira, TheHive, Slack webhooks, AWS IAM service account, Azure service principal

### Stack Launch

```bash
git clone https://github.com/yourusername/soar-ir-pipeline.git
cd soar-ir-pipeline
cp .env.example .env
# Populate .env with your API keys
docker-compose -f docker/docker-compose.yml up -d
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Import All Playbooks

```bash
for pb in shuffle/pb*.json; do
  curl -X POST http://localhost:5001/api/v1/workflows/import \
    -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    -F "file=@$pb"
  echo "Imported: $pb"
done
```

### Deploy Wazuh Rules

```bash
cp wazuh/rules/*.xml /var/ossec/etc/rules/
# Add integration blocks from wazuh/ossec.conf to /var/ossec/etc/ossec.conf
docker exec wazuh-manager-production /var/ossec/bin/wazuh-control restart
```

---

## Detection Rule Summary

60 custom Wazuh detection rules across 10 rule files. Rule ID range: 100001–100095.

| File | Rules | Coverage |
|---|---|---|
| pb01_phishing_rules.xml | 100001–100005 | Email gateway, attachment types, urgency keywords, malicious IPs |
| pb02_bruteforce_rules.xml | 100010–100015 | Failed auth patterns, spray, credential stuffing, geo-anomaly |
| pb03_ransomware_rules.xml | 100020–100025 | File encryption, ransom notes, VSS deletion, known binaries |
| pb04_malware_rules.xml | 100030–100035 | Temp directory execution, unsigned binaries, encoded PS, macros |
| pb05_impossible_travel_rules.xml | 100040–100045 | Multi-country auth, off-hours foreign, Tor login, Azure AD risky |
| pb06_exfiltration_rules.xml | 100050–100055 | Large transfers, unapproved cloud, mass file access, DNS tunnel |
| pb07_cve_rules.xml | 100060–100065 | CVSS 9+, KEV, SLA breach, RCE class, missing patches |
| pb08_c2_rules.xml | 100070–100075 | Beaconing intervals, C2 ports, Cobalt Strike, LOLBin egress |
| pb09_insider_threat_rules.xml | 100080–100085 | Off-hours admin, lateral spread, AD modification, log clearing |
| pb10_cloud_rules.xml | 100090–100095 | Public S3, open SGs, root account, Azure NSG, GuardDuty, IAM |

---

## Threat Intelligence Sources Used

| Source | Used In | What It Provides |
|---|---|---|
| VirusTotal | PB-01/04/06/08/10 | File hash reputation, IP/domain reputation, C2 tags |
| AbuseIPDB | PB-01/02/05/06/08 | IP abuse confidence score, Tor flag, usage type |
| Hybrid Analysis | PB-03/04 | Sandbox detonation, MITRE TTPs, C2 network indicators |
| MalwareBazaar | PB-04/08 | Community malware intel, delivery method, campaign tags |
| URLhaus | PB-08 | C2 URL and malware distribution infrastructure |
| Shodan | PB-08 | Port fingerprinting, SSL cert CN, C2 infrastructure tags |
| MaxMind GeoIP | PB-02/05/06 | Country/city resolution, ASN, hosting provider flag |
| NVD API | PB-07 | Full CVE description, CVSS v3.1 vector breakdown |
| CISA KEV | PB-07 | Active exploitation confirmation, ransomware use flag |
| Tenable | PB-07 | Asset Criticality Rating, open vulnerability counts |
| AWS Config | PB-07/10 | Resource metadata, compliance state, tagging |
| AWS GuardDuty | PB-10 | Active threat findings, severity scoring |
| Azure Defender | PB-10 | Azure misconfiguration and threat detection |

---

## Summary

This repository demonstrates:

- **Full kill-chain coverage** — Initial Access through Impact across 10 distinct threat categories
- **Production architecture** — Docker orchestration, secret management, webhook ingestion, parallel async enrichment
- **Weighted scoring models** — custom composite scores per playbook, not generic CVSS passthrough
- **Zero-tolerance design** — specific indicators that bypass scoring for immediate action (shadow copy deletion, Cobalt Strike signatures, log tampering, root account usage)
- **False positive mitigation** — frequent traveler AD flags, behavioral baselines, change ticket correlation, Jira duplicate checks
- **Legal and HR awareness** — insider threat confidentiality, tiered containment, manager notification before subject contact
- **Cloud-native thinking** — resource tag-driven severity, auto-remediation via AWS/Azure APIs, systemic misconfiguration scope scanning
- **Statistical analysis** — beacon interval coefficient of variation, haversine travel velocity calculation
- **Multi-tool orchestration** — 13+ threat intel sources, 5+ containment platforms, 3 case management systems
