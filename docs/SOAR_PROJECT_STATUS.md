
---

## UPDATE — TheHive Installed & Connected

TheHive 5.2 deployed via Docker on SIEMserver. SOC-Lab organisation created with org-admin user. API key generated and authenticated in Shuffle (green/connected status confirmed). Full pipeline now operational:

Wazuh → Shuffle → TheHive

All 10 playbook webhooks reconfirmed working after a system reboot (Docker network IP reassignment issue resolved by restarting the Shuffle stack).

**Remaining:**
- Real Kali attack simulations (Hydra brute force, ransomware file-rename, Metasploit C2)
- Enrichment API keys (VirusTotal, AbuseIPDB, Shodan, etc.)
- Screenshot capture for all 10 playbooks
- Final GitHub polish (repo description, topics, pinning)

---

## UPDATE — Real End-to-End Attack Confirmed Working

Fixed critical issue: wazuh-integratord was failing on SSL certificate verification against Shuffle's self-signed cert on port 3443. Resolved by switching all 10 integration webhook URLs to plain HTTP on port 3001.

Also fixed PB-02 detection rules — original rules were written against synthetic JSON field names that do not exist in real Wazuh-decoded Windows Security events. Rewrote PB-02 rules to match real Wazuh native fields (win.system.eventID, if_sid chaining against built-in rule 60122) using frequency/timeframe for brute force threshold detection.

**Real attack test confirmed via Shuffle Execution UI:**
- Created test account soctest on CLIENT01
- Generated failed logon bursts via net use against soctest with wrong passwords
- Wazuh rule 100011 fired correctly at Level 10 with MITRE-mapped Windows event data
- Shuffle execution shows Status: FINISHED with full real alert payload including win.system and win.eventdata fields (31 total fields captured)
- Two confirmed executions at 09:51:55 and 09:52:24 UTC matching the exact timing of the PowerShell brute force commands

This is the first fully verified real-world (non-curl) end-to-end detection in the lab:
Real Windows attack -> Wazuh agent -> Wazuh rule engine -> wazuh-integratord -> Shuffle webhook -> Playbook execution -> FINISHED

**Remaining:**
- Apply the same real-Wazuh-field fix used for PB-02 to PB-01, PB-03 through PB-10 (currently only PB-02 confirmed against real Windows telemetry)
- Real Kali attack simulations for remaining playbooks (ransomware file-rename, Metasploit C2)
- Enrichment API keys (VirusTotal, AbuseIPDB, Shodan, etc.)
- Screenshot capture for all 10 playbooks
- Final GitHub polish (repo description, topics, pinning)
