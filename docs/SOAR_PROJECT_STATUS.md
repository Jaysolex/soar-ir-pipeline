
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
