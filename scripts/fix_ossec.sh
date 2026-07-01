#!/bin/bash
echo "Fixing ossec.conf integration blocks..."

docker exec single-node_wazuh.manager_1 python3 -c "
content = open('/var/ossec/etc/ossec.conf').read()
old = '''<ossec_config>
  <integration>
    <name>shuffle</name>
    <hook_url>https://192.168.238.132:3443/api/v1/hooks/bc89974a-7068-4085-86e9-ad6977829849</hook_url>
    <alert_format>json</alert_format>
    <level>3</level>
  </integration>
</ossec_config>'''
content = content.replace(old, '')
# Also remove any stale 10-block sections to avoid duplicates
import re
content = re.sub(r'<ossec_config>\s*<integration>\s*<name>shuffle</name>.*?</ossec_config>', '', content, flags=re.DOTALL)
open('/var/ossec/etc/ossec.conf', 'w').write(content)
print('Cleaned old blocks')
"

docker exec single-node_wazuh.manager_1 bash -c "cat >> /var/ossec/etc/ossec.conf << 'OSSECEOF'
<ossec_config>
  <integration>
    <name>shuffle</name>
    <hook_url>http://192.168.238.132:3001/api/v1/hooks/webhook_95d1c723-6427-4051-bd60-5dcc3628d8cb</hook_url>
    <alert_format>json</alert_format>
    <level>10</level>
  </integration>
  <integration>
    <name>shuffle</name>
    <hook_url>http://192.168.238.132:3001/api/v1/hooks/webhook_c231ee64-16d6-4ce8-b3a6-fede82c87c03</hook_url>
    <alert_format>json</alert_format>
    <level>10</level>
  </integration>
  <integration>
    <name>shuffle</name>
    <hook_url>http://192.168.238.132:3001/api/v1/hooks/webhook_c2b931c2-bdd6-43b4-9708-9e25b54b2588</hook_url>
    <alert_format>json</alert_format>
    <level>12</level>
  </integration>
  <integration>
    <name>shuffle</name>
    <hook_url>http://192.168.238.132:3001/api/v1/hooks/webhook_2531c4b4-c09d-432a-8a88-d0534333c5cc</hook_url>
    <alert_format>json</alert_format>
    <level>11</level>
  </integration>
  <integration>
    <name>shuffle</name>
    <hook_url>http://192.168.238.132:3001/api/v1/hooks/webhook_d7bbc83b-0a10-4b61-b931-5541cc59a674</hook_url>
    <alert_format>json</alert_format>
    <level>11</level>
  </integration>
  <integration>
    <name>shuffle</name>
    <hook_url>http://192.168.238.132:3001/api/v1/hooks/webhook_92e64d04-8eb6-4e53-b5ea-d79b402dd9d5</hook_url>
    <alert_format>json</alert_format>
    <level>12</level>
  </integration>
  <integration>
    <name>shuffle</name>
    <hook_url>http://192.168.238.132:3001/api/v1/hooks/webhook_c905e648-71ca-47f5-8365-b324e7c5b077</hook_url>
    <alert_format>json</alert_format>
    <level>11</level>
  </integration>
  <integration>
    <name>shuffle</name>
    <hook_url>http://192.168.238.132:3001/api/v1/hooks/webhook_9e3753f5-98f4-4f1c-9c01-6606ba595eba</hook_url>
    <alert_format>json</alert_format>
    <level>12</level>
  </integration>
  <integration>
    <name>shuffle</name>
    <hook_url>http://192.168.238.132:3001/api/v1/hooks/webhook_a13cdb07-14ff-43a9-a703-3f102912b826</hook_url>
    <alert_format>json</alert_format>
    <level>12</level>
  </integration>
  <integration>
    <name>shuffle</name>
    <hook_url>http://192.168.238.132:3001/api/v1/hooks/webhook_15bb9f38-f7fb-470c-88e3-c8a6b2b6b32b</hook_url>
    <alert_format>json</alert_format>
    <level>13</level>
  </integration>
</ossec_config>
OSSECEOF"

docker exec single-node_wazuh.manager_1 grep -c "hook_url" /var/ossec/etc/ossec.conf
docker exec single-node_wazuh.manager_1 /var/ossec/bin/wazuh-control restart 2>&1 | grep -E "Completed|ERROR|CRITICAL"
echo "ossec.conf fix complete"
