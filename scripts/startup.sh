#!/bin/bash
echo "=== SOC Lab Startup: $(date) ==="

sudo sysctl -w vm.max_map_count=262144

echo "Starting Wazuh..."
cd ~/cyberlab/wazuh/single-node && docker-compose up -d
sleep 45

echo "Starting Shuffle..."
cd ~/cyberlab/shuffle && docker-compose up -d
sleep 30

echo "Starting TheHive..."
cd ~/cyberlab/thehive && docker-compose up -d
sleep 20

echo "Starting Wazuh Agent..."
sudo systemctl start wazuh-agent

echo "Fixing ossec.conf integration blocks..."
sleep 10
~/cyberlab/fix_ossec.sh

echo ""
echo "=== Status Check ==="
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "wazuh|shuffle|thehive"
echo ""
curl -k -s -o /dev/null -w "Shuffle: %{http_code}\n" https://192.168.238.132:3443
curl -s -o /dev/null -w "TheHive: %{http_code}\n" http://192.168.238.132:9000
echo ""
echo "=== Done: $(date) ==="
echo "Wazuh:   https://192.168.238.132"
echo "Shuffle: https://192.168.238.132:3443"
echo "TheHive: http://192.168.238.132:9000"
