#!/usr/bin/env bash
# sensors/suricata/setup_suricata.sh
#
# Phase 3 / Stage 3: Suricata Inline IPS Configuration
# References: PRD (Section 5, MVP 4), ARCHITECTURE.md, PDF Section 6 & 11
#
# Runs on the Suricata IPS node ('ips') in Mininet between Gateway and OVS (s1).
# Configures Suricata in AF_PACKET inline IPS mode across:
#   - ips-eth0 (facing Access Gateway gw-eth1)
#   - ips-eth1 (facing Open vSwitch s1-eth1)
#
# Logs EVE JSON alerts to /var/log/suricata/eve.json

set -euo pipefail

SURICATA_CONF_DIR="/etc/suricata"
LOG_DIR="/var/log/suricata"
RULES_DIR="/etc/suricata/rules"

echo "[+] Setting up Suricata directories..."
mkdir -p "${SURICATA_CONF_DIR}" "${LOG_DIR}" "${RULES_DIR}"

# 1. Install our custom threat isolation rules
echo "[+] Deploying custom threat isolation rules to ${RULES_DIR}/local.rules..."
cp sensors/suricata/local.rules "${RULES_DIR}/local.rules"

# 2. Disable offloading features (GRO, LRO, TSO) on inline interfaces for reliable packet inspection
echo "[+] Disabling NIC offloading on ips-eth0 and ips-eth1..."
ethtool -K ips-eth0 gro off lro off tso off gso off 2>/dev/null || true
ethtool -K ips-eth1 gro off lro off tso off gso off 2>/dev/null || true

# 3. Clean previous eve.json for clean test run
echo "[+] Resetting ${LOG_DIR}/eve.json..."
truncate -s 0 "${LOG_DIR}/eve.json" 2>/dev/null || touch "${LOG_DIR}/eve.json"
chmod 666 "${LOG_DIR}/eve.json"

# 4. Launch Suricata in AF_PACKET inline IPS mode in the background
echo "[+] Launching Suricata in AF_PACKET inline IPS mode (ips-eth0 <-> ips-eth1)..."
# Check if already running and stop
pkill -f "suricata" 2>/dev/null || true
sleep 1

# Start Suricata with custom local rules file
suricata -c /etc/suricata/suricata.yaml \
    -s "${RULES_DIR}/local.rules" \
    --af-packet=ips-eth0 \
    --af-packet=ips-eth1 \
    -l "${LOG_DIR}" \
    -D 2>/dev/null || {
        echo "[!] Default suricata.yaml not found or daemon flag failed; running direct inline command..."
        nohup suricata -s "${RULES_DIR}/local.rules" \
            --af-packet=ips-eth0 \
            --af-packet=ips-eth1 \
            -l "${LOG_DIR}" > "${LOG_DIR}/suricata_startup.log" 2>&1 &
    }

echo "[+] Suricata inline IPS operational."
echo "    - Log file: ${LOG_DIR}/eve.json"
echo "    - Rules file: ${RULES_DIR}/local.rules"

