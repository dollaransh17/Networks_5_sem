#!/usr/bin/env bash
# lab/gateway/setup_gateway.sh
#
# Access Gateway Policy Configuration
# Principle: Default Deny + Least Privilege + Rate Limiting
# References: PRD (Section 5), FEATURES.md (F1), AGENTS.md, DESIGN.md
#
# Runs locally on the Gateway node (Linux network namespace/host) in Mininet.
# Prevents unauthorized access and brute-force attempts BEFORE packets ever reach
# Suricata, Open vSwitch (s1), or the Protected Server.
#
# Network Addresses:
#   Test Client:      192.0.2.10
#   Protected Server: 198.51.100.20

set -euo pipefail

CLIENT_IP="192.0.2.10"
SERVER_IP="198.51.100.20"

echo "[+] Step 1: Ensure IPv4 forwarding is enabled on the gateway..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "[+] Step 2: Flush existing FORWARD chain rules..."
iptables -F FORWARD

echo "[+] Step 3: Set default policy to DROP (Default-Deny for all forwarded traffic)..."
# Any traffic not explicitly allowed below is discarded.
iptables -P FORWARD DROP

echo "[+] Step 4: Allow established and related connections..."
# Allows return packets for sessions that were initiated legally.
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[+] Step 5: Explicitly deny and log TCP port 22 (SSH) from Client to Server..."
# Explicit denial for unauthorized SSH management attempts.
# Log dropped packets with prefix 'GATEWAY_DENY: ' for downstream incident logger parsing.
# Rate limit the logging itself (e.g. max 5 log entries/sec) to protect disk and syslog from flood.
iptables -A FORWARD \
    -p tcp \
    -s "${CLIENT_IP}" \
    -d "${SERVER_IP}" \
    --dport 22 \
    -m limit --limit 5/sec --limit-burst 10 \
    -j LOG --log-prefix "GATEWAY_DENY: " --log-level 4

# Drop the unauthorized SSH packet immediately (does not reach OVS or increment switch counters)
iptables -A FORWARD \
    -p tcp \
    -s "${CLIENT_IP}" \
    -d "${SERVER_IP}" \
    --dport 22 \
    -j DROP

echo "[+] Step 6: Allow TCP port 443 (HTTPS) with rate limiting..."
# Least-privilege access: permit HTTPS to protected service.
# Uses iptables limit module to throttle excessive connection bursts (max 50/sec with burst 100).
iptables -A FORWARD \
    -p tcp \
    -s "${CLIENT_IP}" \
    -d "${SERVER_IP}" \
    --dport 443 \
    -m conntrack --ctstate NEW \
    -m limit --limit 50/sec --limit-burst 100 \
    -j ACCEPT

# Log excess connection attempts exceeding the rate limit on port 443
iptables -A FORWARD \
    -p tcp \
    -s "${CLIENT_IP}" \
    -d "${SERVER_IP}" \
    --dport 443 \
    -m conntrack --ctstate NEW \
    -m limit --limit 5/sec \
    -j LOG --log-prefix "GATEWAY_DENY: " --log-level 4

# Explicitly drop rate-exceeded port 443 attempts
iptables -A FORWARD \
    -p tcp \
    -s "${CLIENT_IP}" \
    -d "${SERVER_IP}" \
    --dport 443 \
    -j DROP

echo "[+] Step 7: Log all other unexpected/unauthorized packets prior to default drop..."
# Log unmatched packets (rate-limited to 10 entries per minute to prevent log storms)
iptables -A FORWARD \
    -m limit --limit 10/min \
    -j LOG --log-prefix "GATEWAY_DENY: " --log-level 4

echo "[+] Access Gateway firewall rules applied successfully."
echo "    - Default FORWARD policy: DROP"
echo "    - Allowed: TCP 443 (Client -> Server, <= 50 req/s)"
echo "    - Denied & Logged: TCP 22 (Client -> Server)"
echo "    - Log Prefix: 'GATEWAY_DENY: '"

