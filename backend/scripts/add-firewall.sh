#!/bin/bash
# Add firewall rules script
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARTIFACTS_PATH="${ARTIFACTS_PATH:-/workspaces/cns/artifacts}"
OUTPUT_FILE="${ARTIFACTS_PATH}/firewall-${TARGET}-${TIMESTAMP}.log"

echo "Configuring firewall rules for $TARGET" | tee "$OUTPUT_FILE"
echo "Timestamp: $(date)" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

{
    echo "=== Basic Firewall Configuration (Simulated) ==="
    echo ""
    echo "1. Allow established/related connections:"
    echo "   iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
    echo ""
    echo "2. Allow SSH access (port 22):"
    echo "   iptables -A INPUT -p tcp --dport 22 -j ACCEPT"
    echo ""
    echo "3. Allow HTTP/HTTPS (ports 80, 443):"
    echo "   iptables -A INPUT -p tcp --dport 80 -j ACCEPT"
    echo "   iptables -A INPUT -p tcp --dport 443 -j ACCEPT"
    echo ""
    echo "4. Rate limit ICMP (ping):"
    echo "   iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT"
    echo "   iptables -A INPUT -p icmp -j DROP"
    echo ""
    echo "5. Drop invalid packets:"
    echo "   iptables -A INPUT -m state --state INVALID -j DROP"
    echo ""
    echo "6. Log and drop all other traffic:"
    echo "   iptables -A INPUT -j LOG --log-prefix 'FW-DROP: ' --log-level 4"
    echo "   iptables -A INPUT -j DROP"
    echo ""
    echo "Status: Firewall rules configured successfully (simulation mode)"
    echo ""
    echo "NOTE: In production, these rules would be applied with root privileges"
    echo "      using: sudo iptables [commands]"
} 2>&1 | tee -a "$OUTPUT_FILE"

echo ""
echo "Firewall configuration completed"
echo "ARTIFACT: $OUTPUT_FILE"
exit 0