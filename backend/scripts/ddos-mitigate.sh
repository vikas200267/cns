#!/bin/bash
# DDoS mitigation script
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="/artifacts/ddos-mitigation-${TARGET}-${TIMESTAMP}.log"

# Validate target
if ! grep -qx "$TARGET" /etc/lab_allowed_targets; then
    echo "ERROR: Target $TARGET not in allowed list"
    exit 1
fi

echo "Applying DDoS mitigation for $TARGET"
echo "Output: $OUTPUT_FILE"

# Add iptables rules for basic DDoS mitigation
{
    echo "Adding rate limiting rules..."
    iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j DROP
    
    echo "Adding connection tracking rules..."
    iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 50/second --limit-burst 50 -j ACCEPT
    
    echo "Adding SYN flood protection..."
    iptables -A INPUT -p tcp --syn -m limit --limit 1/second -j ACCEPT
    
    echo "Rules added successfully."
} 2>&1 | tee "$OUTPUT_FILE"

echo "DDoS mitigation applied"
echo "ARTIFACT: $OUTPUT_FILE"
exit 0