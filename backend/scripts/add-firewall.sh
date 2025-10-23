#!/bin/bash
# Add firewall rules script
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="/artifacts/firewall-${TARGET}-${TIMESTAMP}.log"

# Validate target
if ! grep -qx "$TARGET" /etc/lab_allowed_targets; then
    echo "ERROR: Target $TARGET not in allowed list"
    exit 1
fi

echo "Adding firewall rules for $TARGET"
echo "Output: $OUTPUT_FILE"

{
    echo "Configuring basic firewall rules..."
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH (port 22)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow HTTP/HTTPS (ports 80, 443)
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # Rate limit ICMP (ping)
    iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT
    
    # Drop invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP
    
    # Log and drop everything else
    iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: "
    iptables -A INPUT -j DROP
    
    echo "Firewall rules added successfully."
} 2>&1 | tee "$OUTPUT_FILE"

echo "Firewall configuration completed"
echo "ARTIFACT: $OUTPUT_FILE"
exit 0