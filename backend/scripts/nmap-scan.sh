#!/bin/bash
# Nmap port scan with service detection
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="/artifacts/nmap-${TARGET}-${TIMESTAMP}.xml"

# Validate target against whitelist
if ! grep -qx "$TARGET" /etc/lab_allowed_targets; then
    echo "ERROR: Target $TARGET not in allowed list"
    exit 1
fi

echo "Starting nmap scan of $TARGET"
echo "Output: $OUTPUT_FILE"

# Run nmap with safe options
nmap -sV \
     --top-ports 100 \
     --max-retries 1 \
     --host-timeout 5m \
     -oX "$OUTPUT_FILE" \
     "$TARGET"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "Scan completed successfully"
    echo "ARTIFACT: $OUTPUT_FILE"
else
    echo "Scan failed with exit code $EXIT_CODE"
fi

exit $EXIT_CODE