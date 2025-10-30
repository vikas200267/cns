#!/bin/bash
# Nmap port scan with service detection
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARTIFACTS_PATH="${ARTIFACTS_PATH:-/workspaces/cns/artifacts}"
OUTPUT_FILE="${ARTIFACTS_PATH}/nmap-${TARGET}-${TIMESTAMP}.xml"
OUTPUT_TXT="${ARTIFACTS_PATH}/nmap-${TARGET}-${TIMESTAMP}.txt"

echo "Starting nmap scan of $TARGET"
echo "Output files:"
echo "  XML: $OUTPUT_FILE"
echo "  TXT: $OUTPUT_TXT"
echo ""

# Ensure artifacts directory exists
mkdir -p "$ARTIFACTS_PATH"

# Run nmap with safe options
# Using -sT (TCP connect scan) without version detection to avoid NSE errors
nmap -sT \
     --top-ports 100 \
     --max-retries 1 \
     --host-timeout 5m \
     -oX "$OUTPUT_FILE" \
     -oN "$OUTPUT_TXT" \
     "$TARGET"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "Scan completed successfully"
    echo "ARTIFACT: $OUTPUT_TXT"
    echo ""
    echo "=== Scan Results ==="
    cat "$OUTPUT_TXT"
else
    echo "Scan failed with exit code $EXIT_CODE"
fi

exit $EXIT_CODE