#!/bin/bash
# Nikto web vulnerability scan
set -euo pipefail

TARGET="$1"
PORT="${2:-80}"  # Default to port 80 if not specified
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARTIFACTS_PATH="${ARTIFACTS_PATH:-/workspaces/cns/artifacts}"
OUTPUT_FILE="${ARTIFACTS_PATH}/nikto-${TARGET}-${TIMESTAMP}.txt"

echo "Starting nikto scan of http://$TARGET:$PORT"
echo "Output: $OUTPUT_FILE"
echo ""

# Ensure artifacts directory exists
mkdir -p "$ARTIFACTS_PATH"

# Run nikto with timeout and throttling (15 minutes = 900 seconds)
timeout 900 /usr/bin/nikto.pl \
    -host "$TARGET" \
    -port "$PORT" \
    -timeout 30 \
    -maxtime 900 \
    -output "$OUTPUT_FILE" 2>&1 || true

EXIT_CODE=$?

# Nikto returns various exit codes, 0 or 124 (timeout) are acceptable
if [ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 124 ]; then
    echo ""
    echo "Scan completed (timeout is normal for thorough scans)"
    echo "ARTIFACT: $OUTPUT_FILE"
    echo ""
    if [ -f "$OUTPUT_FILE" ]; then
        echo "=== Scan Results (first 50 lines) ==="
        head -50 "$OUTPUT_FILE"
    fi
    exit 0
else
    echo "Scan failed with exit code $EXIT_CODE"
    exit $EXIT_CODE
fi