#!/bin/bash
# Nikto web vulnerability scan
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="/artifacts/nikto-${TARGET}-${TIMESTAMP}.txt"

# Validate target
if ! grep -qx "$TARGET" /etc/lab_allowed_targets; then
    echo "ERROR: Target $TARGET not in allowed list"
    exit 1
fi

echo "Starting nikto scan of http://$TARGET"
echo "Output: $OUTPUT_FILE"

# Run nikto with timeout and throttling
timeout 120 nikto \
    -host "http://$TARGET" \
    -timeout 10 \
    -maxtime 120 \
    -output "$OUTPUT_FILE"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 124 ]; then
    echo "Scan completed (timeout is normal)"
    echo "ARTIFACT: $OUTPUT_FILE"
    exit 0
else
    echo "Scan failed with exit code $EXIT_CODE"
    exit $EXIT_CODE
fi