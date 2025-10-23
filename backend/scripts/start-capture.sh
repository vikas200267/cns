#!/bin/bash
# Start packet capture for 60 seconds
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="/artifacts/capture-${TARGET}-${TIMESTAMP}.pcap"
PID_FILE="/artifacts/capture-${TARGET}.pid"

# Validate target
if ! grep -qx "$TARGET" /etc/lab_allowed_targets; then
    echo "ERROR: Target $TARGET not in allowed list"
    exit 1
fi

# Check if capture already running
if [ -f "$PID_FILE" ]; then
    echo "ERROR: Capture already running for $TARGET"
    exit 1
fi

echo "Starting packet capture for $TARGET (60 seconds)"
echo "Output: $OUTPUT_FILE"

# Start tshark capture in background with timeout
timeout 60 tshark \
    -i any \
    -f "host $TARGET" \
    -w "$OUTPUT_FILE" \
    2>&1 &

TSHARK_PID=$!
echo $TSHARK_PID > "$PID_FILE"

# Wait for capture to complete
wait $TSHARK_PID
EXIT_CODE=$?

# Clean up PID file
rm -f "$PID_FILE"

if [ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 124 ]; then
    echo "Capture completed"
    echo "ARTIFACT: $OUTPUT_FILE"
    exit 0
else
    echo "Capture failed with exit code $EXIT_CODE"
    exit $EXIT_CODE
fi