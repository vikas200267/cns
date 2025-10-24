#!/bin/bash
# Start packet capture for 60 seconds
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARTIFACTS_PATH="${ARTIFACTS_PATH:-/workspaces/cns/artifacts}"
OUTPUT_FILE="${ARTIFACTS_PATH}/capture-${TARGET}-${TIMESTAMP}.pcap"
PID_FILE="${ARTIFACTS_PATH}/capture-${TARGET}.pid"

# Check if capture already running
if [ -f "$PID_FILE" ]; then
    echo "ERROR: Capture already running for $TARGET"
    exit 1
fi

echo "Starting packet capture for traffic to/from $TARGET (60 seconds)"
echo "Output: $OUTPUT_FILE"
echo ""
echo "NOTE: Packet capture requires root/sudo privileges"
echo ""

# Start tcpdump capture with timeout
# Note: May require sudo privileges
timeout 60 sudo tcpdump \
    -i any \
    -w "$OUTPUT_FILE" \
    host "$TARGET" \
    2>&1 &

TCPDUMP_PID=$!
echo $TCPDUMP_PID > "$PID_FILE"

echo "Capture started with PID: $TCPDUMP_PID"
echo "Capturing for 60 seconds..."

# Wait for capture to complete
wait $TCPDUMP_PID || true
EXIT_CODE=$?

# Clean up PID file
rm -f "$PID_FILE"

if [ -f "$OUTPUT_FILE" ]; then
    PACKETS=$(sudo tcpdump -r "$OUTPUT_FILE" 2>/dev/null | wc -l || echo "0")
    echo ""
    echo "Capture completed"
    echo "Captured $PACKETS packets"
    echo "ARTIFACT: $OUTPUT_FILE"
    echo ""
    echo "=== First 10 packets ==="
    sudo tcpdump -r "$OUTPUT_FILE" -n -c 10 2>/dev/null || echo "No packets captured"
    exit 0
else
    echo "Capture failed - no output file created"
    exit 1
fi