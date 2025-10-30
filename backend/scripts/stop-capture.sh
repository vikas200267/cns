#!/bin/bash
# Stop active packet capture
set -euo pipefail

TARGET="$1"
ARTIFACTS_PATH="${ARTIFACTS_PATH:-/workspaces/cns/artifacts}"
PID_FILE="${ARTIFACTS_PATH}/capture-${TARGET}.pid"

# Check if capture is running
if [ ! -f "$PID_FILE" ]; then
    echo "No active capture found for $TARGET"
    exit 0
fi

# Read PID and kill process
TSHARK_PID=$(cat "$PID_FILE")
echo "Stopping capture (PID: $TSHARK_PID)"

if kill -0 $TSHARK_PID 2>/dev/null; then
    kill -TERM $TSHARK_PID
    echo "Capture stopped"
else
    echo "Capture process not found (may have already finished)"
fi

# Clean up PID file
rm -f "$PID_FILE"

exit 0