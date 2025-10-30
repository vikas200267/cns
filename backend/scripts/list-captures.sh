#!/bin/bash
# List saved packet captures
set -euo pipefail

ARTIFACTS_PATH="${ARTIFACTS_PATH:-/workspaces/cns/artifacts}"

echo "Available packet captures:"
echo "=========================="

# List all pcap files with metadata
if [ -d "$ARTIFACTS_PATH" ]; then
    find "$ARTIFACTS_PATH" -name "*.pcap" -type f 2>/dev/null | sort -r | while read filepath; do
        if [ -f "$filepath" ]; then
            filename=$(basename "$filepath")
            size=$(stat -f%z "$filepath" 2>/dev/null || stat -c%s "$filepath" 2>/dev/null || echo "0")
            size_mb=$(echo "scale=2; $size / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
            modified=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$filepath" 2>/dev/null || date -r "$filepath" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "unknown")
            echo "$modified | ${size_mb}MB | $filename"
        fi
    done
else
    echo "No artifacts directory found"
fi

echo ""
echo "ARTIFACT: $ARTIFACTS_PATH"

exit 0