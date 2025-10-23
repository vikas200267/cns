#!/bin/bash
# List saved packet captures
set -euo pipefail

echo "Available packet captures:"
echo "=========================="

# List all pcap files with metadata
find /artifacts -name "*.pcap" -type f -printf "%T@ %s %p\n" | \
sort -rn | \
while read timestamp size filepath; do
    filename=$(basename "$filepath")
    size_mb=$(echo "scale=2; $size / 1024 / 1024" | bc)
    date=$(date -d "@${timestamp%.*}" "+%Y-%m-%d %H:%M:%S")
    echo "$date | ${size_mb}MB | $filename"
done

echo "ARTIFACT: /artifacts/"

exit 0