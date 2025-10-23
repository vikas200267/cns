#!/bin/bash
# Lab runner entrypoint - validates environment before executing scripts
set -euo pipefail

# Validate allowed targets file exists
if [ ! -f /etc/lab_allowed_targets ]; then
    echo "ERROR: Allowed targets file not found at /etc/lab_allowed_targets"
    exit 1
fi

# Validate artifacts directory exists (write permission checked by individual scripts if needed)
if [ ! -d /artifacts ]; then
    echo "ERROR: Artifacts directory /artifacts not found"
    exit 1
fi

# Execute the requested script
if [ $# -eq 0 ]; then
    echo "ERROR: No script specified"
    exit 1
fi

SCRIPT="$1"
shift

# Validate script exists
if [ ! -f "/usr/local/bin/scripts/$SCRIPT" ]; then
    echo "ERROR: Script $SCRIPT not found"
    exit 1
fi

# Execute script with remaining arguments
exec "/usr/local/bin/scripts/$SCRIPT" "$@"