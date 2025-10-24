#!/bin/bash

# CNS Lab Control System - Stop Script
# This script stops all services

echo "Stopping CNS Lab Control System..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to kill process on a port
kill_port() {
    local port=$1
    local pid=$(lsof -ti :$port)
    if [ ! -z "$pid" ]; then
        echo -e "${GREEN}Stopping process on port $port (PID: $pid)${NC}"
        kill -9 $pid 2>/dev/null
        sleep 1
    else
        echo "No process found on port $port"
    fi
}

# Kill processes by port
echo "Stopping Backend (port 3001)..."
kill_port 3001

echo "Stopping Frontend (port 3000)..."
kill_port 3000

# Also try to kill by PID files if they exist
if [ -f "/tmp/cns_backend.pid" ]; then
    BACKEND_PID=$(cat /tmp/cns_backend.pid)
    if ps -p $BACKEND_PID > /dev/null 2>&1; then
        echo "Killing backend PID: $BACKEND_PID"
        kill -9 $BACKEND_PID 2>/dev/null
    fi
    rm /tmp/cns_backend.pid
fi

if [ -f "/tmp/cns_frontend.pid" ]; then
    FRONTEND_PID=$(cat /tmp/cns_frontend.pid)
    if ps -p $FRONTEND_PID > /dev/null 2>&1; then
        echo "Killing frontend PID: $FRONTEND_PID"
        kill -9 $FRONTEND_PID 2>/dev/null
    fi
    rm /tmp/cns_frontend.pid
fi

# Kill any remaining node processes related to the project
pkill -f "node.*app.js" 2>/dev/null
pkill -f "react-scripts start" 2>/dev/null

echo -e "${GREEN}All services stopped.${NC}"
