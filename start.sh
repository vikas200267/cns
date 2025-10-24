#!/bin/bash

# CNS Lab Control System - Detached Startup Script
# This script starts all services in the background and exits

echo "======================================"
echo "CNS Lab Control System - Starting Services"
echo "======================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to kill process on a port
kill_port() {
    local port=$1
    local pid=$(lsof -ti :$port)
    if [ ! -z "$pid" ]; then
        echo -e "${YELLOW}Killing existing process on port $port (PID: $pid)${NC}"
        kill -9 $pid 2>/dev/null
        sleep 1
    fi
}

echo -e "${GREEN}Step 1: Cleaning up existing processes...${NC}"
kill_port 3000
kill_port 3001

echo ""
echo -e "${GREEN}Step 2: Starting Backend Service (Port 3001)...${NC}"

# Start backend
cd /workspaces/cns/backend

# Create logs directory if it doesn't exist
mkdir -p logs

# Start backend in background with nohup
nohup node app.js > logs/backend.log 2>&1 &
BACKEND_PID=$!
echo -e "${GREEN}✓ Backend started (PID: $BACKEND_PID)${NC}"

# Wait for backend to be ready
echo -e "${YELLOW}Waiting for backend to be ready...${NC}"
for i in {1..30}; do
    if lsof -i :3001 >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Backend is ready on port 3001${NC}"
        break
    fi
    sleep 1
done

echo ""
echo -e "${GREEN}Step 3: Starting Frontend Service (Port 3000)...${NC}"

# Start frontend
cd /workspaces/cns/frontend

# Start frontend in background with nohup
nohup npm start > /tmp/frontend.log 2>&1 &
FRONTEND_PID=$!
echo -e "${GREEN}✓ Frontend started (PID: $FRONTEND_PID)${NC}"

# Wait for frontend to be ready
echo -e "${YELLOW}Waiting for frontend to be ready...${NC}"
for i in {1..60}; do
    if lsof -i :3000 >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Frontend is ready on port 3000${NC}"
        break
    fi
    sleep 1
done

echo ""
echo -e "${GREEN}======================================"
echo "✓ All services started successfully!"
echo "======================================${NC}"
echo ""
echo "Services running:"
echo "  - Backend:  http://localhost:3001 (PID: $BACKEND_PID)"
echo "  - Frontend: http://localhost:3000 (PID: $FRONTEND_PID)"
echo ""
echo "Access the application:"
echo "  - Local: http://localhost:3000"
echo "  - Public: Check VS Code Ports tab for forwarded URL"
echo ""
echo "API Keys:"
echo "  - Operator: op_1234567890abcdef"
echo "  - Admin:    adm_fedcba0987654321"
echo ""
echo "To stop all services, run: ./stop.sh"
echo "To view logs:"
echo "  - Backend:  tail -f /workspaces/cns/backend/logs/backend.log"
echo "  - Frontend: tail -f /tmp/frontend.log"
echo ""
