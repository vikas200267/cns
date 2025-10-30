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
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if rebuild flag is passed
REBUILD=false
if [ "$1" == "--rebuild" ] || [ "$1" == "-r" ]; then
    REBUILD=true
fi

if [ "$REBUILD" = true ]; then
    echo -e "${BLUE}Step 0a: Rebuilding Frontend...${NC}"
    cd /workspaces/cns/frontend
    npm run build
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ Frontend build failed${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Frontend rebuilt successfully${NC}"
    echo ""
fi

echo -e "${GREEN}Step 0: Verifying required tools...${NC}"

# Check for required security tools
MISSING_TOOLS=()

if ! command_exists nmap; then
    MISSING_TOOLS+=("nmap")
fi

if ! command_exists nikto && ! command_exists nikto.pl; then
    MISSING_TOOLS+=("nikto")
fi

if ! command_exists tcpdump; then
    MISSING_TOOLS+=("tcpdump")
fi

if ! command_exists tshark; then
    MISSING_TOOLS+=("tshark")
fi

if ! command_exists jq; then
    MISSING_TOOLS+=("jq")
fi

if ! command_exists python3; then
    MISSING_TOOLS+=("python3")
fi

if ! command_exists iptables; then
    MISSING_TOOLS+=("iptables")
fi

# Check Python packages
if command_exists python3; then
    if ! python3 -c "import scapy" 2>/dev/null; then
        MISSING_TOOLS+=("python3-scapy")
    fi
    if ! python3 -c "import requests" 2>/dev/null; then
        MISSING_TOOLS+=("python3-requests")
    fi
    if ! python3 -c "import bs4" 2>/dev/null; then
        MISSING_TOOLS+=("python3-beautifulsoup4")
    fi
fi

if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
    echo -e "${GREEN}✓ All required tools are installed${NC}"
    echo "  Tools verified: nmap, nikto, tcpdump, tshark, jq, python3, iptables"
    echo "  Python packages: scapy, requests, beautifulsoup4"
else
    echo -e "${RED}✗ Missing required tools:${NC}"
    for tool in "${MISSING_TOOLS[@]}"; do
        echo "  - $tool"
    done
    echo ""
    echo -e "${YELLOW}To install missing tools, run:${NC}"
    echo "  apk add nmap nikto tcpdump tshark jq python3 iptables"
    echo "  pip3 install scapy requests beautifulsoup4"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""

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
echo -e "${GREEN}Step 4: Starting OWASP Juice Shop (Port 3003)...${NC}"

# Check if Juice Shop is already running
if pgrep -f "juice-shop.*npm start" > /dev/null; then
    echo -e "${YELLOW}✓ Juice Shop already running${NC}"
    JUICESHOP_PID=$(pgrep -f "juice-shop.*npm start")
else
    # Start Juice Shop
    cd /workspaces/cns/juice-shop
    nohup npm start > /tmp/juice-shop.log 2>&1 &
    JUICESHOP_PID=$!
    echo -e "${GREEN}✓ Juice Shop started (PID: $JUICESHOP_PID)${NC}"
    
    # Wait for Juice Shop to be ready
    echo -e "${YELLOW}Waiting for Juice Shop to be ready...${NC}"
    for i in {1..30}; do
        if lsof -i :3003 >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Juice Shop is ready on port 3003${NC}"
            break
        fi
        sleep 1
    done
fi

echo ""
echo -e "${GREEN}======================================"
echo "✓ All services started successfully!"
echo "======================================${NC}"
echo ""
echo "Services running:"
echo "  - Backend:     http://localhost:3001 (PID: $BACKEND_PID)"
echo "  - Frontend:    http://localhost:3000 (PID: $FRONTEND_PID)"
echo "  - Juice Shop:  http://localhost:3003 (PID: $JUICESHOP_PID)"
echo ""
echo "Access the application:"
echo "  - Lab Control: http://localhost:3000"
echo "  - Juice Shop:  http://localhost:3003"
echo "  - Public: Check VS Code Ports tab for forwarded URLs"
echo ""
echo "API Keys:"
echo "  - Operator: op_1234567890abcdef"
echo "  - Admin:    adm_fedcba0987654321"
echo ""
echo "Test Targets:"
echo "  - Use 'localhost' as target for all security tests"
echo "  - Nikto will scan port 3003 automatically"
echo "  - Session hijacking works on Juice Shop HTTP traffic"
echo ""
echo "Available Security Features:"
echo "  ✓ Network Scanning (nmap)"
echo "  ✓ Web Vulnerability Scanning (nikto)"
echo "  ✓ Packet Capture (tcpdump, tshark)"
echo "  ✓ Session Hijacking Attack & Mitigation (advanced)"
echo "  ✓ Firewall Management (iptables)"
echo ""
echo "To stop all services, run: ./stop.sh"
echo "To view logs:"
echo "  - Backend:  tail -f /workspaces/cns/backend/logs/backend.log"
echo "  - Frontend: tail -f /tmp/frontend.log"
echo "  - Juice Shop: tail -f /tmp/juice-shop.log"
echo ""
