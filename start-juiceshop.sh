#!/bin/bash
# Start OWASP Juice Shop

cd /workspaces/cns/juice-shop

# Check if already running
if pgrep -f "juice-shop.*npm start" > /dev/null; then
    echo "❌ Juice Shop is already running"
    echo "   PID: $(pgrep -f 'juice-shop.*npm start')"
    echo "   Access at: http://localhost:3003"
    exit 0
fi

# Start Juice Shop
echo "🚀 Starting OWASP Juice Shop..."
PORT=3003 nohup npm start > /tmp/juice-shop.log 2>&1 &

# Wait for it to start
echo "⏳ Waiting for Juice Shop to start..."
sleep 8

# Check if it's running
if curl -s -o /dev/null -w "%{http_code}" http://localhost:3003 | grep -q "200"; then
    echo "✅ Juice Shop is running!"
    echo ""
    echo "📍 Access at: http://localhost:3003"
    echo "🔍 Use target: localhost (with port 3003 for Nikto)"
    echo "📋 Log file: /tmp/juice-shop.log"
    echo ""
    echo "Available tests:"
    echo "  - Nikto scan: Use target 'localhost' (scans port 3003)"
    echo "  - Packet capture: Use target 'localhost' or '127.0.0.1'"
    echo "  - Nmap scan: Use target 'localhost' or '127.0.0.1'"
else
    echo "❌ Failed to start Juice Shop"
    echo "Check log: tail -f /tmp/juice-shop.log"
    exit 1
fi
