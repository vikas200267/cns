#!/bin/bash
# Stop OWASP Juice Shop

echo "🛑 Stopping OWASP Juice Shop..."

# Find and kill Juice Shop processes
PIDS=$(pgrep -f "juice-shop.*npm start")

if [ -z "$PIDS" ]; then
    echo "❌ Juice Shop is not running"
    exit 0
fi

# Kill the processes
kill $PIDS 2>/dev/null

# Wait a moment
sleep 2

# Force kill if still running
if pgrep -f "juice-shop.*npm start" > /dev/null; then
    echo "⚠️  Force stopping..."
    pkill -9 -f "juice-shop.*npm start"
fi

echo "✅ Juice Shop stopped"
