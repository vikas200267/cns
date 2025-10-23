#!/bin/bash
# Security test script for lab control system
set -euo pipefail

API_URL="http://localhost:3001"
API_KEY="op_1234567890abcdef"

echo "Running security tests..."

# Test 1: Reject shell injection in taskId
echo "Test 1: Shell injection in taskId"
response=$(curl -s -w "%{http_code}" -X POST "$API_URL/api/tasks" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"taskId":"nmap-scan; ls","target":"192.168.56.101"}')

if [[ $response == *"400"* ]]; then
  echo "✅ Shell injection rejected"
else
  echo "❌ Shell injection not properly handled"
  exit 1
fi

# Test 2: Reject unauthorized target
echo "Test 2: Unauthorized target"
response=$(curl -s -w "%{http_code}" -X POST "$API_URL/api/tasks" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"taskId":"nmap-scan","target":"8.8.8.8"}')

if [[ $response == *"403"* ]]; then
  echo "✅ Unauthorized target rejected"
else
  echo "❌ Target whitelist not enforced"
  exit 1
fi

# Test 3: Reject sensitive task without admin
echo "Test 3: Sensitive task access"
response=$(curl -s -w "%{http_code}" -X POST "$API_URL/api/tasks" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"taskId":"arp-spoof","target":"192.168.56.101"}')

if [[ $response == *"403"* ]]; then
  echo "✅ Sensitive task properly restricted"
else
  echo "❌ Sensitive task access not properly controlled"
  exit 1
fi

# Test 4: Rate limiting
echo "Test 4: Rate limiting"
for i in {1..5}; do
  curl -s -X POST "$API_URL/api/tasks" \
    -H "x-api-key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"taskId":"nmap-scan","target":"192.168.56.101"}'
done

response=$(curl -s -w "%{http_code}" -X POST "$API_URL/api/tasks" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"taskId":"nmap-scan","target":"192.168.56.101"}')

if [[ $response == *"429"* ]]; then
  echo "✅ Rate limiting working"
else
  echo "❌ Rate limiting not enforced"
  exit 1
fi

echo "All security tests passed! ✅"