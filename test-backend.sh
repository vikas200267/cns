#!/bin/bash

# Quick Backend API Test Script
# Tests core backend functionality

API_URL="http://localhost:3001"
OPERATOR_KEY="op_1234567890abcdef"

echo "Testing Lab Control Backend API..."
echo "==================================="
echo ""

# Test 1: Health
echo "1. Health Check:"
curl -s $API_URL/health | jq .
echo ""

# Test 2: List Captures
echo "2. Executing list-captures task:"
curl -s -X POST $API_URL/api/tasks \
    -H "Content-Type: application/json" \
    -H "x-api-key: $OPERATOR_KEY" \
    -d '{"taskId": "list-captures", "target": "192.168.56.101"}' | jq .
echo ""

# Test 3: Invalid target
echo "3. Testing invalid target (should fail):"
curl -s -X POST $API_URL/api/tasks \
    -H "Content-Type: application/json" \
    -H "x-api-key: $OPERATOR_KEY" \
    -d '{"taskId": "list-captures", "target": "1.2.3.4"}' | jq .
echo ""

echo "Backend tests complete!"
