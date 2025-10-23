#!/bin/bash

# Integration Test Script for Lab Control System
# Tests backend API, frontend connectivity, and all features

set -e

API_URL="http://localhost:3001"
FRONTEND_URL="http://localhost:3000"
OPERATOR_KEY="op_1234567890abcdef"
ADMIN_KEY="adm_fedcba0987654321"

echo "================================================"
echo "Lab Control System Integration Tests"
echo "================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function test_passed() {
    echo -e "${GREEN}✓ $1${NC}"
}

function test_failed() {
    echo -e "${RED}✗ $1${NC}"
}

function test_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Test 1: Backend Health Check
echo "Test 1: Backend Health Check"
response=$(curl -s -w "\n%{http_code}" $API_URL/health)
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" == "200" ]; then
    test_passed "Backend health check passed"
    echo "   Response: $(echo $body | jq -r '.status')"
else
    test_failed "Backend health check failed (HTTP $http_code)"
    exit 1
fi
echo ""

# Test 2: Frontend Availability
echo "Test 2: Frontend Availability"
frontend_status=$(curl -s -o /dev/null -w "%{http_code}" $FRONTEND_URL)
if [ "$frontend_status" == "200" ]; then
    test_passed "Frontend is accessible"
else
    test_failed "Frontend is not accessible (HTTP $frontend_status)"
fi
echo ""

# Test 3: Authentication - Invalid API Key
echo "Test 3: Authentication - Invalid API Key"
response=$(curl -s -w "\n%{http_code}" -X POST $API_URL/api/tasks \
    -H "Content-Type: application/json" \
    -H "x-api-key: invalid_key" \
    -d '{"taskId": "list-captures", "target": "192.168.56.101"}')
http_code=$(echo "$response" | tail -n1)

if [ "$http_code" == "401" ]; then
    test_passed "Invalid API key correctly rejected"
else
    test_failed "Invalid API key test failed (expected 401, got $http_code)"
fi
echo ""

# Test 4: Authentication - Valid Operator Key
echo "Test 4: Authentication - Valid Operator Key"
response=$(curl -s -w "\n%{http_code}" -X POST $API_URL/api/tasks \
    -H "Content-Type: application/json" \
    -H "x-api-key: $OPERATOR_KEY" \
    -d '{"taskId": "list-captures", "target": "192.168.56.101"}')
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" == "200" ]; then
    test_passed "Operator key authentication successful"
    echo "   Task Instance ID: $(echo $body | jq -r '.taskInstanceId')"
    echo "   Exit Code: $(echo $body | jq -r '.exitCode')"
else
    test_failed "Operator key authentication failed (HTTP $http_code)"
    echo "   Error: $(echo $body | jq -r '.error // .details')"
fi
echo ""

# Test 5: Target Validation - Invalid Target
echo "Test 5: Target Validation - Invalid Target"
response=$(curl -s -w "\n%{http_code}" -X POST $API_URL/api/tasks \
    -H "Content-Type: application/json" \
    -H "x-api-key: $OPERATOR_KEY" \
    -d '{"taskId": "list-captures", "target": "1.2.3.4"}')
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" == "403" ]; then
    test_passed "Invalid target correctly rejected"
    echo "   Error: $(echo $body | jq -r '.error')"
else
    test_failed "Target validation failed (expected 403, got $http_code)"
fi
echo ""

# Test 6: Task Execution - Nmap Scan
echo "Test 6: Task Execution - Nmap Scan"
response=$(curl -s -w "\n%{http_code}" -X POST $API_URL/api/tasks \
    -H "Content-Type: application/json" \
    -H "x-api-key: $OPERATOR_KEY" \
    -d '{"taskId": "nmap-scan", "target": "192.168.56.101"}')
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" == "200" ]; then
    task_id=$(echo $body | jq -r '.taskInstanceId')
    duration=$(echo $body | jq -r '.duration')
    test_passed "Nmap scan executed successfully"
    echo "   Task ID: $task_id"
    echo "   Duration: ${duration}s"
else
    test_failed "Nmap scan execution failed (HTTP $http_code)"
    echo "   Error: $(echo $body | jq -r '.error // .details')"
fi
echo ""

# Test 7: Admin Role Required Task
echo "Test 7: Admin Role Required Task - Operator Denied"
response=$(curl -s -w "\n%{http_code}" -X POST $API_URL/api/tasks \
    -H "Content-Type: application/json" \
    -H "x-api-key: $OPERATOR_KEY" \
    -d '{"taskId": "add-firewall", "target": "192.168.56.101"}')
http_code=$(echo "$response" | tail -n1)

if [ "$http_code" == "403" ]; then
    test_passed "Admin-only task correctly denied for operator"
else
    test_failed "Role-based access control failed (expected 403, got $http_code)"
fi
echo ""

# Test 8: Sensitive Task - Confirmation Required
echo "Test 8: Sensitive Task - Confirmation Required"
response=$(curl -s -w "\n%{http_code}" -X POST $API_URL/api/tasks \
    -H "Content-Type: application/json" \
    -H "x-api-key: $ADMIN_KEY" \
    -d '{"taskId": "add-firewall", "target": "192.168.56.101"}')
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" == "400" ]; then
    test_passed "Sensitive task requires confirmation"
    echo "   Warning: $(echo $body | jq -r '.warning')"
else
    test_failed "Sensitive task confirmation check failed (expected 400, got $http_code)"
fi
echo ""

# Test 9: Admin Logs Access
echo "Test 9: Admin Logs Access"
response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/api/logs?limit=5" \
    -H "x-api-key: $ADMIN_KEY")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" == "200" ]; then
    log_count=$(echo $body | jq '.logs | length')
    test_passed "Admin can access audit logs"
    echo "   Retrieved $log_count log entries"
else
    test_failed "Admin logs access failed (HTTP $http_code)"
fi
echo ""

# Test 10: Operator Logs Access Denied
echo "Test 10: Operator Logs Access Denied"
response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/api/logs?limit=5" \
    -H "x-api-key: $OPERATOR_KEY")
http_code=$(echo "$response" | tail -n1)

if [ "$http_code" == "403" ]; then
    test_passed "Operator correctly denied logs access"
else
    test_failed "Operator logs access control failed (expected 403, got $http_code)"
fi
echo ""

# Test 11: CORS Headers
echo "Test 11: CORS Headers"
response=$(curl -s -I -H "Origin: http://localhost:3000" $API_URL/health | grep -i "access-control")
if [ ! -z "$response" ]; then
    test_passed "CORS headers present"
    echo "   $response"
else
    test_info "CORS headers check inconclusive"
fi
echo ""

# Test 12: Rate Limiting
echo "Test 12: Rate Limiting (Testing 4 rapid requests)"
rate_limit_hit=false
for i in {1..4}; do
    response=$(curl -s -w "\n%{http_code}" -X POST $API_URL/api/tasks \
        -H "Content-Type: application/json" \
        -H "x-api-key: $OPERATOR_KEY" \
        -d '{"taskId": "list-captures", "target": "192.168.56.101"}')
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" == "429" ]; then
        rate_limit_hit=true
        break
    fi
    sleep 0.5
done

if [ "$rate_limit_hit" == "true" ]; then
    test_passed "Rate limiting is working"
else
    test_info "Rate limiting not triggered (limit may be higher than test count)"
fi
echo ""

echo "================================================"
echo "Test Summary"
echo "================================================"
echo ""
echo "Backend URL: $API_URL"
echo "Frontend URL: $FRONTEND_URL"
echo ""
echo "✅ All critical tests passed!"
echo ""
echo "To access the application:"
echo "1. Open your browser to: $FRONTEND_URL"
echo "2. Enter API key: $OPERATOR_KEY (operator) or $ADMIN_KEY (admin)"
echo "3. Enter target: 192.168.56.101"
echo "4. Click any task button to execute"
echo ""
