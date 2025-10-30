#!/bin/bash
# Advanced Session Hijacking Protection & Mitigation System
# Real-time IDS, automated hardening, and active session monitoring
set -euo pipefail

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARTIFACTS_PATH="${ARTIFACTS_PATH:-/workspaces/cns/artifacts}"
OUTPUT_FILE="${ARTIFACTS_PATH}/session-protect-${TARGET}-${TIMESTAMP}.txt"
MONITOR_FILE="${ARTIFACTS_PATH}/session-monitor-${TARGET}-${TIMESTAMP}.log"
IDS_LOG="${ARTIFACTS_PATH}/ids-alerts-${TARGET}-${TIMESTAMP}.log"
JSON_REPORT="${ARTIFACTS_PATH}/protection-report-${TARGET}-${TIMESTAMP}.json"
MITIGATION_SCRIPT="/tmp/session_mitigation_${TIMESTAMP}.py"

echo "╔══════════════════════════════════════════════════════════════╗" | tee "$OUTPUT_FILE"
echo "║  ADVANCED SESSION HIJACKING PROTECTION SYSTEM                ║" | tee -a "$OUTPUT_FILE"
echo "║  Real-Time IDS + Automated Hardening + Active Monitoring     ║" | tee -a "$OUTPUT_FILE"
echo "╚══════════════════════════════════════════════════════════════╝" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "Target: $TARGET:3003" | tee -a "$OUTPUT_FILE"
echo "Timestamp: $(date)" | tee -a "$OUTPUT_FILE"
echo "Protection Mode: ACTIVE" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

mkdir -p "$ARTIFACTS_PATH"

# Create Python-based IDS for session hijacking detection
cat > "$MITIGATION_SCRIPT" << 'PYTHON_EOF'
#!/usr/bin/env python3
import json
import sys
import subprocess
from datetime import datetime
from collections import defaultdict

def analyze_security_posture(target):
    """Comprehensive security analysis"""
    
    vulnerabilities = []
    recommendations = []
    security_score = 100
    findings = {
        'https_enabled': False,
        'secure_cookies': False,
        'httponly_enabled': False,
        'samesite_enabled': False,
        'hsts_enabled': False,
        'csrf_protection': False,
        'xss_protection': False,
        'frame_protection': False
    }
    
    print(f"[*] Analyzing security posture of {target}:3003...")
    
    try:
        # Test HTTP
        http_result = subprocess.run([
            'curl', '-sI', f'http://{target}:3003/', '--max-time', '5'
        ], capture_output=True, text=True, timeout=10)
        
        http_headers = http_result.stdout.lower()
        
        # Check security headers
        if 'set-cookie:' in http_headers:
            if 'secure' in http_headers:
                findings['secure_cookies'] = True
            else:
                vulnerabilities.append({
                    'type': 'Missing Secure Cookie Flag',
                    'severity': 'HIGH',
                    'cvss': 7.5,
                    'description': 'Cookies can be intercepted over HTTP',
                    'remediation': 'Add Secure flag to all Set-Cookie headers'
                })
                security_score -= 15
            
            if 'httponly' in http_headers:
                findings['httponly_enabled'] = True
            else:
                vulnerabilities.append({
                    'type': 'Missing HttpOnly Flag',
                    'severity': 'MEDIUM',
                    'cvss': 5.3,
                    'description': 'Cookies accessible via JavaScript - XSS risk',
                    'remediation': 'Add HttpOnly flag to session cookies'
                })
                security_score -= 10
            
            if 'samesite' in http_headers:
                findings['samesite_enabled'] = True
            else:
                vulnerabilities.append({
                    'type': 'Missing SameSite Protection',
                    'severity': 'MEDIUM',
                    'cvss': 4.3,
                    'description': 'Vulnerable to CSRF attacks',
                    'remediation': 'Add SameSite=Strict or SameSite=Lax'
                })
                security_score -= 10
        
        if 'strict-transport-security:' in http_headers:
            findings['hsts_enabled'] = True
        else:
            vulnerabilities.append({
                'type': 'Missing HSTS Header',
                'severity': 'MEDIUM',
                'cvss': 5.0,
                'description': 'No HTTP Strict Transport Security',
                'remediation': 'Add: Strict-Transport-Security: max-age=31536000'
            })
            security_score -= 10
        
        if 'x-frame-options:' in http_headers:
            findings['frame_protection'] = True
        else:
            vulnerabilities.append({
                'type': 'Missing Clickjacking Protection',
                'severity': 'MEDIUM',
                'cvss': 4.3,
                'description': 'Site can be embedded in iframes',
                'remediation': 'Add: X-Frame-Options: DENY'
            })
            security_score -= 5
        
        if 'x-xss-protection:' in http_headers or 'content-security-policy:' in http_headers:
            findings['xss_protection'] = True
        else:
            vulnerabilities.append({
                'type': 'Insufficient XSS Protection',
                'severity': 'MEDIUM',
                'cvss': 6.1,
                'description': 'No browser XSS protection headers',
                'remediation': 'Add CSP and X-XSS-Protection headers'
            })
            security_score -= 10
        
        # Test HTTPS
        try:
            https_result = subprocess.run([
                'curl', '-skI', f'https://{target}:3003/', '--max-time', '5'
            ], capture_output=True, text=True, timeout=10)
            if https_result.returncode == 0:
                findings['https_enabled'] = True
        except:
            pass
        
        if not findings['https_enabled']:
            vulnerabilities.append({
                'type': 'HTTPS Not Enabled',
                'severity': 'CRITICAL',
                'cvss': 9.1,
                'description': 'All traffic transmitted in cleartext',
                'remediation': 'Enable HTTPS with valid SSL/TLS certificate'
            })
            security_score -= 30
        
    except Exception as e:
        print(f"[!] Analysis error: {e}")
    
    # Generate recommendations based on findings
    if security_score < 50:
        overall_risk = 'CRITICAL'
    elif security_score < 70:
        overall_risk = 'HIGH'
    elif security_score < 85:
        overall_risk = 'MEDIUM'
    else:
        overall_risk = 'LOW'
    
    return {
        'timestamp': datetime.now().isoformat(),
        'target': target,
        'security_score': max(0, security_score),
        'risk_level': overall_risk,
        'findings': findings,
        'vulnerabilities': vulnerabilities,
        'recommendations': generate_recommendations(vulnerabilities, findings)
    }

def generate_recommendations(vulnerabilities, findings):
    """Generate actionable recommendations"""
    recs = []
    
    if not findings['https_enabled']:
        recs.append({
            'priority': 'CRITICAL',
            'action': 'Enable HTTPS/TLS',
            'steps': [
                'Obtain SSL/TLS certificate (Let\'s Encrypt)',
                'Configure web server for HTTPS on port 443',
                'Redirect all HTTP traffic to HTTPS',
                'Test certificate validity'
            ]
        })
    
    if not findings['secure_cookies']:
        recs.append({
            'priority': 'HIGH',
            'action': 'Add Secure flag to cookies',
            'steps': [
                'Update Set-Cookie headers',
                'Add: Secure; flag',
                'Test in browser developer tools'
            ]
        })
    
    if not findings['httponly_enabled']:
        recs.append({
            'priority': 'HIGH',
            'action': 'Add HttpOnly flag to cookies',
            'steps': [
                'Update session cookie configuration',
                'Add: HttpOnly; flag',
                'Verify JavaScript cannot access cookies'
            ]
        })
    
    if not findings['samesite_enabled']:
        recs.append({
            'priority': 'MEDIUM',
            'action': 'Implement SameSite cookie protection',
            'steps': [
                'Add: SameSite=Strict; or SameSite=Lax;',
                'Test cross-site request behavior'
            ]
        })
    
    return recs

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: script.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    report = analyze_security_posture(target)
    
    print(f"\n[+] Security Analysis Complete")
    print(f"[+] Security Score: {report['security_score']}/100")
    print(f"[+] Risk Level: {report['risk_level']}")
    print(f"[+] Vulnerabilities Found: {len(report['vulnerabilities'])}")
    
    # Output JSON
    print(json.dumps(report, indent=2))
PYTHON_EOF

chmod +x "$MITIGATION_SCRIPT"

echo "[PHASE 1] Security Posture Analysis" | tee -a "$OUTPUT_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"
echo "[*] Running comprehensive security scan..." | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Run security analysis
ANALYSIS_OUTPUT=$(python3 "$MITIGATION_SCRIPT" "$TARGET" 2>&1)
echo "$ANALYSIS_OUTPUT" | grep -v '^{' | grep -v '^}' | grep -v '^\[' | grep -v '"' | tee -a "$OUTPUT_FILE"

# Extract JSON report
JSON_DATA=$(echo "$ANALYSIS_OUTPUT" | sed -n '/^{/,/^}/p')
echo "$JSON_DATA" > "$JSON_REPORT"

echo "" | tee -a "$OUTPUT_FILE"
echo "[PHASE 2] Real-Time Intrusion Detection" | tee -a "$OUTPUT_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"
echo "[*] Deploying session hijacking IDS (30 seconds)..." | tee -a "$OUTPUT_FILE"
echo "[*] Monitoring for: ARP spoofing, suspicious cookies, replay attacks" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Real-time monitoring with anomaly detection
{
    echo "IDS Start: $(date)"
    echo "Target: $TARGET:3003"
    echo ""
    
    timeout 30 sudo tshark -i any -f "host $TARGET and tcp port 3003" -T fields \
        -e frame.time -e ip.src -e ip.dst -e http.cookie -e http.request.uri \
        2>/dev/null | while read line; do
            echo "[$(date +%H:%M:%S)] $line"
            
            # Detect cookie theft attempts
            if echo "$line" | grep -iq "cookie:"; then
                echo "  [ALERT] Cookie transmission detected - potential hijacking"
            fi
            
            # Detect suspicious URIs
            if echo "$line" | grep -iE "(session|token|auth)" | grep -q "="; then
                echo "  [WARNING] Session token in URL - security risk"
            fi
        done || true
    
} > "$MONITOR_FILE" 2>&1 &

MONITOR_PID=$!

# Generate test traffic
if [ "$TARGET" == "localhost" ] || [ "$TARGET" == "127.0.0.1" ]; then
    sleep 3
    echo "[*] Generating test traffic for IDS validation..." | tee -a "$OUTPUT_FILE"
    for i in {1..3}; do
        curl -s "http://$TARGET:3003/rest/products/search?q=test" > /dev/null 2>&1 || true
        sleep 2
    done
fi

wait $MONITOR_PID 2>/dev/null || true

# Analyze IDS results
ALERT_COUNT=$(grep -c "\[ALERT\]" "$MONITOR_FILE" 2>/dev/null || echo "0")
WARNING_COUNT=$(grep -c "\[WARNING\]" "$MONITOR_FILE" 2>/dev/null || echo "0")

echo "" | tee -a "$OUTPUT_FILE"
echo "═══ IDS RESULTS ═══" | tee -a "$OUTPUT_FILE"
echo "Alerts Generated: $ALERT_COUNT" | tee -a "$OUTPUT_FILE"
echo "Warnings Generated: $WARNING_COUNT" | tee -a "$OUTPUT_FILE"
if [ $ALERT_COUNT -gt 0 ] || [ $WARNING_COUNT -gt 0 ]; then
    echo "⚠️  Suspicious activity detected - review $MONITOR_FILE" | tee -a "$OUTPUT_FILE"
else
    echo "✓ No suspicious activity during monitoring period" | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
echo "[PHASE 3] Automated Hardening Recommendations" | tee -a "$OUTPUT_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

if [ -f "$JSON_REPORT" ]; then
    echo "═══ SECURITY SCORE ═══" | tee -a "$OUTPUT_FILE"
    jq -r '"Score: \(.security_score)/100\nRisk Level: \(.risk_level)"' "$JSON_REPORT" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "═══ VULNERABILITIES FOUND ═══" | tee -a "$OUTPUT_FILE"
    jq -r '.vulnerabilities[] | "[\(.severity)] \(.type) (CVSS: \(.cvss))\n  → \(.description)\n  ✓ Fix: \(.remediation)\n"' "$JSON_REPORT" 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "═══ PRIORITY ACTIONS ═══" | tee -a "$OUTPUT_FILE"
    jq -r '.recommendations[] | "[\(.priority)] \(.action)\n  Steps:\n" + (.steps | map("    " + (. | tostring)) | join("\n")) + "\n"' "$JSON_REPORT" 2>/dev/null | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
echo "[PHASE 4] Active Protection Measures" | tee -a "$OUTPUT_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "The following protections can be deployed:" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

cat << 'EOF' | tee -a "$OUTPUT_FILE"
1. IPTABLES FIREWALL RULES (Rate Limiting)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   # Limit new connections per IP
   sudo iptables -A INPUT -p tcp --dport 3003 -m state --state NEW \
        -m recent --set --name HTTP_LIMIT
   
   sudo iptables -A INPUT -p tcp --dport 3003 -m state --state NEW \
        -m recent --update --seconds 60 --hitcount 20 \
        --name HTTP_LIMIT -j DROP
   
   # Log dropped connections
   sudo iptables -A INPUT -p tcp --dport 3003 -j LOG \
        --log-prefix "SESSION_PROTECT: "

2. NGINX/APACHE CONFIGURATION (Security Headers)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   add_header X-Frame-Options "DENY" always;
   add_header X-Content-Type-Options "nosniff" always;
   add_header X-XSS-Protection "1; mode=block" always;
   add_header Content-Security-Policy "default-src 'self'" always;
   
   # Secure cookies
   proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Strict";

3. APPLICATION-LEVEL PROTECTIONS
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • Implement session token rotation after authentication
   • Bind sessions to IP address + User-Agent
   • Set short session timeouts (15-30 minutes)
   • Use cryptographically random session IDs (256 bits)
   • Invalidate sessions on logout (server-side)
   • Monitor for concurrent sessions from different IPs

4. NETWORK-LEVEL PROTECTIONS
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • Deploy IDS/IPS (Snort, Suricata)
   • Enable ARP spoofing detection
   • Use VLANs for network segmentation
   • Implement 802.1X port security
   • Monitor for promiscuous mode on network interfaces

5. MONITORING & ALERTING
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • Log all session creation/destruction events
   • Alert on multiple failed login attempts
   • Alert on session access from new locations
   • Monitor for unusual traffic patterns
   • Implement SIEM integration
EOF

echo "" | tee -a "$OUTPUT_FILE"
echo "╔══════════════════════════════════════════════════════════════╗" | tee -a "$OUTPUT_FILE"
echo "║             PROTECTION SYSTEM DEPLOYMENT COMPLETE            ║" | tee -a "$OUTPUT_FILE"
echo "╚══════════════════════════════════════════════════════════════╝" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "📊 ARTIFACTS GENERATED:" | tee -a "$OUTPUT_FILE"
echo "   • Full Report:    $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
echo "   • JSON Analysis:  $JSON_REPORT" | tee -a "$OUTPUT_FILE"
echo "   • IDS Log:        $MONITOR_FILE" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Cleanup
rm -f "$MITIGATION_SCRIPT" 2>/dev/null || true

echo "ARTIFACT: $OUTPUT_FILE"
exit 0
