# 🧃 OWASP Juice Shop Testing Guide

## Overview

OWASP Juice Shop is a vulnerable web application installed for testing security tools.

- **Version**: 19.0.0
- **Port**: 3003
- **URL**: http://localhost:3003
- **Status**: ✅ Running

---

## Quick Start

### Start Juice Shop
```bash
./start-juiceshop.sh
```

### Stop Juice Shop
```bash
./stop-juiceshop.sh
```

### Check Status
```bash
curl http://localhost:3003
```

---

## Testing with Security Tools

### 1. 🔍 Nikto Scan (Web Vulnerability Scanner)

**Target**: `localhost` (automatically scans port 3003)

**Example findings**:
- Server information leaks
- Missing security headers (X-XSS-Protection)
- Uncommon headers (feature-policy, x-recruiting)
- robots.txt entries
- SSL/TLS issues

**Via API**:
```bash
curl -X POST http://localhost:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "x-api-key: op_1234567890abcdef" \
  -d '{"taskId": "nikto-scan", "target": "localhost"}'
```

**Via Frontend**:
1. Enter API key: `op_1234567890abcdef`
2. Enter target: `localhost`
3. Click "Nikto Scan"

---

### 2. 📡 Packet Capture (Network Traffic Analysis)

**Target**: `localhost` or `127.0.0.1`

**What it captures**:
- HTTP requests to Juice Shop
- Database queries
- API calls
- WebSocket connections
- All network traffic to/from localhost

**Via API**:
```bash
# Start capture
curl -X POST http://localhost:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "x-api-key: op_1234567890abcdef" \
  -d '{"taskId": "start-capture", "target": "localhost"}'

# Generate traffic (browse Juice Shop in another terminal)
curl http://localhost:3003
curl http://localhost:3003/rest/products/search
```

**Via Frontend**:
1. Enter API key: `op_1234567890abcdef`
2. Enter target: `localhost`
3. Click "Start Capture"
4. Browse Juice Shop to generate traffic
5. Wait 60 seconds for capture to complete

---

### 3. 🗺️ Nmap Scan (Port Scanner)

**Target**: `localhost` or `127.0.0.1`

**What it finds**:
- Open port 3003 (Juice Shop)
- Port 3001 (Backend API)
- Port 3000 (Frontend)
- Other services

**Via API**:
```bash
curl -X POST http://localhost:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "x-api-key: op_1234567890abcdef" \
  -d '{"taskId": "nmap-scan", "target": "localhost"}'
```

---

## Allowed Targets

The following targets are whitelisted for testing:

✅ **localhost** - Juice Shop and local services
✅ **127.0.0.1** - Same as localhost
✅ **192.168.56.101-103** - Lab VMs (if available)
✅ **8.8.8.8, 8.8.4.4** - DNS servers
✅ **scanme.nmap.org** - Official nmap test target

---

## Juice Shop Features for Testing

### Vulnerabilities to Test:

1. **SQL Injection** - Search box, login forms
2. **XSS (Cross-Site Scripting)** - User reviews, product names
3. **Broken Authentication** - Password reset, admin access
4. **Sensitive Data Exposure** - API endpoints
5. **Missing Function Level Access Control** - Admin functions
6. **CSRF (Cross-Site Request Forgery)** - Various forms
7. **Security Misconfiguration** - Error messages, headers
8. **Insecure Direct Object References** - Product IDs, user IDs
9. **File Upload Vulnerabilities** - Complaint forms
10. **Unvalidated Redirects** - Login redirects

### Interesting Endpoints:

- `http://localhost:3003/rest/products/search` - Search API
- `http://localhost:3003/rest/user/login` - Login API
- `http://localhost:3003/ftp` - FTP directory
- `http://localhost:3003/api/Users` - Users API
- `http://localhost:3003/api/Challenges` - Challenges info

---

## Example Testing Workflow

### 1. Start Everything
```bash
# Start backend
cd /workspaces/cns/backend && npm start &

# Start Juice Shop
./start-juiceshop.sh

# Start frontend
cd /workspaces/cns/frontend && npm start &
```

### 2. Run Nikto Scan
- Open http://localhost:3000
- Login with operator key
- Target: `localhost`
- Run Nikto Scan
- Review vulnerabilities found

### 3. Capture Traffic
- Start packet capture on `localhost`
- Open http://localhost:3003 in browser
- Browse the shop, login, search products
- Wait for capture to complete (60s)
- Analyze captured packets

### 4. Port Scan
- Run nmap scan on `localhost`
- Identify all open ports
- Check service versions

---

## Artifacts Location

All scan results are saved to:
```
/workspaces/cns/artifacts/
```

Files include:
- `nikto-localhost-[timestamp].txt` - Nikto scan results
- `capture-localhost-[timestamp].pcap` - Packet captures
- `nmap-localhost-[timestamp].txt` - Nmap scan results
- `nmap-localhost-[timestamp].xml` - Nmap XML output

---

## Troubleshooting

### Juice Shop won't start
```bash
# Check logs
tail -f /tmp/juice-shop.log

# Kill stuck processes
pkill -9 -f juice-shop

# Restart
./start-juiceshop.sh
```

### Can't scan localhost
- Check if localhost is in `/workspaces/cns/backend/allowed_targets.txt`
- Should include both `localhost` and `127.0.0.1`

### Nikto scan times out
- This is normal for thorough scans
- Results are still saved to artifacts
- Reduce scan time in script if needed

---

## Security Notes

⚠️ **Important**:
- Juice Shop is INTENTIONALLY VULNERABLE
- Only use in isolated lab environments
- Do NOT expose to the internet
- Only scan authorized targets
- Packet capture requires sudo privileges

---

## Resources

- Juice Shop Documentation: https://pwning.owasp-juice.shop/
- Juice Shop GitHub: https://github.com/juice-shop/juice-shop
- OWASP Top 10: https://owasp.org/www-project-top-ten/

---

**Ready to test!** 🚀

Access Juice Shop: http://localhost:3003
Access Frontend: http://localhost:3000
Access Backend: http://localhost:3001

