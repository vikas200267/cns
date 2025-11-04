# Quick Start Guide: Using New Targets

## 🎯 57 Targets Now Available!

### Categories
1. **Local Lab** - 127.0.0.1, localhost, 192.168.56.101-122
2. **Test Sites** - scanme.nmap.org, testphp.vulnweb.com, testasp.vulnweb.com
3. **CTF Platforms** - Hack The Box (10.10.10.x), TryHackMe (10.10.100.x)
4. **Public IPs** - DNS servers, Cloudflare, Google, Amazon, GitHub

## 🚀 Quick Test Commands

### 1. Port Scan External Host
```bash
curl -X POST http://127.0.0.1:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "X-API-Key: op_1234567890abcdef" \
  -d '{"taskId":"nmap-scan","target":"scanme.nmap.org"}'
```
**Result:** Discovers SSH, HTTP, and other services in ~3 seconds

### 2. Web Vulnerability Scan
```bash
curl -X POST http://127.0.0.1:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "X-API-Key: op_1234567890abcdef" \
  -d '{"taskId":"nikto-scan","target":"testphp.vulnweb.com"}'
```
**Result:** Comprehensive web vulnerability assessment

### 3. Steal Session Tokens (Local)
```bash
curl -X POST http://127.0.0.1:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "X-API-Key: op_1234567890abcdef" \
  -d '{"taskId":"session-hijack","target":"127.0.0.1"}'
```
**Result:** Captures 9+ JWT tokens in real-time

### 4. Capture Network Traffic
```bash
curl -X POST http://127.0.0.1:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "X-API-Key: op_1234567890abcdef" \
  -d '{"taskId":"start-capture","target":"44.228.249.3"}'
```
**Result:** 60-second PCAP with 500+ packets

## 📋 Available Tasks

| Task ID | Description | Example Target |
|---------|-------------|----------------|
| `nmap-scan` | Port scanning with service detection | scanme.nmap.org |
| `nikto-scan` | Web vulnerability assessment | testphp.vulnweb.com |
| `session-hijack` | Capture JWT tokens/cookies | 127.0.0.1 |
| `session-hijack-msf` | MSF-style token exploitation | localhost |
| `start-capture` | Packet capture (60s) | 44.228.249.3 |
| `stop-capture` | Stop active capture | N/A |
| `session-protect` | Apply session protection | 127.0.0.1 |
| `add-firewall` | Configure firewall rules | N/A |

## 🎓 Recommended Test Targets

### For Beginners
- **scanme.nmap.org** - Official nmap test server (safe to scan)
- **testphp.vulnweb.com** - OWASP test site (44.228.249.3)
- **127.0.0.1** - Local Juice Shop (session hijacking)

### For Intermediate
- **testasp.vulnweb.com** - ASP.NET vulnerabilities (44.238.29.244)
- **192.168.56.101-122** - Local VM range
- **10.10.10.10-15** - Hack The Box practice range

### For Advanced
- **8.8.8.8, 1.1.1.1** - DNS servers (traffic analysis only)
- **104.16.132.229** - Cloudflare (capture study)
- **142.250.185.206** - Google (network analysis)

## ⚠️ Important Notes

### API Field Names
- Use `"taskId"` NOT `"task"`
- Use `"target"` for IP or domain
- Include `X-API-Key` header

### Target Formats Accepted
✅ IP addresses: `127.0.0.1`, `44.228.249.3`  
✅ Hostnames: `scanme.nmap.org`, `testphp.vulnweb.com`  
✅ Special: `localhost`  
❌ Port numbers: `127.0.0.1:3003` (not needed)  
❌ Protocols: `http://scanme.nmap.org` (just domain/IP)

### Check Task Status
```bash
# Replace {taskInstanceId} with actual ID from response
curl -H "X-API-Key: op_1234567890abcdef" \
  http://127.0.0.1:3001/api/tasks/{taskInstanceId}
```

### View Results
Artifacts are saved in `/workspaces/cns/artifacts/`:
- **PCAP files**: `capture-*.pcap`, `session-hijack-*.pcap`
- **Scan results**: `nmap-*.txt`, `nikto-*.txt`
- **Token dumps**: `session-tokens-*.txt`
- **JSON analysis**: `session-hijack-*.json`

## 🔥 Attack Scenarios

### Scenario 1: Reconnaissance
```bash
# Step 1: Scan for open ports
curl -X POST http://127.0.0.1:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "X-API-Key: op_1234567890abcdef" \
  -d '{"taskId":"nmap-scan","target":"scanme.nmap.org"}'

# Step 2: Web vulnerability scan
curl -X POST http://127.0.0.1:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "X-API-Key: op_1234567890abcdef" \
  -d '{"taskId":"nikto-scan","target":"testphp.vulnweb.com"}'
```

### Scenario 2: Session Hijacking
```bash
# Step 1: Start packet capture
curl -X POST http://127.0.0.1:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "X-API-Key: op_1234567890abcdef" \
  -d '{"taskId":"start-capture","target":"127.0.0.1"}'

# Step 2: Hijack sessions
curl -X POST http://127.0.0.1:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "X-API-Key: op_1234567890abcdef" \
  -d '{"taskId":"session-hijack","target":"127.0.0.1"}'

# Result: 9+ JWT tokens captured!
```

### Scenario 3: External Target Analysis
```bash
# Analyze traffic to/from external test site
curl -X POST http://127.0.0.1:3001/api/tasks \
  -H "Content-Type: application/json" \
  -H "X-API-Key: op_1234567890abcdef" \
  -d '{"taskId":"start-capture","target":"44.228.249.3"}'

# Result: 565 packets captured in 60 seconds
```

## 📊 Expected Results

| Task | Duration | Typical Output |
|------|----------|----------------|
| nmap-scan | 3-10s | 4-10 open ports found |
| nikto-scan | 60-180s | 10-50 vulnerabilities found |
| session-hijack | 60-70s | 9+ JWT tokens captured |
| start-capture | 60s | 500+ packets captured |

## 🐛 Troubleshooting

### "Task not in whitelist"
- Check you're using `"taskId"` not `"task"`
- Verify task name has hyphens: `nmap-scan` not `nmap`

### "Target not in allowed list"
- Check `/workspaces/cns/backend/allowed_targets.txt`
- Ensure target is uncommented (no `#`)
- Verify exact spelling (case-sensitive for domains)

### "Invalid target format"
- Use domain or IP only (no `http://` or port numbers)
- Examples: `scanme.nmap.org` or `44.228.249.3`

### Task stays "running"
- Long tasks (nikto-scan) can take 2-5 minutes
- Check status again after waiting
- View backend logs: `tail -f /tmp/backend.log`

## 🎯 Success Metrics

**You know it's working when:**
- nmap finds 4+ ports on scanme.nmap.org ✅
- session-hijack captures 9+ tokens on 127.0.0.1 ✅
- start-capture saves 500+ packets in PCAP ✅
- Artifacts appear in `/workspaces/cns/artifacts/` ✅

## 📚 Additional Resources

- Full validation: `NEW_TARGETS_VALIDATION.md`
- Session hijacking fix: `SESSION_HIJACKING_FIX.md`
- Real-time proof: `REALTIME_HIJACK_PROOF.md`
- Beginner guide: `BEGINNER_GUIDE.md`

---

**Need Help?** Check backend logs:
```bash
tail -f /tmp/backend.log
```

**View All Targets:**
```bash
grep -v "^#" /workspaces/cns/backend/allowed_targets.txt | grep -v "^$"
```

**View All Tasks:**
```bash
cat /workspaces/cns/backend/tasks.json | jq 'keys'
```
