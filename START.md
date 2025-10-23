# 🚀 Lab Control System - Quick Start

## ✅ Current Status
- **Backend**: Running on port 3001
- **Frontend**: Running on port 3000
- **No Errors Found**: All systems operational

## 🌐 Access URLs

### GitHub Codespaces URLs:
- **Frontend**: https://ominous-yodel-7v54g6x9pgpqhwqg7-3000.app.github.dev
- **Backend API**: https://ominous-yodel-7v54g6x9pgpqhwqg7-3001.app.github.dev

### Local URLs (within Codespaces):
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:3001

## 🔧 Troubleshooting "ERR_NAME_NOT_RESOLVED"

This error means GitHub Codespaces ports need to be made public:

### Step-by-Step Fix:

1. **Open the PORTS Tab**
   - Look at the bottom panel in VS Code
   - Click the "PORTS" tab (next to TERMINAL, PROBLEMS, OUTPUT)

2. **Set Ports to Public**
   - Find port **3000** (Frontend)
   - Right-click → **Port Visibility** → **Public**
   - Find port **3001** (Backend API)
   - Right-click → **Port Visibility** → **Public**

3. **Wait for DNS**
   - Wait 10-20 seconds for DNS changes to propagate
   - The URLs should now resolve

4. **Refresh Browser**
   - Go to: https://ominous-yodel-7v54g6x9pgpqhwqg7-3000.app.github.dev
   - The application should load

## 🔑 Test Credentials

Once the app loads, use these API keys:

- **Operator Key**: `op_1234567890abcdef`
- **Admin Key**: `adm_fedcba0987654321`

**Test Target**: `192.168.56.101`

## 📝 Services Status

Check if services are running:
```bash
# Check running processes
ps aux | grep node | grep -v grep

# Check listening ports
lsof -i :3000 -i :3001 | grep LISTEN

# Test backend health
curl http://localhost:3001/health

# Test frontend
curl -I http://localhost:3000
```

## 🔄 Restart Services (if needed)

```bash
# Stop services
pkill -f "node app.js"
pkill -f "react-scripts"

# Start backend
cd /workspaces/cns/backend
nohup npm start > /tmp/backend.log 2>&1 &

# Start frontend
cd /workspaces/cns/frontend
nohup npm start > /tmp/frontend.log 2>&1 &

# Check logs
tail -f /tmp/backend.log
tail -f /tmp/frontend.log
```

## ✨ Features

- ✅ No compilation errors
- ✅ Backend running with CORS enabled for all origins
- ✅ Frontend configured to auto-detect Codespaces URLs
- ✅ Port forwarding configured in devcontainer.json
- ✅ All dependencies installed

## 🎯 Next Steps

1. Make ports public (see troubleshooting above)
2. Access frontend URL
3. Enter API key
4. Select target
5. Run security tasks!
