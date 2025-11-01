# 🚀 Installation Guide

Complete guide for installing all prerequisites for the CNS Lab Control System.

---

## 📋 Quick Start

### One-Command Installation (Recommended)

```bash
# Make the installation script executable
chmod +x install-tools.sh

# Run the installation script
./install-tools.sh
```

This will automatically install:
- ✅ System tools (nmap, nikto, tcpdump, tshark, etc.)
- ✅ Python packages (scapy, requests, beautifulsoup4, etc.)
- ✅ Node.js dependencies (backend, frontend, Juice Shop)
- ✅ OWASP Juice Shop (if not already installed)

---

## 📦 Manual Installation

If you prefer to install components manually or the script fails:

### 1. System Tools Installation

#### For Alpine Linux (Default in Codespaces):
```bash
sudo apk update
sudo apk add nmap nikto tcpdump tshark jq python3 py3-pip iptables curl wget git
```

#### For Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y nmap nikto tcpdump tshark jq python3 python3-pip iptables curl wget git
```

#### For RHEL/CentOS:
```bash
sudo yum update -y
sudo yum install -y nmap nikto tcpdump wireshark jq python3 python3-pip iptables curl wget git
```

### 2. Python Packages Installation

```bash
# Install Python packages from requirements file
pip3 install --user -r requirements-python.txt

# Or install individually
pip3 install --user scapy requests beautifulsoup4 PyJWT cryptography
```

**If you get permission errors:**
```bash
# For Alpine Linux in Codespaces
pip3 install --break-system-packages -r requirements-python.txt
```

### 3. Node.js Dependencies

```bash
# Install root dependencies
npm install

# Install backend dependencies
cd backend && npm install && cd ..

# Install frontend dependencies
cd frontend && npm install && cd ..

# Install Juice Shop dependencies (if directory exists)
cd juice-shop && npm install && cd ..
```

### 4. OWASP Juice Shop Installation

If Juice Shop is not installed:

```bash
# Clone from GitHub
git clone --depth 1 --branch v19.0.0 https://github.com/juice-shop/juice-shop.git

# Install dependencies
cd juice-shop && npm install
```

---

## ✅ Verification

### Check Installed Tools

```bash
# Network scanning tools
nmap --version
nikto -Version
tcpdump --version
tshark --version

# Utilities
jq --version
python3 --version
pip3 --version
node --version
npm --version

# Firewall
iptables --version
```

### Check Python Packages

```bash
pip3 list | grep -E "scapy|requests|beautifulsoup4|PyJWT"
```

Expected output:
```
beautifulsoup4     4.14.2
PyJWT              2.9.0
requests           2.32.5
scapy              2.6.1
```

### Check Node.js Projects

```bash
# Check if dependencies are installed
ls backend/node_modules frontend/node_modules juice-shop/node_modules
```

---

## 🔧 Troubleshooting

### Issue: "command not found: nikto"

**Solution:**
```bash
# Nikto might be installed as nikto.pl
sudo ln -sf /usr/bin/nikto.pl /usr/bin/nikto

# Verify
nikto -Version
```

### Issue: "pip3: permission denied"

**Solution 1 (Recommended - User Install):**
```bash
pip3 install --user -r requirements-python.txt
```

**Solution 2 (For Alpine Linux):**
```bash
pip3 install --break-system-packages -r requirements-python.txt
```

**Solution 3 (Virtual Environment):**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-python.txt
```

### Issue: "tcpdump: permission denied"

**Solution:**
```bash
# Add current user to specific groups (if needed)
sudo usermod -a -G netdev $USER

# Or run with sudo
sudo tcpdump -i any
```

### Issue: "npm install fails with EACCES"

**Solution:**
```bash
# Clear npm cache
npm cache clean --force

# Try again
npm install
```

### Issue: "Juice Shop won't install"

**Solution:**
```bash
# Remove existing directory
rm -rf juice-shop

# Clone again
git clone --depth 1 --branch v19.0.0 https://github.com/juice-shop/juice-shop.git

# Install with more memory (if needed)
cd juice-shop
NODE_OPTIONS="--max-old-space-size=4096" npm install
```

---

## 📊 Requirements Files

### requirements-python.txt
Contains all Python packages needed for security testing.

**Location:** `/workspaces/cns/requirements-python.txt`

**Includes:**
- Network analysis: scapy, dpkt
- Web: requests, beautifulsoup4, selenium
- Security: impacket, PyJWT, cryptography
- Data: pandas, numpy
- Utilities: colorama, tqdm, python-dotenv

### package.json files
Contains Node.js dependencies for each component.

**Locations:**
- Root: `/workspaces/cns/package.json`
- Backend: `/workspaces/cns/backend/package.json`
- Frontend: `/workspaces/cns/frontend/package.json`
- Juice Shop: `/workspaces/cns/juice-shop/package.json`

---

## 🎯 What Gets Installed

### System Tools (via apk/apt/yum)

| Tool | Purpose | Size |
|------|---------|------|
| **nmap** | Network port scanner | ~7 MB |
| **nikto** | Web vulnerability scanner | ~5 MB |
| **tcpdump** | Packet capture utility | ~1 MB |
| **tshark** | Packet analyzer (Wireshark CLI) | ~30 MB |
| **jq** | JSON processor | ~2 MB |
| **python3** | Python interpreter | ~50 MB |
| **py3-pip** | Python package manager | ~10 MB |
| **iptables** | Firewall utility | ~1 MB |

**Total System Tools:** ~106 MB

### Python Packages (via pip)

| Package | Purpose | Size |
|---------|---------|------|
| **scapy** | Packet manipulation | ~10 MB |
| **requests** | HTTP library | ~500 KB |
| **beautifulsoup4** | HTML parsing | ~500 KB |
| **PyJWT** | JWT token handling | ~100 KB |
| **cryptography** | Encryption libraries | ~5 MB |
| **pandas** | Data analysis | ~20 MB |
| **numpy** | Numerical computing | ~15 MB |
| **selenium** | Browser automation | ~10 MB |

**Total Python Packages:** ~61 MB

### Node.js Dependencies (via npm)

| Project | Packages | Size |
|---------|----------|------|
| **Root** | 93 packages | ~20 MB |
| **Backend** | 427 packages | ~80 MB |
| **Frontend** | 1,397 packages | ~300 MB |
| **Juice Shop** | 2,136 packages | ~450 MB |

**Total Node.js:** ~850 MB

### Total Disk Space Required
**~1.0 GB** (rounded up for safety)

---

## 🔐 Security Notes

### Package Sources

All packages come from official repositories:
- **Alpine packages:** https://pkgs.alpinelinux.org/
- **Python packages:** https://pypi.org/
- **Node packages:** https://www.npmjs.com/
- **Juice Shop:** https://github.com/juice-shop/juice-shop

### Verification

You can verify package integrity:

```bash
# Verify Python package checksums
pip3 hash scapy

# Verify npm package integrity
npm audit
```

### Minimal Installation

If disk space is limited, install only essential tools:

```bash
# Minimal installation
sudo apk add nmap nikto tcpdump python3 py3-pip
pip3 install --user scapy requests

# Then install Node.js deps per project as needed
cd backend && npm install
```

---

## 📱 Platform-Specific Notes

### GitHub Codespaces
- ✅ Pre-configured with Alpine Linux
- ✅ Most tools work out of the box
- ⚠️ May need to use `--break-system-packages` for pip
- ⚠️ Remember to make ports public (3000, 3001, 3003)

### Local Development
- Ensure Docker is installed (if using containers)
- Ensure Node.js v16+ is installed
- Ensure Python 3.8+ is installed

### WSL (Windows Subsystem for Linux)
- Use Ubuntu commands (apt-get)
- May need to install `sudo` first
- Docker Desktop integration may be needed

---

## 🆘 Getting Help

### Installation Issues

1. **Check the logs:**
   ```bash
   ./install-tools.sh 2>&1 | tee install.log
   ```

2. **Verify system:**
   ```bash
   uname -a
   cat /etc/os-release
   ```

3. **Check disk space:**
   ```bash
   df -h
   ```

4. **Check memory:**
   ```bash
   free -h
   ```

### Common Solutions

| Error | Solution |
|-------|----------|
| "No space left on device" | Free up disk space or use smaller installation |
| "Permission denied" | Use `sudo` or install in user directory (`--user`) |
| "Package not found" | Update package lists (`apk update` / `apt-get update`) |
| "Command not found" | Check if binary is in PATH or create symlink |

---

## 📚 Next Steps

After installation:

1. ✅ **Verify installation** using the verification commands above
2. ✅ **Read the documentation:**
   - Quick Start: `cat START.md`
   - Beginner Guide: `cat BEGINNER_GUIDE.md`
   - Juice Shop Guide: `cat JUICESHOP_GUIDE.md`
3. ✅ **Start the services:**
   ```bash
   cd backend && npm start &
   cd frontend && npm start &
   ./start-juiceshop.sh
   ```
4. ✅ **Configure Codespaces ports** (if using GitHub Codespaces)
5. ✅ **Access the lab** at http://localhost:3000

---

## 🎓 Learn More

- **Installation Script:** See `install-tools.sh` for detailed implementation
- **Python Requirements:** See `requirements-python.txt` for all Python packages
- **Security Tools Documentation:**
  - Nmap: https://nmap.org/docs.html
  - Nikto: https://cirt.net/Nikto2
  - Wireshark/tshark: https://www.wireshark.org/docs/
  - Scapy: https://scapy.readthedocs.io/

---

**Last Updated:** November 1, 2025  
**Version:** 1.0
