#!/bin/bash
################################################################################
# CNS Lab Control System - Prerequisites Installation Script
# This script installs all necessary tools for the security lab
################################################################################

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  $1${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════╝${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

# Check if running as root for system packages
check_sudo() {
    if ! command -v sudo &> /dev/null; then
        print_error "sudo is not available. Please run as root or install sudo."
        exit 1
    fi
}

print_header "CNS Lab - Installing Prerequisites"

# Step 1: Update package lists
print_header "Step 1: Updating Package Lists"
if command -v apk &> /dev/null; then
    print_info "Detected Alpine Linux (apk)"
    sudo apk update
    print_success "Package lists updated"
elif command -v apt-get &> /dev/null; then
    print_info "Detected Debian/Ubuntu (apt)"
    sudo apt-get update
    print_success "Package lists updated"
elif command -v yum &> /dev/null; then
    print_info "Detected RHEL/CentOS (yum)"
    sudo yum update -y
    print_success "Package lists updated"
else
    print_error "Unsupported package manager. Please install packages manually."
    exit 1
fi

# Step 2: Install System Tools
print_header "Step 2: Installing System Tools"

TOOLS_TO_INSTALL=""

# Check and queue tools for installation
check_tool() {
    if ! command -v $1 &> /dev/null; then
        TOOLS_TO_INSTALL="$TOOLS_TO_INSTALL $2"
        print_info "Will install: $1"
    else
        print_success "$1 is already installed"
    fi
}

# Network scanning and analysis tools
check_tool nmap nmap
check_tool nikto nikto
check_tool tcpdump tcpdump
check_tool tshark tshark
check_tool ncat nmap-ncat

# System utilities
check_tool jq jq
check_tool curl curl
check_tool wget wget
check_tool git git

# Python
check_tool python3 python3
check_tool pip3 py3-pip

# Firewall
check_tool iptables iptables

# Text processing
check_tool awk gawk

# Install queued tools
if [ ! -z "$TOOLS_TO_INSTALL" ]; then
    print_info "Installing: $TOOLS_TO_INSTALL"
    
    if command -v apk &> /dev/null; then
        sudo apk add $TOOLS_TO_INSTALL
    elif command -v apt-get &> /dev/null; then
        sudo apt-get install -y $TOOLS_TO_INSTALL
    elif command -v yum &> /dev/null; then
        sudo yum install -y $TOOLS_TO_INSTALL
    fi
    
    print_success "System tools installed"
else
    print_success "All system tools already installed"
fi

# Step 3: Fix nikto symlink (if needed)
print_header "Step 3: Configuring Nikto"
if [ -f "/usr/bin/nikto.pl" ] && [ ! -f "/usr/bin/nikto" ]; then
    sudo ln -sf /usr/bin/nikto.pl /usr/bin/nikto
    print_success "Nikto symlink created"
elif command -v nikto &> /dev/null; then
    print_success "Nikto is properly configured"
else
    print_error "Nikto not found. It may need manual installation."
fi

# Step 4: Install Python Packages
print_header "Step 4: Installing Python Packages"

if [ -f "requirements-python.txt" ]; then
    print_info "Installing from requirements-python.txt..."
    
    # Try to install without breaking system packages
    if pip3 install --user -r requirements-python.txt 2>/dev/null; then
        print_success "Python packages installed (user mode)"
    elif pip3 install --break-system-packages -r requirements-python.txt 2>/dev/null; then
        print_success "Python packages installed (break-system-packages mode)"
    else
        print_error "Failed to install Python packages"
        print_info "Try manually: pip3 install --user -r requirements-python.txt"
    fi
else
    print_error "requirements-python.txt not found"
    print_info "Installing essential Python packages manually..."
    
    PYTHON_PACKAGES="scapy requests beautifulsoup4 PyJWT"
    for pkg in $PYTHON_PACKAGES; do
        if pip3 install --user $pkg 2>/dev/null || pip3 install --break-system-packages $pkg 2>/dev/null; then
            print_success "Installed $pkg"
        else
            print_error "Failed to install $pkg"
        fi
    done
fi

# Step 5: Install Node.js Dependencies
print_header "Step 5: Installing Node.js Dependencies"

install_npm_deps() {
    local dir=$1
    local name=$2
    
    if [ -d "$dir" ] && [ -f "$dir/package.json" ]; then
        print_info "Installing $name dependencies..."
        (cd "$dir" && npm install) && print_success "$name dependencies installed" || print_error "Failed to install $name dependencies"
    else
        print_info "Skipping $name (directory not found or no package.json)"
    fi
}

# Root dependencies
install_npm_deps "." "root"

# Backend dependencies
install_npm_deps "backend" "backend"

# Frontend dependencies
install_npm_deps "frontend" "frontend"

# Juice Shop dependencies
if [ ! -d "juice-shop" ] || [ ! -f "juice-shop/package.json" ]; then
    print_header "Step 6: Installing OWASP Juice Shop"
    print_info "Cloning Juice Shop from GitHub..."
    
    if [ -d "juice-shop" ]; then
        rm -rf juice-shop
    fi
    
    if git clone --depth 1 --branch v19.0.0 https://github.com/juice-shop/juice-shop.git 2>/dev/null; then
        print_success "Juice Shop cloned"
        install_npm_deps "juice-shop" "Juice Shop"
    else
        print_error "Failed to clone Juice Shop"
    fi
else
    install_npm_deps "juice-shop" "Juice Shop"
fi

# Step 6: Verify Installation
print_header "Step 7: Verifying Installation"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  INSTALLATION VERIFICATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

verify_tool() {
    if command -v $1 &> /dev/null; then
        local version=$($1 $2 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' || echo "installed")
        printf "%-20s ${GREEN}✓${NC} %s\n" "$1:" "$version"
        return 0
    else
        printf "%-20s ${RED}✗${NC} Not found\n" "$1:"
        return 1
    fi
}

# Verify tools
verify_tool "nmap" "--version"
verify_tool "nikto" "-Version"
verify_tool "tcpdump" "--version"
verify_tool "tshark" "--version"
verify_tool "jq" "--version"
verify_tool "python3" "--version"
verify_tool "pip3" "--version"
verify_tool "node" "--version"
verify_tool "npm" "--version"
verify_tool "iptables" "--version"

echo ""
echo "Python Packages:"
for pkg in scapy requests beautifulsoup4 PyJWT; do
    if pip3 list 2>/dev/null | grep -i "^$pkg " > /dev/null; then
        version=$(pip3 list 2>/dev/null | grep -i "^$pkg " | awk '{print $2}')
        printf "  %-18s ${GREEN}✓${NC} %s\n" "$pkg:" "$version"
    else
        printf "  %-18s ${RED}✗${NC} Not installed\n" "$pkg:"
    fi
done

echo ""
echo "Node.js Projects:"
[ -f "backend/node_modules/.package-lock.json" ] && printf "  %-18s ${GREEN}✓${NC} Installed\n" "Backend:" || printf "  %-18s ${RED}✗${NC} Not installed\n" "Backend:"
[ -f "frontend/node_modules/.package-lock.json" ] && printf "  %-18s ${GREEN}✓${NC} Installed\n" "Frontend:" || printf "  %-18s ${RED}✗${NC} Not installed\n" "Frontend:"
[ -f "juice-shop/node_modules/.package-lock.json" ] && printf "  %-18s ${GREEN}✓${NC} Installed\n" "Juice Shop:" || printf "  %-18s ${RED}✗${NC} Not installed\n" "Juice Shop:"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Final summary
print_header "Installation Complete!"

echo ""
print_success "All prerequisites have been installed!"
echo ""
print_info "Next steps:"
echo "  1. Start the backend:    cd backend && npm start"
echo "  2. Start the frontend:   cd frontend && npm start"
echo "  3. Start Juice Shop:     ./start-juiceshop.sh"
echo "  4. Make ports public in Codespaces (3000, 3001, 3003)"
echo "  5. Access the lab at:    http://localhost:3000"
echo ""
print_info "API Keys:"
echo "  Operator: op_1234567890abcdef"
echo "  Admin:    adm_fedcba0987654321"
echo ""
print_info "Documentation:"
echo "  Beginner Guide: cat BEGINNER_GUIDE.md"
echo "  Quick Start:    cat START.md"
echo ""

exit 0
