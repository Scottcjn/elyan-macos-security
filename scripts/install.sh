#!/bin/bash
# Elyan Labs Security Shield - Manual Installation Script
# Use this if you don't want to use the PKG installer

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        Elyan Labs Security Shield - Installer                ║"
echo "║          macOS CVE Mitigation Toolkit                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
    echo "Usage: sudo ./install.sh"
    exit 1
fi

# Detect script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

echo "Installing from: $REPO_DIR"
echo ""

# Create directories
echo "Creating directories..."
mkdir -p /usr/local/bin
mkdir -p /usr/local/share/elyan-security
mkdir -p /var/db/elyan
mkdir -p /var/log/elyan

# Copy scripts
echo "Installing scripts..."
cp "$SCRIPT_DIR/elyan-harden.sh" /usr/local/bin/elyan-harden
cp "$SCRIPT_DIR/elyan-audit.sh" /usr/local/bin/elyan-audit
cp "$SCRIPT_DIR/elyan-monitor.sh" /usr/local/bin/elyan-monitor

# Also copy to share directory (for reference)
cp "$SCRIPT_DIR/elyan-harden.sh" /usr/local/share/elyan-security/
cp "$SCRIPT_DIR/elyan-audit.sh" /usr/local/share/elyan-security/
cp "$SCRIPT_DIR/elyan-monitor.sh" /usr/local/share/elyan-security/

# Make executable
chmod 755 /usr/local/bin/elyan-harden
chmod 755 /usr/local/bin/elyan-audit
chmod 755 /usr/local/bin/elyan-monitor

# Create status command
cat > /usr/local/bin/elyan-status << 'EOF'
#!/bin/bash
echo "Elyan Labs Security Shield Status"
echo "=================================="
echo ""

if launchctl list 2>/dev/null | grep -q "com.elyanlabs.security-monitor"; then
    echo "[RUNNING] Security monitor is active"
else
    echo "[STOPPED] Security monitor is not running"
    echo "  Start with: sudo launchctl load /Library/LaunchDaemons/com.elyanlabs.security-monitor.plist"
fi

if [[ -f /var/log/elyan/security_alerts.log ]]; then
    ALERTS=$(wc -l < /var/log/elyan/security_alerts.log | tr -d ' ')
    echo ""
    echo "Security alerts logged: $ALERTS"
    echo "Recent alerts:"
    tail -5 /var/log/elyan/security_alerts.log 2>/dev/null || echo "  (none)"
fi

echo ""
echo "Commands:"
echo "  sudo elyan-audit    - Run security audit"
echo "  sudo elyan-harden   - Apply security hardening"
echo "  elyan-status        - Show this status"
EOF
chmod 755 /usr/local/bin/elyan-status

# Install LaunchDaemon
echo "Installing LaunchDaemon..."
if [[ -f "$REPO_DIR/LaunchDaemons/com.elyanlabs.security-monitor.plist" ]]; then
    cp "$REPO_DIR/LaunchDaemons/com.elyanlabs.security-monitor.plist" /Library/LaunchDaemons/
    cp "$REPO_DIR/LaunchDaemons/com.elyanlabs.security-monitor.plist" /usr/local/share/elyan-security/
    chown root:wheel /Library/LaunchDaemons/com.elyanlabs.security-monitor.plist
    chmod 644 /Library/LaunchDaemons/com.elyanlabs.security-monitor.plist
    echo -e "${GREEN}[OK] LaunchDaemon installed${NC}"
fi

# Create baselines
echo "Creating security baselines..."
find /usr/bin /usr/sbin /usr/libexec -perm -4000 2>/dev/null | sort > /var/db/elyan/suid_baseline.txt || true
ls -la /Library/Filesystems 2>/dev/null > /var/db/elyan/filesystems_baseline.txt || true

# Record installation
echo "$(date)" > /var/log/elyan/installed.txt
echo "manual" > /var/log/elyan/install_method.txt

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Installation Complete!                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Installed commands:"
echo "  elyan-audit   - Scan for CVE exposure"
echo "  elyan-harden  - Apply security mitigations"
echo "  elyan-monitor - Real-time exploitation detection"
echo "  elyan-status  - Show security status"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Run: sudo elyan-audit"
echo "  2. Run: sudo elyan-harden --level moderate"
echo "  3. Enable monitoring:"
echo "     sudo launchctl load /Library/LaunchDaemons/com.elyanlabs.security-monitor.plist"
echo ""
