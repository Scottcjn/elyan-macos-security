#!/bin/bash
# Elyan Labs macOS Security Shield - Audit Script
# Scans system for CVE exposure and security misconfigurations
# Version: 1.0.0

set -e

VERSION="1.0.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

ISSUES_FOUND=0
WARNINGS_FOUND=0

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          Elyan Labs Security Audit v${VERSION}                    ║"
    echo "║              CVE Exposure Scanner                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

issue() {
    echo -e "  ${RED}[ISSUE]${NC} $1"
    ((ISSUES_FOUND++)) || true
}

warning() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    ((WARNINGS_FOUND++)) || true
}

ok() {
    echo -e "  ${GREEN}[OK]${NC} $1"
}

info() {
    echo -e "  ${CYAN}[INFO]${NC} $1"
}

section() {
    echo ""
    echo -e "${BLUE}━━━ $1 ━━━${NC}"
}

#==============================================================================
# System Information
#==============================================================================
check_system_info() {
    section "System Information"

    OS_VERSION=$(sw_vers -productVersion)
    OS_BUILD=$(sw_vers -buildVersion)
    MAJOR=$(echo "$OS_VERSION" | cut -d. -f1)

    echo "  macOS Version: $OS_VERSION ($OS_BUILD)"
    echo "  Hardware: $(sysctl -n hw.model 2>/dev/null || echo 'Unknown')"
    echo "  Architecture: $(uname -m)"
    echo ""

    if [[ "$MAJOR" == "10" ]]; then
        MINOR=$(echo "$OS_VERSION" | cut -d. -f2)
        if [[ "$MINOR" == "15" ]]; then
            issue "macOS Catalina - NO SECURITY UPDATES SINCE JULY 2022"
            issue "Exposed to 50+ known CVEs with no patches available"
        fi
    elif [[ "$MAJOR" == "12" ]]; then
        issue "macOS Monterey - NO SECURITY UPDATES SINCE SEPTEMBER 2024"
        issue "Exposed to CVEs discovered after July 2024"
    elif [[ "$MAJOR" == "11" ]]; then
        issue "macOS Big Sur - NO SECURITY UPDATES SINCE OCTOBER 2023"
    elif [[ "$MAJOR" -ge "13" ]]; then
        ok "macOS $OS_VERSION may still receive security updates"
        info "Check: https://support.apple.com/en-us/100100"
    fi
}

#==============================================================================
# CVE-2024-44243: SIP Bypass
#==============================================================================
check_cve_2024_44243() {
    section "CVE-2024-44243 (SIP Bypass via storagekitd)"

    # Check SIP status
    SIP_STATUS=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$SIP_STATUS" | grep -q "enabled"; then
        ok "System Integrity Protection (SIP) is enabled"
    else
        issue "SIP is DISABLED - system vulnerable to kernel extension attacks"
        echo "     Enable in Recovery Mode: csrutil enable"
    fi

    # Check for suspicious filesystem bundles
    if [[ -d /Library/Filesystems ]]; then
        FS_COUNT=$(ls -1 /Library/Filesystems 2>/dev/null | wc -l | tr -d ' ')
        if [[ "$FS_COUNT" -gt "3" ]]; then
            warning "Unusual filesystem bundles found ($FS_COUNT items)"
            ls -la /Library/Filesystems/ 2>/dev/null | head -10
        else
            ok "Filesystem bundles look normal ($FS_COUNT items)"
        fi
    fi

    # Check third-party kexts
    THIRD_PARTY_KEXTS=$(kextstat 2>/dev/null | grep -v "com.apple" | grep -v "Index" | wc -l | tr -d ' ')
    if [[ "$THIRD_PARTY_KEXTS" -gt "0" ]]; then
        warning "$THIRD_PARTY_KEXTS third-party kernel extensions loaded"
        kextstat 2>/dev/null | grep -v "com.apple" | grep -v "Index" | awk '{print "     " $6}'
    else
        ok "No third-party kernel extensions loaded"
    fi
}

#==============================================================================
# CVE-2023-42931: diskutil Privilege Escalation
#==============================================================================
check_cve_2023_42931() {
    section "CVE-2023-42931 (diskutil Privilege Escalation)"

    # Check diskutil permissions
    if [[ -f /usr/sbin/diskutil ]]; then
        PERMS=$(ls -la /usr/sbin/diskutil | awk '{print $1}')
        OWNER=$(ls -la /usr/sbin/diskutil | awk '{print $3}')
        if [[ "$OWNER" == "root" ]]; then
            info "diskutil owned by root (expected)"
        fi

        # Check if monitoring is in place
        if [[ -f /usr/local/bin/diskutil-monitor ]]; then
            ok "diskutil monitoring wrapper installed"
        else
            warning "No diskutil monitoring - run elyan-harden to enable"
        fi
    fi

    # Check recent diskutil activity
    if [[ -f /var/log/elyan/diskutil.log ]]; then
        RECENT=$(tail -5 /var/log/elyan/diskutil.log 2>/dev/null | wc -l | tr -d ' ')
        info "diskutil log entries: $RECENT recent operations logged"
    fi
}

#==============================================================================
# CVE-2024-23225/23296: Kernel Memory Bypass
#==============================================================================
check_cve_2024_23225() {
    section "CVE-2024-23225/23296 (Kernel Memory Protection Bypass)"

    # Check ASLR
    ASLR=$(sysctl -n kern.aslr 2>/dev/null || echo "0")
    if [[ "$ASLR" == "2" ]]; then
        ok "Kernel ASLR enabled (level 2 - full)"
    elif [[ "$ASLR" == "1" ]]; then
        warning "Kernel ASLR partial (level 1)"
    else
        issue "Kernel ASLR may be disabled"
    fi

    # Check NX bit
    if sysctl -n machdep.cpu.features 2>/dev/null | grep -q "NX"; then
        ok "NX (No-Execute) bit supported"
    else
        warning "NX bit not detected in CPU features"
    fi

    # Check for debug/dev kernel
    if sysctl -n kern.development 2>/dev/null | grep -q "1"; then
        issue "Development kernel detected - reduced security"
    else
        ok "Production kernel in use"
    fi
}

#==============================================================================
# CVE-2023-42916/42917: WebKit Vulnerabilities
#==============================================================================
check_webkit_cves() {
    section "CVE-2023-42916/42917 (WebKit Remote Code Execution)"

    # Check Safari version
    if [[ -d "/Applications/Safari.app" ]]; then
        SAFARI_VER=$(defaults read /Applications/Safari.app/Contents/Info CFBundleShortVersionString 2>/dev/null || echo "unknown")
        warning "Safari $SAFARI_VER installed - uses unpatched WebKit"
        echo "     Recommendation: Use Firefox or Chromium for web browsing"
    fi

    # Check for alternative browsers
    BROWSERS=""
    [[ -d "/Applications/Firefox.app" ]] && BROWSERS="${BROWSERS}Firefox "
    [[ -d "/Applications/Google Chrome.app" ]] && BROWSERS="${BROWSERS}Chrome "
    [[ -d "/Applications/Chromium.app" ]] && BROWSERS="${BROWSERS}Chromium "
    [[ -d "/Applications/Brave Browser.app" ]] && BROWSERS="${BROWSERS}Brave "

    if [[ -n "$BROWSERS" ]]; then
        ok "Alternative browsers available: $BROWSERS"
        info "Use these instead of Safari for safer browsing"
    else
        warning "No alternative browsers found"
        echo "     Install Firefox: https://www.mozilla.org/firefox/"
    fi

    # Check default browser (if possible)
    DEFAULT_BROWSER=$(defaults read com.apple.LaunchServices/com.apple.launchservices.secure LSHandlers 2>/dev/null | grep -A1 "https" | grep "LSHandlerRoleAll" | head -1 || echo "")
    if echo "$DEFAULT_BROWSER" | grep -qi "safari"; then
        warning "Safari appears to be default browser - consider changing"
    fi
}

#==============================================================================
# CVE-2024-40828: Root Privilege Escalation
#==============================================================================
check_cve_2024_40828() {
    section "CVE-2024-40828 (Root Privilege Escalation)"

    # Count SUID binaries
    SUID_COUNT=$(find /usr/bin /usr/sbin /usr/libexec -perm -4000 2>/dev/null | wc -l | tr -d ' ')
    info "SUID binaries found: $SUID_COUNT"

    # Compare to baseline if exists
    if [[ -f /var/db/elyan/suid_baseline.txt ]]; then
        BASELINE_COUNT=$(wc -l < /var/db/elyan/suid_baseline.txt | tr -d ' ')
        if [[ "$SUID_COUNT" -gt "$BASELINE_COUNT" ]]; then
            issue "More SUID binaries than baseline ($SUID_COUNT vs $BASELINE_COUNT)"
            echo "     New SUID binaries may indicate compromise"
            # Show differences
            find /usr/bin /usr/sbin /usr/libexec -perm -4000 2>/dev/null | sort > /tmp/suid_current.txt
            diff /var/db/elyan/suid_baseline.txt /tmp/suid_current.txt 2>/dev/null | grep "^>" | head -5
        else
            ok "SUID binary count matches baseline"
        fi
    else
        info "No baseline exists - run elyan-harden to create one"
    fi

    # Check for world-writable SUID binaries (very bad)
    WORLD_WRITABLE=$(find /usr/bin /usr/sbin -perm -4002 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$WORLD_WRITABLE" -gt "0" ]]; then
        issue "World-writable SUID binaries found! Possible backdoor!"
        find /usr/bin /usr/sbin -perm -4002 2>/dev/null
    else
        ok "No world-writable SUID binaries"
    fi
}

#==============================================================================
# Firewall Status
#==============================================================================
check_firewall() {
    section "Firewall Configuration"

    # Application firewall
    FW_STATUS=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if echo "$FW_STATUS" | grep -q "enabled"; then
        ok "Application firewall is enabled"
    else
        issue "Application firewall is DISABLED"
        echo "     Enable with: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
    fi

    # Stealth mode
    STEALTH=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")
    if echo "$STEALTH" | grep -q "enabled"; then
        ok "Stealth mode is enabled"
    else
        warning "Stealth mode is disabled (responds to pings)"
    fi

    # Block all incoming
    BLOCK_ALL=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null || echo "unknown")
    if echo "$BLOCK_ALL" | grep -q "enabled"; then
        ok "Block all incoming connections enabled"
    else
        info "Allowing signed application connections"
    fi
}

#==============================================================================
# Gatekeeper Status
#==============================================================================
check_gatekeeper() {
    section "Gatekeeper & Code Signing"

    GK_STATUS=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$GK_STATUS" | grep -q "enabled"; then
        ok "Gatekeeper is enabled"
    else
        issue "Gatekeeper is DISABLED - unsigned apps can run"
        echo "     Enable with: sudo spctl --master-enable"
    fi

    # Check for apps bypassing Gatekeeper
    QUARANTINE_DISABLED=$(xattr -l /Applications/*.app 2>/dev/null | grep -c "com.apple.quarantine" || echo "0")
    info "$QUARANTINE_DISABLED apps have quarantine flag set"
}

#==============================================================================
# FileVault Status
#==============================================================================
check_filevault() {
    section "Disk Encryption (FileVault)"

    FV_STATUS=$(fdesetup status 2>/dev/null || echo "unknown")
    if echo "$FV_STATUS" | grep -q "On"; then
        ok "FileVault is enabled - disk is encrypted"
    else
        warning "FileVault is OFF - disk is not encrypted"
        echo "     Enable in: System Preferences > Security & Privacy > FileVault"
    fi
}

#==============================================================================
# Remote Access
#==============================================================================
check_remote_access() {
    section "Remote Access Services"

    # SSH
    SSH_STATUS=$(systemsetup -getremotelogin 2>/dev/null || echo "unknown")
    if echo "$SSH_STATUS" | grep -qi "off"; then
        ok "Remote Login (SSH) is disabled"
    else
        warning "Remote Login (SSH) is enabled"
        echo "     Disable if not needed: sudo systemsetup -setremotelogin off"
    fi

    # Screen Sharing
    if launchctl list 2>/dev/null | grep -q "com.apple.screensharing"; then
        warning "Screen Sharing may be enabled"
    else
        ok "Screen Sharing appears disabled"
    fi

    # Remote Apple Events
    RAE_STATUS=$(systemsetup -getremoteappleevents 2>/dev/null || echo "unknown")
    if echo "$RAE_STATUS" | grep -qi "off"; then
        ok "Remote Apple Events disabled"
    else
        warning "Remote Apple Events enabled"
    fi
}

#==============================================================================
# Summary
#==============================================================================
print_summary() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                     AUDIT SUMMARY                            ${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo ""

    if [[ $ISSUES_FOUND -gt 0 ]]; then
        echo -e "${RED}Critical Issues Found: $ISSUES_FOUND${NC}"
    else
        echo -e "${GREEN}Critical Issues Found: 0${NC}"
    fi

    if [[ $WARNINGS_FOUND -gt 0 ]]; then
        echo -e "${YELLOW}Warnings Found: $WARNINGS_FOUND${NC}"
    else
        echo -e "${GREEN}Warnings Found: 0${NC}"
    fi

    echo ""

    if [[ $ISSUES_FOUND -gt 0 ]] || [[ $WARNINGS_FOUND -gt 3 ]]; then
        echo -e "${YELLOW}Recommendation: Run 'sudo elyan-harden --level moderate' to apply mitigations${NC}"
    else
        echo -e "${GREEN}System security posture is reasonable for an EOL macOS version${NC}"
    fi

    echo ""
    echo "For detailed CVE information, see:"
    echo "  https://github.com/Scottcjn/elyan-macos-security"
    echo ""
}

#==============================================================================
# Main
#==============================================================================
main() {
    print_banner

    check_system_info
    check_cve_2024_44243
    check_cve_2023_42931
    check_cve_2024_23225
    check_webkit_cves
    check_cve_2024_40828
    check_firewall
    check_gatekeeper
    check_filevault
    check_remote_access

    print_summary
}

main "$@"
