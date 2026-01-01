# Elyan Labs macOS Security Shield

**Security mitigations for end-of-life macOS systems (Monterey 12, Catalina 10.15)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Apple no longer provides security updates for macOS Monterey (EOL Sept 2024) or Catalina (EOL 2022). This toolkit provides **defense-in-depth mitigations** for known CVEs affecting these systems.

**This is NOT a patch** - we cannot modify Apple's closed-source code. Instead, we provide:
- Configuration hardening using Apple's built-in security features
- Firewall rules to block known attack vectors
- Monitoring tools to detect exploitation attempts
- Virtual patching via system configuration

## CVEs Addressed

| CVE | CVSS | Type | Mitigation |
|-----|------|------|------------|
| CVE-2024-44243 | 5.5 | SIP Bypass | Restrict kernel extensions, monitor storagekitd |
| CVE-2024-23225 | 7.8 | Kernel Bypass | Enable kernel protections, restrict memory access |
| CVE-2023-42931 | 7.8 | diskutil Privesc | Restrict diskutil access, audit disk operations |
| CVE-2023-42916/17 | 8.8 | WebKit RCE | Disable Safari, use Firefox/Chromium |
| CVE-2024-40828 | 7.8 | Root Escalation | Audit SUID binaries, restrict permissions |
| CVE-2024-27822 | 7.8 | PackageKit Exploit | Restrict PKG installations, audit sources |

## Installation

### Option 1: PKG Installer (Recommended)
```bash
# Download and install
curl -LO https://github.com/Scottcjn/elyan-macos-security/releases/latest/download/ElyanSecurityShield.pkg
sudo installer -pkg ElyanSecurityShield.pkg -target /
```

### Option 2: Manual Installation
```bash
git clone https://github.com/Scottcjn/elyan-macos-security.git
cd elyan-macos-security
chmod +x scripts/*.sh
sudo ./scripts/install.sh
```

## Components

| Component | Description |
|-----------|-------------|
| `elyan-audit` | Scan system for vulnerable configurations |
| `elyan-harden` | Apply security hardening |
| `elyan-monitor` | Real-time exploitation detection |
| `elyan-firewall` | Network-level protection rules |
| `elyan-webkit-guard` | WebKit vulnerability mitigations |

## Usage

### Run Security Audit
```bash
sudo elyan-audit
```

### Apply Hardening
```bash
sudo elyan-harden --level moderate  # Options: minimal, moderate, maximum
```

### Enable Monitoring
```bash
sudo launchctl load /Library/LaunchDaemons/com.elyanlabs.security-monitor.plist
```

### Check Status
```bash
elyan-status
```

## Legal Notice

This software provides **configuration-based mitigations** only. We do NOT:
- Modify Apple system binaries
- Circumvent code signing or SIP
- Distribute patched Apple code
- Bypass security measures

This approach is consistent with DMCA security research exemptions and industry-standard "virtual patching" practices.

## Compatibility

| macOS Version | Status |
|---------------|--------|
| Catalina 10.15 | ✅ Fully Supported |
| Monterey 12.x | ✅ Fully Supported |
| Big Sur 11.x | ✅ Compatible |
| Ventura 13.x | ⚠️ Use Apple's updates instead |

## Contributing

Pull requests welcome. Please ensure all contributions:
1. Use only Apple's documented configuration options
2. Do not modify system binaries
3. Include documentation for each mitigation

## License

MIT License - See [LICENSE](LICENSE)

## Disclaimer

This software is provided AS-IS. While we strive to improve security, no mitigation can fully replace vendor security patches. **Upgrading to a supported macOS version is always the best option.**

---

**Elyan Labs** - Securing legacy systems
