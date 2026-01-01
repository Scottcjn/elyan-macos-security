#!/bin/bash
# Elyan Labs Security Shield - PKG Builder
# Run this on macOS to build the installer package

set -e

VERSION="1.0.0"
IDENTIFIER="com.elyanlabs.security-shield"
PKG_NAME="ElyanSecurityShield-${VERSION}.pkg"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/pkg-build"
PAYLOAD_DIR="$BUILD_DIR/payload"
SCRIPTS_DIR="$BUILD_DIR/scripts"

echo "Building Elyan Security Shield PKG v${VERSION}"
echo "=============================================="

# Check we're on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "Error: This script must be run on macOS to build a PKG"
    exit 1
fi

# Clean previous build
rm -rf "$PAYLOAD_DIR"
mkdir -p "$PAYLOAD_DIR/usr/local/share/elyan-security"
mkdir -p "$PAYLOAD_DIR/usr/local/bin"
mkdir -p "$PAYLOAD_DIR/Library/LaunchDaemons"

# Copy payload files
echo "Preparing payload..."
cp "$SCRIPT_DIR/scripts/elyan-harden.sh" "$PAYLOAD_DIR/usr/local/share/elyan-security/"
cp "$SCRIPT_DIR/scripts/elyan-audit.sh" "$PAYLOAD_DIR/usr/local/share/elyan-security/"
cp "$SCRIPT_DIR/scripts/elyan-monitor.sh" "$PAYLOAD_DIR/usr/local/share/elyan-security/"
cp "$SCRIPT_DIR/LaunchDaemons/com.elyanlabs.security-monitor.plist" "$PAYLOAD_DIR/usr/local/share/elyan-security/"

# Make scripts executable
chmod 755 "$PAYLOAD_DIR/usr/local/share/elyan-security/"*.sh

# Make postinstall executable
chmod 755 "$SCRIPTS_DIR/postinstall"

# Build component package
echo "Building component package..."
pkgbuild \
    --root "$PAYLOAD_DIR" \
    --scripts "$SCRIPTS_DIR" \
    --identifier "$IDENTIFIER" \
    --version "$VERSION" \
    --install-location "/" \
    "$BUILD_DIR/component.pkg"

# Create distribution.xml
cat > "$BUILD_DIR/distribution.xml" << EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>Elyan Labs Security Shield</title>
    <organization>com.elyanlabs</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="true" rootVolumeOnly="true"/>

    <welcome file="welcome.html" mime-type="text/html"/>
    <license file="license.txt" mime-type="text/plain"/>
    <readme file="readme.html" mime-type="text/html"/>

    <choices-outline>
        <line choice="default">
            <line choice="com.elyanlabs.security-shield"/>
        </line>
    </choices-outline>

    <choice id="default"/>
    <choice id="com.elyanlabs.security-shield" visible="false">
        <pkg-ref id="com.elyanlabs.security-shield"/>
    </choice>

    <pkg-ref id="com.elyanlabs.security-shield"
             version="${VERSION}"
             onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
EOF

# Create resources
mkdir -p "$BUILD_DIR/resources"

# Welcome page
cat > "$BUILD_DIR/resources/welcome.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 20px; }
        h1 { color: #333; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; border-radius: 5px; margin: 15px 0; }
        .info { background: #cce5ff; border: 1px solid #0066cc; padding: 10px; border-radius: 5px; margin: 15px 0; }
    </style>
</head>
<body>
    <h1>Elyan Labs Security Shield</h1>
    <p><strong>CVE Mitigations for End-of-Life macOS Systems</strong></p>

    <div class="warning">
        <strong>Important:</strong> This toolkit provides configuration-based mitigations,
        not actual patches. Upgrading to a supported macOS version is always recommended.
    </div>

    <h2>What This Installs</h2>
    <ul>
        <li><strong>elyan-audit</strong> - Scan system for CVE exposure</li>
        <li><strong>elyan-harden</strong> - Apply security mitigations</li>
        <li><strong>elyan-monitor</strong> - Real-time exploitation detection</li>
    </ul>

    <h2>CVEs Addressed</h2>
    <ul>
        <li>CVE-2024-44243 (SIP Bypass)</li>
        <li>CVE-2023-42931 (Privilege Escalation)</li>
        <li>CVE-2024-23225/23296 (Kernel Bypass)</li>
        <li>CVE-2023-42916/42917 (WebKit RCE)</li>
        <li>CVE-2024-40828 (Root Escalation)</li>
    </ul>

    <div class="info">
        After installation, run <code>sudo elyan-harden</code> to apply mitigations.
    </div>
</body>
</html>
EOF

# Readme
cat > "$BUILD_DIR/resources/readme.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 20px; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>Post-Installation Steps</h1>

    <h2>1. Run Security Audit</h2>
    <pre>sudo elyan-audit</pre>
    <p>This scans your system for CVE exposure and misconfigurations.</p>

    <h2>2. Apply Hardening</h2>
    <pre>sudo elyan-harden --level moderate</pre>
    <p>Levels: minimal, moderate, maximum</p>

    <h2>3. Enable Monitoring</h2>
    <pre>sudo launchctl load /Library/LaunchDaemons/com.elyanlabs.security-monitor.plist</pre>
    <p>This enables real-time detection of exploitation attempts.</p>

    <h2>4. Check Status</h2>
    <pre>elyan-status</pre>

    <h2>Uninstallation</h2>
    <pre>sudo launchctl unload /Library/LaunchDaemons/com.elyanlabs.security-monitor.plist
sudo rm -rf /usr/local/bin/elyan-*
sudo rm -rf /usr/local/share/elyan-security
sudo rm -rf /var/db/elyan
sudo rm /Library/LaunchDaemons/com.elyanlabs.security-monitor.plist</pre>

    <h2>Support</h2>
    <p>GitHub: <a href="https://github.com/Scottcjn/elyan-macos-security">github.com/Scottcjn/elyan-macos-security</a></p>
</body>
</html>
EOF

# License
cat > "$BUILD_DIR/resources/license.txt" << 'EOF'
MIT License

Copyright (c) 2025 Elyan Labs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

DISCLAIMER

This software provides configuration-based security mitigations for end-of-life
macOS systems. It does NOT modify Apple system binaries or circumvent security
measures. While we strive to improve security posture, no mitigation can fully
replace vendor security patches. Use at your own risk.
EOF

# Build final product package
echo "Building product package..."
productbuild \
    --distribution "$BUILD_DIR/distribution.xml" \
    --resources "$BUILD_DIR/resources" \
    --package-path "$BUILD_DIR" \
    "$SCRIPT_DIR/$PKG_NAME"

echo ""
echo "=============================================="
echo "Build complete: $PKG_NAME"
echo "=============================================="
echo ""
echo "To install:"
echo "  sudo installer -pkg $PKG_NAME -target /"
echo ""
echo "Or double-click the PKG file in Finder."
