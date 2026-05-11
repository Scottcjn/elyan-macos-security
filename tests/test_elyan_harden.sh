#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

make_sw_vers() {
    local version="$1"
    cat > "$TMP_DIR/sw_vers" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "-productVersion" ]]; then
    echo "$version"
else
    echo "$version"
fi
EOF
    chmod +x "$TMP_DIR/sw_vers"
}

assert_eq() {
    local expected="$1"
    local actual="$2"
    local label="$3"

    if [[ "$expected" != "$actual" ]]; then
        echo "$label: expected '$expected', got '$actual'" >&2
        exit 1
    fi
}

PATH="$TMP_DIR:$PATH"
tr -d '\r' < "$ROOT_DIR/scripts/elyan-harden.sh" > "$TMP_DIR/elyan-harden.sh"
source "$TMP_DIR/elyan-harden.sh"

make_sw_vers "10.15.7"
assert_eq "catalina" "$(detect_macos_version)" "Catalina detection"

make_sw_vers "12.7.6"
assert_eq "monterey" "$(detect_macos_version)" "Monterey detection"

make_sw_vers "11.7.10"
assert_eq "bigsur" "$(detect_macos_version)" "Big Sur detection"

make_sw_vers "13.6.9"
assert_eq "other" "$(detect_macos_version)" "unsupported macOS detection"
