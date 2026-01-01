#!/bin/bash
# Elyan Labs macOS Security Shield - Real-time Monitor
# Detects exploitation attempts for known CVEs
# Version: 1.0.0

set -e

VERSION="1.0.0"
LOG_DIR="/var/log/elyan"
ALERT_LOG="$LOG_DIR/security_alerts.log"
PID_FILE="/var/run/elyan-monitor.pid"

# Create log directory
mkdir -p "$LOG_DIR"

log_alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$severity] $message" | tee -a "$ALERT_LOG"

    # Optional: Send notification (if osascript available)
    if [[ "$severity" == "CRITICAL" ]] && command -v osascript &>/dev/null; then
        osascript -e "display notification \"$message\" with title \"Elyan Security Alert\" sound name \"Basso\"" 2>/dev/null || true
    fi
}

check_pid() {
    if [[ -f "$PID_FILE" ]]; then
        OLD_PID=$(cat "$PID_FILE")
        if kill -0 "$OLD_PID" 2>/dev/null; then
            echo "Monitor already running (PID: $OLD_PID)"
            exit 1
        fi
    fi
    echo $$ > "$PID_FILE"
}

cleanup() {
    rm -f "$PID_FILE"
    log_alert "INFO" "Elyan Security Monitor stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM

#==============================================================================
# Monitor: Filesystem changes (/Library/Filesystems - CVE-2024-44243)
#==============================================================================
monitor_filesystems() {
    if [[ -d /Library/Filesystems ]]; then
        CURRENT_HASH=$(ls -la /Library/Filesystems 2>/dev/null | md5 2>/dev/null || md5sum | cut -d' ' -f1)
        if [[ -f /var/db/elyan/filesystems_hash ]]; then
            SAVED_HASH=$(cat /var/db/elyan/filesystems_hash)
            if [[ "$CURRENT_HASH" != "$SAVED_HASH" ]]; then
                log_alert "CRITICAL" "CVE-2024-44243: /Library/Filesystems modified! Possible SIP bypass attempt"
                echo "$CURRENT_HASH" > /var/db/elyan/filesystems_hash
            fi
        else
            mkdir -p /var/db/elyan
            echo "$CURRENT_HASH" > /var/db/elyan/filesystems_hash
        fi
    fi
}

#==============================================================================
# Monitor: New kernel extensions loaded
#==============================================================================
monitor_kexts() {
    CURRENT_KEXTS=$(kextstat 2>/dev/null | grep -v "com.apple" | grep -v "Index" | awk '{print $6}' | sort | md5 2>/dev/null || md5sum | cut -d' ' -f1)
    if [[ -f /var/db/elyan/kexts_hash ]]; then
        SAVED_HASH=$(cat /var/db/elyan/kexts_hash)
        if [[ "$CURRENT_KEXTS" != "$SAVED_HASH" ]]; then
            log_alert "WARNING" "New kernel extension loaded - review with: kextstat | grep -v com.apple"
            echo "$CURRENT_KEXTS" > /var/db/elyan/kexts_hash
        fi
    else
        mkdir -p /var/db/elyan
        echo "$CURRENT_KEXTS" > /var/db/elyan/kexts_hash
    fi
}

#==============================================================================
# Monitor: SUID binary changes (CVE-2024-40828)
#==============================================================================
monitor_suid() {
    if [[ -f /var/db/elyan/suid_baseline.txt ]]; then
        CURRENT_SUID=$(find /usr/bin /usr/sbin /usr/libexec -perm -4000 2>/dev/null | sort | md5 2>/dev/null || md5sum | cut -d' ' -f1)
        if [[ -f /var/db/elyan/suid_hash ]]; then
            SAVED_HASH=$(cat /var/db/elyan/suid_hash)
            if [[ "$CURRENT_SUID" != "$SAVED_HASH" ]]; then
                log_alert "CRITICAL" "CVE-2024-40828: SUID binaries changed! Possible privilege escalation"
                echo "$CURRENT_SUID" > /var/db/elyan/suid_hash
                # Log the difference
                find /usr/bin /usr/sbin /usr/libexec -perm -4000 2>/dev/null | sort > /tmp/suid_current.txt
                diff /var/db/elyan/suid_baseline.txt /tmp/suid_current.txt >> "$ALERT_LOG" 2>/dev/null || true
            fi
        else
            mkdir -p /var/db/elyan
            echo "$CURRENT_SUID" > /var/db/elyan/suid_hash
        fi
    fi
}

#==============================================================================
# Monitor: Suspicious process activity
#==============================================================================
monitor_processes() {
    # Check for storagekitd doing unusual things (CVE-2024-44243)
    if pgrep -x storagekitd > /dev/null; then
        STORAGEKITD_CPU=$(ps -p $(pgrep -x storagekitd) -o %cpu= 2>/dev/null | tr -d ' ')
        if [[ -n "$STORAGEKITD_CPU" ]] && (( $(echo "$STORAGEKITD_CPU > 50" | bc -l 2>/dev/null || echo 0) )); then
            log_alert "WARNING" "storagekitd high CPU usage ($STORAGEKITD_CPU%) - possible exploitation"
        fi
    fi

    # Check for suspicious diskutil activity (CVE-2023-42931)
    if pgrep -f "diskutil" > /dev/null; then
        DISKUTIL_PARENT=$(ps -p $(pgrep -f "diskutil" | head -1) -o ppid= 2>/dev/null | tr -d ' ')
        if [[ -n "$DISKUTIL_PARENT" ]] && [[ "$DISKUTIL_PARENT" != "1" ]]; then
            PARENT_CMD=$(ps -p "$DISKUTIL_PARENT" -o comm= 2>/dev/null || echo "unknown")
            if [[ "$PARENT_CMD" != "bash" ]] && [[ "$PARENT_CMD" != "zsh" ]] && [[ "$PARENT_CMD" != "Terminal" ]]; then
                log_alert "WARNING" "diskutil spawned by unusual parent: $PARENT_CMD (PID $DISKUTIL_PARENT)"
            fi
        fi
    fi
}

#==============================================================================
# Monitor: New listening ports
#==============================================================================
monitor_network() {
    LISTENING=$(lsof -iTCP -sTCP:LISTEN -P 2>/dev/null | grep -v "^COMMAND" | awk '{print $1":"$9}' | sort | md5 2>/dev/null || md5sum | cut -d' ' -f1)
    if [[ -f /var/db/elyan/listening_hash ]]; then
        SAVED_HASH=$(cat /var/db/elyan/listening_hash)
        if [[ "$LISTENING" != "$SAVED_HASH" ]]; then
            log_alert "WARNING" "New listening network service detected"
            lsof -iTCP -sTCP:LISTEN -P 2>/dev/null | tail -5 >> "$ALERT_LOG"
            echo "$LISTENING" > /var/db/elyan/listening_hash
        fi
    else
        mkdir -p /var/db/elyan
        echo "$LISTENING" > /var/db/elyan/listening_hash
    fi
}

#==============================================================================
# Monitor: Login attempts
#==============================================================================
monitor_logins() {
    # Check for recent failed sudo attempts
    FAILED_SUDO=$(grep -c "authentication failure" /var/log/system.log 2>/dev/null || echo "0")
    if [[ -f /var/db/elyan/failed_sudo_count ]]; then
        SAVED_COUNT=$(cat /var/db/elyan/failed_sudo_count)
        if [[ "$FAILED_SUDO" -gt "$SAVED_COUNT" ]]; then
            NEW_FAILURES=$((FAILED_SUDO - SAVED_COUNT))
            if [[ $NEW_FAILURES -gt 5 ]]; then
                log_alert "WARNING" "$NEW_FAILURES new failed sudo attempts detected"
            fi
        fi
    fi
    mkdir -p /var/db/elyan
    echo "$FAILED_SUDO" > /var/db/elyan/failed_sudo_count
}

#==============================================================================
# Main monitoring loop
#==============================================================================
main() {
    echo "Elyan Labs Security Monitor v$VERSION"
    echo "Monitoring for CVE exploitation attempts..."
    echo "Log file: $ALERT_LOG"
    echo ""

    check_pid
    log_alert "INFO" "Elyan Security Monitor started (PID: $$)"

    # Initial baseline capture
    monitor_filesystems
    monitor_kexts
    monitor_suid
    monitor_network

    INTERVAL=${1:-60}  # Default 60 second intervals
    echo "Check interval: ${INTERVAL}s"
    echo "Press Ctrl+C to stop"
    echo ""

    while true; do
        monitor_filesystems
        monitor_kexts
        monitor_suid
        monitor_processes
        monitor_network
        monitor_logins

        sleep "$INTERVAL"
    done
}

# Parse arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: elyan-monitor [interval_seconds]"
        echo ""
        echo "Monitors system for CVE exploitation attempts in real-time."
        echo "Default interval: 60 seconds"
        echo ""
        echo "Examples:"
        echo "  elyan-monitor          # Check every 60 seconds"
        echo "  elyan-monitor 30       # Check every 30 seconds"
        echo "  elyan-monitor --daemon # Run as background daemon"
        exit 0
        ;;
    --daemon)
        nohup "$0" 60 > /dev/null 2>&1 &
        echo "Monitor started in background (PID: $!)"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
