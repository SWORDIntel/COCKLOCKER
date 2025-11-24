#!/bin/bash
################################################################################
# CockLocker Post-Stop Script
# ============================================================================
# Executed after Cockpit service stops
# Cleanup and logging
################################################################################

set -euo pipefail

LOG_DIR="/var/log/cockpit-hardened"

log() {
    echo "[$(date -Iseconds)] $1" >> "$LOG_DIR/shutdown.log"
}

log "CockLocker post-stop cleanup starting..."

# Kill any orphaned cockpit processes
pkill -9 -f cockpit-ws 2>/dev/null || true
pkill -9 -f cockpit-bridge 2>/dev/null || true

# Rotate logs if they're too large
for logfile in "$LOG_DIR"/*.log; do
    if [ -f "$logfile" ]; then
        size=$(stat -c%s "$logfile" 2>/dev/null || echo 0)
        if [ "$size" -gt 104857600 ]; then  # 100MB
            mv "$logfile" "${logfile}.1" 2>/dev/null || true
            gzip "${logfile}.1" 2>/dev/null || true
        fi
    fi
done

# Reset power settings to balanced (optional)
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo "schedutil" > "$cpu" 2>/dev/null || true
done

log "CockLocker post-stop cleanup complete"

exit 0
