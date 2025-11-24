#!/bin/bash
################################################################################
# CockLocker Pre-Start Script
# ============================================================================
# Executed before Cockpit service starts
# Configures Intel Meteor Lake optimizations and security hardening
################################################################################

set -euo pipefail

COCKLOCKER_PREFIX="${COCKLOCKER_PREFIX:-/opt/cockpit-hardened}"
LOG_DIR="/var/log/cockpit-hardened"

log() {
    echo "[$(date -Iseconds)] $1" | tee -a "$LOG_DIR/startup.log"
}

log "CockLocker pre-start initializing..."

# Create log directory
mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"

# ============================================================================
# INTEL METEOR LAKE POWER OPTIMIZATION
# ============================================================================

configure_meteorlake() {
    log "Configuring Intel Meteor Lake optimizations..."

    # Check for Meteor Lake CPU
    local cpu_model=$(grep -m1 "model" /proc/cpuinfo | cut -d: -f2 | tr -d ' ')

    if [ "$cpu_model" -ge 170 ] && [ "$cpu_model" -le 175 ]; then
        log "Meteor Lake CPU detected (model $cpu_model)"

        # Set Thread Director for AI workloads
        for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            echo "schedutil" > "$cpu" 2>/dev/null || true
        done

        # Set energy performance preference
        for epp in /sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference; do
            echo "balance_performance" > "$epp" 2>/dev/null || true
        done

        # Enable NPU power management if available
        if [ -d "/sys/class/accel/accel0" ]; then
            echo "auto" > /sys/class/accel/accel0/power_mode 2>/dev/null || true
            log "NPU power management configured"
        fi

        log "Meteor Lake optimizations applied"
    else
        log "Non-Meteor Lake CPU (model $cpu_model), using generic settings"
    fi
}

# ============================================================================
# SECURITY HARDENING
# ============================================================================

apply_security_hardening() {
    log "Applying security hardening..."

    # Kernel hardening via sysctl
    sysctl -w kernel.dmesg_restrict=1 2>/dev/null || true
    sysctl -w kernel.kptr_restrict=2 2>/dev/null || true
    sysctl -w kernel.perf_event_paranoid=3 2>/dev/null || true
    sysctl -w kernel.yama.ptrace_scope=2 2>/dev/null || true

    # Network hardening
    sysctl -w net.ipv4.tcp_syncookies=1 2>/dev/null || true
    sysctl -w net.ipv4.tcp_rfc1337=1 2>/dev/null || true
    sysctl -w net.ipv4.conf.all.rp_filter=1 2>/dev/null || true
    sysctl -w net.ipv4.conf.default.rp_filter=1 2>/dev/null || true

    log "Security hardening applied"
}

# ============================================================================
# FIREWALL CONFIGURATION
# ============================================================================

configure_firewall() {
    log "Configuring firewall rules..."

    local firewall_script="$COCKLOCKER_PREFIX/etc/cockpit/firewall-rules.sh"

    if [ -x "$firewall_script" ]; then
        "$firewall_script" 2>&1 | tee -a "$LOG_DIR/firewall.log"
        log "Firewall rules applied"
    else
        log "Firewall script not found, applying basic rules..."

        # Basic iptables rules for Cockpit
        iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
        iptables -A INPUT -p tcp --dport 9090 -s 127.0.0.1 -j ACCEPT 2>/dev/null || true
        iptables -A INPUT -p tcp --dport 9090 -j DROP 2>/dev/null || true

        ip6tables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
        ip6tables -A INPUT -p tcp --dport 9090 -s ::1 -j ACCEPT 2>/dev/null || true
        ip6tables -A INPUT -p tcp --dport 9090 -j DROP 2>/dev/null || true
    fi
}

# ============================================================================
# VERIFY DEPENDENCIES
# ============================================================================

verify_dependencies() {
    log "Verifying dependencies..."

    local required_binaries=(
        "$COCKLOCKER_PREFIX/libexec/cockpit-ws"
        "$COCKLOCKER_PREFIX/libexec/cockpit-session"
    )

    for binary in "${required_binaries[@]}"; do
        if [ -x "$binary" ]; then
            log "Found: $binary"
        else
            log "ERROR: Missing required binary: $binary"
            exit 1
        fi
    done

    # Check for cockpit-ws user
    if ! id -u cockpit-ws &>/dev/null; then
        log "Creating cockpit-ws user..."
        useradd -r -s /sbin/nologin -d /nonexistent cockpit-ws
    fi

    log "Dependencies verified"
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    verify_dependencies
    configure_meteorlake
    apply_security_hardening
    configure_firewall

    log "CockLocker pre-start complete"
}

main "$@"
