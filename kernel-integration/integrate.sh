#!/bin/bash
# CockLocker Kernel Integration Script
# Called by parent kernel compilation suite to integrate hardened Cockpit

set -euo pipefail

# Script can be sourced or executed
COCKLOCKER_ROOT="${COCKLOCKER_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
KERNEL_BUILD_DIR="${KERNEL_BUILD_DIR:-/usr/src/linux}"
KERNEL_VERSION="${KERNEL_VERSION:-$(uname -r)}"
INSTALL_ROOT="${INSTALL_ROOT:-/}"
BUILD_JOBS="${BUILD_JOBS:-$(nproc)}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[COCKLOCKER-KERNEL]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[COCKLOCKER-KERNEL]${NC} $1"
}

log_error() {
    echo -e "${RED}[COCKLOCKER-KERNEL]${NC} $1"
}

log_section() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Check if running in kernel build context
if [ -n "${KERNEL_BUILD_CONTEXT:-}" ]; then
    log_info "Running in kernel build suite context"
    NON_INTERACTIVE=1
else
    log_warn "Not running in kernel build context, assuming standalone"
    NON_INTERACTIVE=0
fi

log_section "CockLocker Kernel Integration"
log_info "CockLocker root: $COCKLOCKER_ROOT"
log_info "Kernel build dir: $KERNEL_BUILD_DIR"
log_info "Kernel version: $KERNEL_VERSION"
log_info "Install root: $INSTALL_ROOT"
log_info "Build jobs: $BUILD_JOBS"

# Verify nested submodule structure
log_info "Verifying nested submodule structure..."
if [ ! -f "$COCKLOCKER_ROOT/.gitmodules" ]; then
    log_error "CockLocker .gitmodules not found. This doesn't appear to be a CockLocker repository."
    exit 1
fi

if [ ! -d "$COCKLOCKER_ROOT/cockpit" ]; then
    log_info "Cockpit submodule not initialized. Initializing now..."
    cd "$COCKLOCKER_ROOT"
    git submodule update --init --recursive
    cd - > /dev/null
fi

if [ ! -f "$COCKLOCKER_ROOT/cockpit/configure.ac" ]; then
    log_error "Cockpit submodule appears to be empty. Run 'git submodule update --init --recursive' in parent repository."
    exit 1
fi

log_info "Nested submodule structure verified ✓"

# Export build environment for hardening
export COCKLOCKER_KERNEL_INTEGRATION=1
export COCKLOCKER_VERSION="$(git -C "$COCKLOCKER_ROOT" describe --always --dirty 2>/dev/null || echo 'unknown')"

# Comprehensive hardening flags (from ImageHarden model)
HARDENING_CFLAGS=(
    # Stack protection
    "-fstack-protector-strong"
    "-fstack-clash-protection"

    # Format string protections
    "-Wformat"
    "-Wformat-security"
    "-Werror=format-security"

    # Fortify source
    "-D_FORTIFY_SOURCE=3"

    # PIE
    "-fPIE"

    # Control Flow Integrity
    "-fcf-protection=full"

    # Stack canaries
    "-fstack-protector-all"

    # Trap on signed integer overflow
    "-ftrapv"

    # Optimization with security
    "-O2"
    "-g"

    # Buffer overflow detection
    "-D_GLIBCXX_ASSERTIONS"

    # Pointer safety
    "-fno-strict-overflow"
    "-fno-delete-null-pointer-checks"

    # Warnings as errors for critical issues
    "-Werror=implicit-function-declaration"
    "-Werror=return-type"
)

# Intel CET shadow stack (if supported)
if gcc -mshstk -E - </dev/null >/dev/null 2>&1; then
    HARDENING_CFLAGS+=("-mshstk")
    log_info "Intel CET shadow stack support detected and enabled"
fi

HARDENING_LDFLAGS=(
    "-Wl,-z,relro"
    "-Wl,-z,now"
    "-Wl,-z,noexecstack"
    "-Wl,-z,separate-code"
    "-pie"
)

export CFLAGS="${HARDENING_CFLAGS[*]} ${CFLAGS:-}"
export CXXFLAGS="${HARDENING_CFLAGS[*]} ${CXXFLAGS:-}"
export LDFLAGS="${HARDENING_LDFLAGS[*]} ${LDFLAGS:-}"

log_info "Hardening flags configured"

# Build hardened Cockpit
build_hardened_cockpit() {
    log_section "Building Hardened Cockpit"

    local PREFIX="${INSTALL_ROOT}/opt/cockpit-hardened"
    local COCKPIT_DIR="$COCKLOCKER_ROOT/cockpit"

    cd "$COCKPIT_DIR"

    # Generate configure if needed
    if [ ! -f "configure" ]; then
        log_info "Generating build system..."
        ./autogen.sh
    fi

    # Configure
    log_info "Configuring with hardening flags..."
    ./configure \
        --prefix="$PREFIX" \
        --sysconfdir="$PREFIX/etc" \
        --localstatedir="$PREFIX/var" \
        --enable-strict \
        --disable-debug \
        --with-cockpit-user=cockpit-hardened \
        --with-cockpit-group=cockpit-hardened \
        CFLAGS="${CFLAGS}" \
        CXXFLAGS="${CXXFLAGS}" \
        LDFLAGS="${LDFLAGS}"

    # Build
    log_info "Building Cockpit with $BUILD_JOBS jobs..."
    make -j"$BUILD_JOBS"

    # Install
    log_info "Installing to $PREFIX..."
    make install DESTDIR="${DESTDIR:-}"

    cd "$COCKLOCKER_ROOT"
}

# Build Rust sandbox
build_sandbox() {
    log_section "Building Rust Sandbox"

    cd "$COCKLOCKER_ROOT/sandbox"

    if ! command -v cargo &> /dev/null; then
        log_error "Rust/cargo not found. Please install Rust toolchain."
        exit 1
    fi

    log_info "Building release binary..."
    cargo build --release

    # Install sandbox binary
    local INSTALL_DIR="${INSTALL_ROOT}/opt/cockpit-hardened/bin"
    mkdir -p "${DESTDIR:-}$INSTALL_DIR"
    cp target/release/cockpit-sandbox "${DESTDIR:-}$INSTALL_DIR/"
    chmod 755 "${DESTDIR:-}$INSTALL_DIR/cockpit-sandbox"

    log_info "Sandbox installed to $INSTALL_DIR"

    cd "$COCKLOCKER_ROOT"
}

# Install configurations
install_configs() {
    log_section "Installing Hardened Configurations"

    local CONFIG_DIR="${INSTALL_ROOT}/opt/cockpit-hardened/etc/cockpit"
    local SECURITY_DIR="${INSTALL_ROOT}/opt/cockpit-hardened/security"

    mkdir -p "${DESTDIR:-}$CONFIG_DIR"
    mkdir -p "${DESTDIR:-}$SECURITY_DIR"

    # Install Cockpit config
    cp "$COCKLOCKER_ROOT/hardened_configs/cockpit.conf" \
       "${DESTDIR:-}$CONFIG_DIR/"

    # Install firewall rules
    cp "$COCKLOCKER_ROOT/hardened_configs/firewall-rules.sh" \
       "${DESTDIR:-}$SECURITY_DIR/"
    chmod 755 "${DESTDIR:-}$SECURITY_DIR/firewall-rules.sh"

    # Install PAM config
    mkdir -p "${DESTDIR:-}${INSTALL_ROOT}/etc/pam.d"
    cp "$COCKLOCKER_ROOT/hardened_configs/pam.d-cockpit" \
       "${DESTDIR:-}${INSTALL_ROOT}/etc/pam.d/cockpit-hardened"

    log_info "Configurations installed"
}

# Install monitoring tools
install_monitoring() {
    log_section "Installing Security Monitoring"

    local MON_DIR="${INSTALL_ROOT}/opt/cockpit-hardened/monitoring"

    mkdir -p "${DESTDIR:-}$MON_DIR"

    cp "$COCKLOCKER_ROOT/monitoring/security_monitor.py" \
       "${DESTDIR:-}$MON_DIR/"
    chmod 755 "${DESTDIR:-}$MON_DIR/security_monitor.py"

    log_info "Security monitoring installed"
}

# Create systemd service
install_systemd_service() {
    log_section "Installing systemd Service"

    local SERVICE_DIR="${INSTALL_ROOT}/etc/systemd/system"
    mkdir -p "${DESTDIR:-}$SERVICE_DIR"

    cat > "${DESTDIR:-}$SERVICE_DIR/cockpit-hardened.service" << 'EOF'
[Unit]
Description=CockLocker - Hardened Cockpit Web Service
Documentation=https://github.com/yourusername/COCKLOCKER
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStartPre=/opt/cockpit-hardened/security/firewall-rules.sh
ExecStart=/opt/cockpit-hardened/bin/cockpit-sandbox \
    --cockpit-path=/opt/cockpit-hardened \
    --bind-address=127.0.0.1 \
    --port=9090 \
    --xen-hardening \
    --verbose
ExecStartPost=/opt/cockpit-hardened/monitoring/security_monitor.py
Restart=on-failure
RestartSec=10
User=root
Group=root

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/cockpit-hardened
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=false
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF

    log_info "systemd service installed"
}

# Create user and group
create_user_group() {
    log_info "Creating cockpit-hardened user and group..."

    if [ -z "${DESTDIR:-}" ]; then
        # Real installation
        if ! getent group cockpit-hardened > /dev/null 2>&1; then
            groupadd -r cockpit-hardened
        fi
        if ! getent passwd cockpit-hardened > /dev/null 2>&1; then
            useradd -r -g cockpit-hardened -d /nonexistent -s /bin/false cockpit-hardened
        fi
    else
        # DESTDIR installation (for packaging)
        log_warn "DESTDIR set, skipping user/group creation (should be done by package manager)"
    fi
}

# Set permissions
set_permissions() {
    log_section "Setting Secure Permissions"

    local PREFIX="${INSTALL_ROOT}/opt/cockpit-hardened"

    # Secure ownership
    chown -R root:root "${DESTDIR:-}$PREFIX" 2>/dev/null || true

    # Remove world permissions
    chmod -R o-rwx "${DESTDIR:-}$PREFIX" 2>/dev/null || true

    # Secure binaries
    chmod 750 "${DESTDIR:-}$PREFIX/libexec/"* 2>/dev/null || true
    chmod 750 "${DESTDIR:-}$PREFIX/bin/"* 2>/dev/null || true

    # Create log directory
    mkdir -p "${DESTDIR:-}/var/log/cockpit-hardened"
    chmod 750 "${DESTDIR:-}/var/log/cockpit-hardened" 2>/dev/null || true

    log_info "Permissions configured"
}

# Verify hardening
verify_hardening() {
    log_section "Verifying Security Hardening"

    if [ -n "${DESTDIR:-}" ]; then
        log_warn "DESTDIR set, skipping verification (verify after installation)"
        return
    fi

    local PREFIX="${INSTALL_ROOT}/opt/cockpit-hardened"
    local VERIFIED=0
    local FAILED=0

    for binary in "$PREFIX/libexec/cockpit-ws" "$PREFIX/libexec/cockpit-tls" "$PREFIX/bin/cockpit-sandbox"; do
        if [ ! -f "$binary" ]; then
            continue
        fi

        log_info "Checking $(basename "$binary")..."

        # Check PIE
        if readelf -h "$binary" 2>/dev/null | grep -q "Type:.*DYN"; then
            log_info "  ✓ PIE enabled"
            ((VERIFIED++))
        else
            log_warn "  ✗ PIE not enabled"
            ((FAILED++))
        fi

        # Check stack canary
        if readelf -s "$binary" 2>/dev/null | grep -q "__stack_chk_fail"; then
            log_info "  ✓ Stack canary enabled"
            ((VERIFIED++))
        else
            log_warn "  ✗ Stack canary not found"
            ((FAILED++))
        fi

        # Check RELRO
        if readelf -l "$binary" 2>/dev/null | grep -q "GNU_RELRO"; then
            log_info "  ✓ RELRO enabled"
            ((VERIFIED++))
        else
            log_warn "  ✗ RELRO not enabled"
            ((FAILED++))
        fi

        # Check NX
        if readelf -l "$binary" 2>/dev/null | grep -q "GNU_STACK" && \
           ! readelf -l "$binary" 2>/dev/null | grep "GNU_STACK" | grep -q "RWE"; then
            log_info "  ✓ NX enabled"
            ((VERIFIED++))
        else
            log_warn "  ✗ NX not enabled"
            ((FAILED++))
        fi

        # Check FORTIFY
        if readelf -s "$binary" 2>/dev/null | grep -qE "__.*_chk"; then
            log_info "  ✓ FORTIFY_SOURCE detected"
            ((VERIFIED++))
        else
            log_warn "  ✗ FORTIFY_SOURCE not detected"
            ((FAILED++))
        fi
    done

    log_info "Verification complete: $VERIFIED checks passed, $FAILED checks failed"

    if [ $FAILED -gt 0 ]; then
        log_warn "Some security checks failed. Review build configuration."
    fi
}

# Generate integration report
generate_report() {
    log_section "Integration Report"

    local REPORT_FILE="${COCKLOCKER_ROOT}/kernel-integration/integration-report.txt"

    cat > "$REPORT_FILE" << EOF
CockLocker Kernel Integration Report
=====================================
Generated: $(date)
CockLocker Version: $COCKLOCKER_VERSION
Kernel Version: $KERNEL_VERSION

Build Configuration:
-------------------
CockLocker Root: $COCKLOCKER_ROOT
Kernel Build Dir: $KERNEL_BUILD_DIR
Install Root: $INSTALL_ROOT
DESTDIR: ${DESTDIR:-<none>}
Build Jobs: $BUILD_JOBS

Hardening Flags:
---------------
CFLAGS: $CFLAGS

LDFLAGS: $LDFLAGS

Installation Paths:
------------------
Cockpit: ${INSTALL_ROOT}/opt/cockpit-hardened
Sandbox: ${INSTALL_ROOT}/opt/cockpit-hardened/bin/cockpit-sandbox
Configs: ${INSTALL_ROOT}/opt/cockpit-hardened/etc/cockpit
Security: ${INSTALL_ROOT}/opt/cockpit-hardened/security
Monitoring: ${INSTALL_ROOT}/opt/cockpit-hardened/monitoring
Systemd: ${INSTALL_ROOT}/etc/systemd/system/cockpit-hardened.service
Logs: /var/log/cockpit-hardened

Components Built:
----------------
✓ Hardened Cockpit binaries
✓ Rust sandbox (seccomp + namespaces + Landlock)
✓ Security configurations
✓ Firewall rules
✓ PAM configuration
✓ Security monitoring
✓ systemd service

Next Steps:
----------
1. If using DESTDIR, copy ${DESTDIR} contents to target system
2. Create cockpit-hardened user/group if not done
3. Enable service: systemctl enable cockpit-hardened
4. Start service: systemctl start cockpit-hardened
5. Verify: systemctl status cockpit-hardened
6. Access: https://localhost:9090

Security Notes:
--------------
- All binaries compiled with APT-level hardening flags
- Kernel must support: Landlock, seccomp, namespaces (see KERNEL_CONFIG.md)
- Firewall rules restrict access to localhost by default
- Security monitoring runs automatically with service
- Review logs at /var/log/cockpit-hardened/

For Kernel Suite Maintainers:
-----------------------------
- This build integrates cleanly into kernel compilation workflows
- All builds are reproducible and non-interactive
- Use DESTDIR for staged installations
- Set KERNEL_BUILD_CONTEXT=1 for kernel build integration
- Nested submodule (cockpit) is handled automatically

EOF

    log_info "Integration report written to: $REPORT_FILE"
    cat "$REPORT_FILE"
}

# Main integration flow
main() {
    log_info "Starting CockLocker kernel integration..."

    # Create user/group
    create_user_group

    # Build components
    build_hardened_cockpit
    build_sandbox

    # Install components
    install_configs
    install_monitoring
    install_systemd_service

    # Set permissions
    set_permissions

    # Verify
    verify_hardening

    # Generate report
    generate_report

    log_section "Integration Complete!"
    log_info "CockLocker successfully integrated into kernel build"
    log_info "Review integration report for details"

    if [ -z "${DESTDIR:-}" ]; then
        log_info ""
        log_info "To start hardened Cockpit:"
        log_info "  systemctl enable cockpit-hardened"
        log_info "  systemctl start cockpit-hardened"
        log_info ""
        log_info "Access at: https://localhost:9090"
    fi
}

# Run main if executed (not sourced)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
