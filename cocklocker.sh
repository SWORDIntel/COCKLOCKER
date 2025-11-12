#!/bin/bash
################################################################################
# CockLocker - APT-Level Hardening Suite Master Entry Point
# ============================================================================
# Unified orchestration script for hardened Cockpit deployment
# Supports standalone and kernel-integrated workflows with SIMD optimization
#
# USAGE:
#   ./cocklocker.sh [COMMAND] [OPTIONS]
#
# COMMANDS:
#   detect-cpu        Detect CPU capabilities (AVX2/AVX512)
#   build             Build hardened Cockpit (standalone mode)
#   kernel-integrate  Integrate with kernel build suite
#   install           Install to system (requires root)
#   verify            Verify security hardening of binaries
#   monitor           Run real-time threat detection
#   test              Run security test suite
#   help              Display this help message
#
# EXAMPLES:
#   # Detect available SIMD capabilities
#   ./cocklocker.sh detect-cpu
#
#   # Build with best available SIMD (AVX2 preferred, AVX512 if available)
#   ./cocklocker.sh build --with-simd=auto
#
#   # Build with specific SIMD (AVX2 only)
#   ./cocklocker.sh build --with-simd=avx2
#
#   # Full standalone installation
#   sudo ./cocklocker.sh build install
#
#   # Kernel build suite integration
#   KERNEL_BUILD_CONTEXT=1 ./cocklocker.sh kernel-integrate
#
#   # Verify installed hardening
#   ./cocklocker.sh verify
#
# ENVIRONMENT VARIABLES:
#   COCKLOCKER_PREFIX      Installation prefix (default: /opt/cockpit-hardened)
#   KERNEL_BUILD_CONTEXT   Set by parent kernel build suite
#   KERNEL_BUILD_DIR       Kernel source directory for integration
#   INSTALL_ROOT           Staging root for DESTDIR builds
#   BUILD_JOBS             Parallel build jobs (default: nproc)
#   SIMD_LEVEL             Force SIMD level: auto, avx2, avx512, none
#   DEBUG                  Enable verbose output (0/1)
#
################################################################################

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COCKLOCKER_VERSION="v1.0-enhanced"
PREFIX="${COCKLOCKER_PREFIX:-/opt/cockpit-hardened}"
BUILD_DIR="${SCRIPT_DIR}/build"
SANDBOX_DIR="${SCRIPT_DIR}/sandbox"
COCKPIT_DIR="${SCRIPT_DIR}/cockpit"

# Build configuration
BUILD_JOBS="${BUILD_JOBS:-$(nproc)}"
DEBUG="${DEBUG:-0}"

# SIMD optimization configuration
SIMD_LEVEL="${SIMD_LEVEL:-auto}"  # auto, avx2, avx512, none

# ============================================================================
# COLOR OUTPUT & LOGGING
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

log_debug() {
    if [ "$DEBUG" -eq 1 ]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
}

# ============================================================================
# CPU CAPABILITY DETECTION
# ============================================================================

# Detect CPU features using /proc/cpuinfo
detect_cpu_features() {
    local cpu_flags=""

    if [ -f /proc/cpuinfo ]; then
        cpu_flags=$(grep "^flags" /proc/cpuinfo | head -1 | cut -d: -f2)
    fi

    echo "$cpu_flags"
}

# Check if specific CPU feature is available
has_cpu_feature() {
    local feature="$1"
    local flags=$(detect_cpu_features)

    [[ "$flags" =~ " $feature " ]] || [[ "$flags" =~ "^$feature " ]]
}

# Detect SIMD capabilities and recommend level
detect_simd_capabilities() {
    log_section "CPU SIMD Capability Detection"

    local has_avx512="no"
    local has_avx2="no"
    local has_sse42="no"

    # Check for AVX512 (Multiple sub-features)
    if has_cpu_feature "avx512f"; then
        has_avx512="yes"
        log_success "AVX-512 Foundation (avx512f) detected"
    fi

    # Check for AVX2
    if has_cpu_feature "avx2"; then
        has_avx2="yes"
        log_success "AVX2 detected"
    fi

    # Check for SSE 4.2
    if has_cpu_feature "sse4_2"; then
        has_sse42="yes"
        log_success "SSE4.2 detected"
    fi

    # Determine recommendation
    local recommended="none"
    if [ "$has_avx512" = "yes" ]; then
        recommended="avx512"
        log_info "Recommendation: ${CYAN}AVX-512${NC} (best performance)"
    elif [ "$has_avx2" = "yes" ]; then
        recommended="avx2"
        log_info "Recommendation: ${CYAN}AVX2${NC} (recommended for compatibility)"
    elif [ "$has_sse42" = "yes" ]; then
        recommended="sse42"
        log_info "Recommendation: ${CYAN}SSE4.2${NC} (baseline support)"
    else
        log_warn "No SIMD support detected"
    fi

    # Output detection results
    echo ""
    echo "Capabilities Summary:"
    echo "  AVX-512: ${has_avx512}"
    echo "  AVX2:    ${has_avx2}"
    echo "  SSE4.2:  ${has_sse42}"
    echo ""
    echo "Build Recommendation: $recommended"
    echo ""

    # Return the recommended level for use in build process
    echo "$recommended"
}

# Resolve SIMD build flags
resolve_simd_flags() {
    local simd_request="$1"
    local detected_simd="$2"

    case "$simd_request" in
        auto)
            # Use detected capabilities, falling back to AVX2 as default
            if [ "$detected_simd" = "avx512" ]; then
                echo "-mavx512f -mavx512cd -mavx512bw -mavx512dq"
            elif [ "$detected_simd" = "avx2" ]; then
                echo "-mavx2"
            elif [ "$detected_simd" = "sse42" ]; then
                echo "-msse4.2"
            else
                echo "-mavx2"  # Safe default if nothing detected
            fi
            ;;
        avx512)
            if [ "$detected_simd" = "avx512" ]; then
                log_info "Using AVX-512 as requested"
                echo "-mavx512f -mavx512cd -mavx512bw -mavx512dq"
            else
                log_error "AVX-512 requested but not detected on this CPU"
                exit 1
            fi
            ;;
        avx2)
            if [ "$detected_simd" = "avx512" ] || [ "$detected_simd" = "avx2" ]; then
                log_info "Using AVX2 as requested"
                echo "-mavx2"
            else
                log_warn "AVX2 requested but not detected, using baseline"
                echo ""
            fi
            ;;
        none)
            log_info "SIMD optimization disabled"
            echo ""
            ;;
        *)
            log_error "Unknown SIMD level: $simd_request"
            exit 1
            ;;
    esac
}

# ============================================================================
# HARDENING CONFIGURATION
# ============================================================================

# Get comprehensive hardening flags
get_hardening_flags() {
    local simd_flags="$1"

    # Core hardening flags (defense-in-depth)
    local base_flags=(
        # Stack protection
        "-fstack-protector-strong"
        "-fstack-clash-protection"

        # Format string protection
        "-Wformat"
        "-Wformat-security"
        "-Werror=format-security"

        # Buffer overflow detection
        "-D_FORTIFY_SOURCE=3"

        # Position Independent Execution
        "-fPIE"
        "-pie"

        # Control Flow Integrity
        "-fcf-protection=full"

        # Stack canaries
        "-fstack-protector-all"

        # Signed integer overflow detection
        "-ftrapv"

        # Relocation hardening
        "-Wl,-z,relro"
        "-Wl,-z,now"
        "-Wl,-z,noexecstack"
        "-Wl,-z,separate-code"

        # Optimization with security
        "-O2"
        "-g"

        # C++ specific assertions
        "-D_GLIBCXX_ASSERTIONS"

        # Pointer safety
        "-fno-strict-overflow"
        "-fno-delete-null-pointer-checks"

        # Treat warnings as errors for critical issues
        "-Werror=implicit-function-declaration"
        "-Werror=return-type"

        # Intel CET Shadow Stack (if available)
        "-mshstk"
    )

    # Add SIMD flags if specified
    if [ -n "$simd_flags" ]; then
        base_flags+=($simd_flags)
    fi

    # Output all flags
    printf '%s\n' "${base_flags[@]}"
}

# ============================================================================
# VERIFICATION FUNCTIONS
# ============================================================================

verify_binary_hardening() {
    local binary="$1"
    local binary_name=$(basename "$binary")

    if [ ! -f "$binary" ]; then
        log_fail "$binary_name: Binary not found"
        return 1
    fi

    echo ""
    log_info "Hardening verification: $binary_name"

    local all_ok=true

    # Check for PIE (Position Independent Executable)
    if readelf -h "$binary" 2>/dev/null | grep -q "Type.*DYN"; then
        log_success "PIE enabled"
    else
        log_fail "PIE not enabled"
        all_ok=false
    fi

    # Check for Stack Canary
    if readelf -s "$binary" 2>/dev/null | grep -q "__stack_chk_fail"; then
        log_success "Stack canary enabled"
    else
        log_fail "Stack canary not found"
        all_ok=false
    fi

    # Check for RELRO (Read-Only Relocations)
    if readelf -l "$binary" 2>/dev/null | grep -q "GNU_RELRO"; then
        log_success "RELRO enabled"
    else
        log_fail "RELRO not enabled"
        all_ok=false
    fi

    # Check for NX (No-Execute)
    if readelf -l "$binary" 2>/dev/null | grep "GNU_STACK" | grep -qv "RWE"; then
        log_success "NX (No-Execute) enabled"
    else
        log_fail "NX not enabled"
        all_ok=false
    fi

    # Check for FORTIFY_SOURCE
    if readelf -s "$binary" 2>/dev/null | grep -qE "__.*_chk"; then
        log_success "FORTIFY_SOURCE enabled"
    else
        log_fail "FORTIFY_SOURCE not detected"
        all_ok=false
    fi

    return $([ "$all_ok" = true ] && echo 0 || echo 1)
}

# ============================================================================
# BUILD FUNCTIONS
# ============================================================================

build_cockpit() {
    log_section "Building Hardened Cockpit"

    # Detect CPU and get SIMD flags
    local detected_simd=$(detect_simd_capabilities)
    local simd_flags=$(resolve_simd_flags "$SIMD_LEVEL" "$detected_simd")

    log_debug "SIMD flags: $simd_flags"

    # Get hardening flags
    local cflags="-Wno-error=format-security $(get_hardening_flags "$simd_flags" | tr '\n' ' ')"
    local cxxflags="$cflags"
    local ldflags="-Wl,-z,relro,-z,now,-z,noexecstack,-z,separate-code -pie"

    log_debug "CFLAGS: $cflags"

    # Create build directory
    mkdir -p "$BUILD_DIR"
    mkdir -p "$PREFIX"

    # Initialize submodule if needed
    if [ ! -f "$COCKPIT_DIR/configure.ac" ]; then
        log_info "Initializing Cockpit submodule..."
        cd "$SCRIPT_DIR"
        git submodule update --init --recursive
    fi

    # Build Cockpit
    cd "$COCKPIT_DIR"

    log_info "Configuring Cockpit with hardening flags..."

    # Run autogen if configure doesn't exist
    if [ ! -f "configure" ]; then
        log_info "Running autogen.sh..."
        ./autogen.sh 2>&1 | grep -v "^$" || true
    fi

    # Configure
    export CFLAGS="$cflags"
    export CXXFLAGS="$cxxflags"
    export LDFLAGS="$ldflags"

    log_info "Running configure..."
    ./configure \
        --prefix="$PREFIX" \
        --sysconfdir="$PREFIX/etc" \
        --localstatedir="$PREFIX/var" \
        --enable-strict \
        --disable-debug \
        2>&1 | tail -5

    # Build
    log_info "Building with $BUILD_JOBS parallel jobs..."
    make -j"$BUILD_JOBS" 2>&1 | tail -10

    log_success "Cockpit build complete"
}

build_sandbox() {
    log_section "Building Rust Sandbox"

    if [ ! -f "$SANDBOX_DIR/Cargo.toml" ]; then
        log_error "Sandbox Cargo.toml not found at $SANDBOX_DIR/Cargo.toml"
        return 1
    fi

    log_info "Building Rust sandbox binary..."
    cd "$SANDBOX_DIR"

    cargo build --release 2>&1 | tail -5

    if [ -f "target/release/cockpit-sandbox" ]; then
        log_success "Rust sandbox build complete"
        return 0
    else
        log_error "Sandbox build failed"
        return 1
    fi
}

install_binaries() {
    log_section "Installing Hardened Components"

    if [ "$EUID" -ne 0 ]; then
        log_error "Installation requires root privileges"
        exit 1
    fi

    # Install Cockpit binaries
    log_info "Installing Cockpit binaries..."
    cd "$COCKPIT_DIR"
    make install 2>&1 | tail -3

    # Create dedicated user/group
    log_info "Creating dedicated cockpit-hardened user..."
    if ! id -u cockpit-hardened >/dev/null 2>&1; then
        useradd -r -s /bin/false -d /nonexistent -M cockpit-hardened || log_warn "User already exists"
    fi

    # Set secure permissions
    log_info "Setting secure permissions..."
    chown -R root:root "$PREFIX" || true
    chmod -R o-rwx "$PREFIX" || true
    chmod 750 "$PREFIX/libexec/cockpit-ws" 2>/dev/null || true
    chmod 750 "$PREFIX/libexec/cockpit-tls" 2>/dev/null || true

    # Install sandbox binary
    if [ -f "$SANDBOX_DIR/target/release/cockpit-sandbox" ]; then
        log_info "Installing sandbox binary..."
        mkdir -p "$PREFIX/bin"
        cp "$SANDBOX_DIR/target/release/cockpit-sandbox" "$PREFIX/bin/"
        chmod 755 "$PREFIX/bin/cockpit-sandbox"
        log_success "Sandbox binary installed"
    fi

    # Install configuration files
    log_info "Installing hardened configurations..."
    mkdir -p "$PREFIX/etc/cockpit"
    cp "$SCRIPT_DIR/hardened_configs/cockpit.conf" "$PREFIX/etc/cockpit/" 2>/dev/null || log_warn "cockpit.conf not found"
    chmod 644 "$PREFIX/etc/cockpit/cockpit.conf" 2>/dev/null || true

    # Install monitoring
    if [ -f "$SCRIPT_DIR/monitoring/security_monitor.py" ]; then
        log_info "Installing monitoring system..."
        mkdir -p "$PREFIX/monitoring"
        cp "$SCRIPT_DIR/monitoring/security_monitor.py" "$PREFIX/monitoring/"
        chmod 755 "$PREFIX/monitoring/security_monitor.py"
        log_success "Monitoring system installed"
    fi

    log_success "All components installed to $PREFIX"
}

install_systemd_service() {
    if [ "$EUID" -ne 0 ]; then
        log_warn "Service installation requires root"
        return 1
    fi

    log_info "Installing systemd service..."

    cat > /etc/systemd/system/cockpit-hardened.service << 'EOF'
[Unit]
Description=CockLocker - Hardened Cockpit Web Interface
Documentation=https://github.com/SWORDIntel/COCKLOCKER
After=network.target

[Service]
Type=simple
User=cockpit-hardened
Group=cockpit-hardened
ExecStartPre=/opt/cockpit-hardened/security/firewall-rules.sh
ExecStart=/opt/cockpit-hardened/bin/cockpit-sandbox \
    --cockpit-path=/opt/cockpit-hardened \
    --bind-address=127.0.0.1 \
    --port=9090 \
    --xen-hardening
ExecStartPost=/opt/cockpit-hardened/monitoring/security_monitor.py
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cockpit-hardened

# Security hardening
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/cockpit-hardened/var

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || true
    log_success "Systemd service installed"
}

# ============================================================================
# VERIFICATION COMMAND
# ============================================================================

verify_hardening() {
    log_section "Security Hardening Verification"

    if [ ! -d "$PREFIX" ]; then
        log_error "Installation directory not found: $PREFIX"
        exit 1
    fi

    local verify_dir="$PREFIX/libexec"
    if [ ! -d "$verify_dir" ]; then
        verify_dir="$PREFIX/bin"
    fi

    if [ ! -d "$verify_dir" ]; then
        log_error "Binary directory not found"
        exit 1
    fi

    log_info "Verifying binaries in: $verify_dir"
    echo ""

    local all_passed=true
    local checked=0

    for binary in "$verify_dir"/*; do
        if [ -f "$binary" ] && file "$binary" | grep -q "ELF"; then
            verify_binary_hardening "$binary" || all_passed=false
            ((checked++))
        fi
    done

    echo ""
    if [ "$all_passed" = true ] && [ "$checked" -gt 0 ]; then
        log_success "All $checked binaries passed hardening verification"
        return 0
    else
        log_fail "Some binaries failed hardening verification"
        return 1
    fi
}

# ============================================================================
# HELP & USAGE
# ============================================================================

show_help() {
    head -n 55 "$0" | tail -n 50
}

show_version() {
    echo "CockLocker $COCKLOCKER_VERSION"
    echo "APT-Level Hardening Suite for Cockpit"
    echo ""
    echo "Repository: https://github.com/SWORDIntel/COCKLOCKER"
}

# ============================================================================
# MAIN COMMAND HANDLER
# ============================================================================

main() {
    local command="${1:-help}"

    case "$command" in
        detect-cpu|detect)
            detect_simd_capabilities
            ;;
        build)
            build_cockpit
            if command -v cargo &> /dev/null; then
                build_sandbox
            else
                log_warn "Rust/Cargo not found, skipping sandbox build"
            fi
            ;;
        install)
            install_binaries
            if [ "$EUID" -eq 0 ]; then
                install_systemd_service
            fi
            ;;
        kernel-integrate)
            log_section "Kernel Build Suite Integration"
            if [ -z "${KERNEL_BUILD_CONTEXT:-}" ]; then
                log_warn "Not running in kernel build context"
            fi
            # Delegate to kernel integration script
            if [ -f "$SCRIPT_DIR/kernel-integration/integrate.sh" ]; then
                bash "$SCRIPT_DIR/kernel-integration/integrate.sh"
            else
                log_error "Integration script not found"
                exit 1
            fi
            ;;
        verify)
            verify_hardening
            ;;
        test)
            log_section "Running Security Test Suite"
            if [ -f "$SCRIPT_DIR/fuzzing/fuzz_harness.py" ] && command -v python3 &> /dev/null; then
                python3 "$SCRIPT_DIR/fuzzing/fuzz_harness.py"
            else
                log_warn "Fuzzing not available"
            fi
            ;;
        version)
            show_version
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# ============================================================================
# ENTRY POINT
# ============================================================================

main "$@"
