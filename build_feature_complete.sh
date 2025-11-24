#!/bin/bash
################################################################################
# CockLocker Feature-Complete Build System
# ============================================================================
# Builds a complete, optimized Cockpit deployment for Intel Meteor Lake
#
# FEATURES:
#   - Full Cockpit with ALL official plugins
#   - Intel Meteor Lake NPU/AI power optimization
#   - Thread Director hybrid core optimization
#   - AVX2/AVX-VNNI/AMX acceleration support
#   - Security hardening (CFI, CET, RELRO, etc.)
#   - Rust sandbox with Landlock/seccomp
#   - Real-time threat monitoring
#
# TARGET: Intel Meteor Lake (and compatible 12th gen+)
#
# USAGE:
#   ./build_feature_complete.sh [--profile=<profile>] [--plugins=all|minimal]
#
# PROFILES:
#   meteorlake  - Optimized for Intel Meteor Lake (default)
#   alderlake   - Optimized for Intel Alder Lake (12th gen)
#   raptorlake  - Optimized for Intel Raptor Lake (13th/14th gen)
#   generic     - Generic x86_64 build
#
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_VERSION="2.0-meteorlake"
BUILD_DATE=$(date -u +"%Y-%m-%d")

# ============================================================================
# CONFIGURATION
# ============================================================================

# Default settings
PROFILE="${PROFILE:-meteorlake}"
PLUGINS="${PLUGINS:-all}"
PREFIX="${PREFIX:-/opt/cockpit-hardened}"
BUILD_DIR="${SCRIPT_DIR}/build"
BUILD_JOBS="${BUILD_JOBS:-$(nproc)}"
DEBUG="${DEBUG:-0}"

# Source directories
COCKPIT_SRC="${SCRIPT_DIR}/cockpit"
SANDBOX_SRC="${SCRIPT_DIR}/IMPLEMENTATION/sandbox"
PLUGINS_SRC="${SCRIPT_DIR}/plugins"
METEORLAKE_SRC="${SCRIPT_DIR}/IMPLEMENTATION/intel-meteorlake"

# ============================================================================
# COLORS & LOGGING
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_debug()   { [ "$DEBUG" -eq 1 ] && echo -e "${CYAN}[DEBUG]${NC} $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_fail()    { echo -e "${RED}✗${NC} $1"; }

log_section() {
    echo ""
    echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC}  $1"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

log_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                      ║${NC}"
    echo -e "${CYAN}║     ${GREEN}CockLocker Feature-Complete Build System${CYAN}                        ║${NC}"
    echo -e "${CYAN}║     ${NC}Version: ${BUILD_VERSION} | Profile: ${PROFILE}${CYAN}                            ║${NC}"
    echo -e "${CYAN}║     ${NC}Optimized for Intel Meteor Lake with AI Power${CYAN}                     ║${NC}"
    echo -e "${CYAN}║                                                                      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ============================================================================
# CPU DETECTION & OPTIMIZATION FLAGS
# ============================================================================

detect_cpu_features() {
    log_section "Detecting CPU Features"

    local cpu_vendor=$(grep -m1 "vendor_id" /proc/cpuinfo | cut -d: -f2 | tr -d ' ')
    local cpu_family=$(grep -m1 "cpu family" /proc/cpuinfo | cut -d: -f2 | tr -d ' ')
    local cpu_model=$(grep -m1 "model" /proc/cpuinfo | cut -d: -f2 | tr -d ' ')
    local cpu_name=$(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | sed 's/^[ \t]*//')
    local cpu_flags=$(grep -m1 "flags" /proc/cpuinfo | cut -d: -f2)

    echo "CPU Vendor:  $cpu_vendor"
    echo "CPU Family:  $cpu_family"
    echo "CPU Model:   $cpu_model"
    echo "CPU Name:    $cpu_name"
    echo ""

    # Feature detection
    local features=()

    # SIMD features
    [[ "$cpu_flags" =~ "avx512f" ]] && features+=("AVX-512")
    [[ "$cpu_flags" =~ "avx2" ]] && features+=("AVX2")
    [[ "$cpu_flags" =~ "avx_vnni" ]] && features+=("AVX-VNNI")
    [[ "$cpu_flags" =~ "amx_tile" ]] && features+=("AMX")

    # AI features
    [[ "$cpu_flags" =~ "avx_vnni_int8" ]] && features+=("AVX-VNNI-INT8")

    # Security features
    [[ "$cpu_flags" =~ "ibt" ]] && features+=("IBT")
    [[ "$cpu_flags" =~ "shstk" ]] && features+=("Shadow-Stack")

    # Hybrid detection
    if [ -f "/sys/devices/system/cpu/cpu0/topology/core_type" ]; then
        features+=("Hybrid-Architecture")
    fi

    echo "Detected Features: ${features[*]:-none}"
    echo ""

    # Auto-detect profile if not specified
    if [ "$PROFILE" = "auto" ]; then
        if [ "$cpu_model" -ge 170 ] && [ "$cpu_model" -le 175 ]; then
            PROFILE="meteorlake"
        elif [ "$cpu_model" -ge 183 ] && [ "$cpu_model" -le 187 ]; then
            PROFILE="raptorlake"
        elif [ "$cpu_model" -ge 151 ] && [ "$cpu_model" -le 155 ]; then
            PROFILE="alderlake"
        else
            PROFILE="generic"
        fi
        log_info "Auto-detected profile: $PROFILE"
    fi
}

get_optimization_flags() {
    local profile="$1"
    local flags=()

    # Base hardening flags (always applied)
    local hardening_flags=(
        "-fstack-protector-strong"
        "-fstack-clash-protection"
        "-D_FORTIFY_SOURCE=3"
        "-D_GLIBCXX_ASSERTIONS"
        "-fPIE"
        "-fcf-protection=full"
        "-Wformat"
        "-Wformat-security"
        "-Werror=format-security"
        "-fno-strict-overflow"
        "-fno-delete-null-pointer-checks"
    )

    # Profile-specific optimizations
    case "$profile" in
        meteorlake)
            flags=(
                # Meteor Lake architecture
                "-march=meteorlake"
                "-mtune=meteorlake"

                # SIMD optimizations
                "-mavx2"
                "-mavxvnni"
                "-mf16c"
                "-mbmi2"
                "-mlzcnt"
                "-mpopcnt"

                # Intel CET (Control-flow Enforcement)
                "-mshstk"
                "-fcf-protection=full"

                # AI-optimized floating point
                "-mfma"

                # Crypto acceleration
                "-maes"
                "-mpclmul"
                "-msha"

                # Optimization level
                "-O2"
                "-ftree-vectorize"
                "-fvect-cost-model=dynamic"
            )
            ;;

        raptorlake)
            flags=(
                "-march=raptorlake"
                "-mtune=raptorlake"
                "-mavx2"
                "-mavxvnni"
                "-mshstk"
                "-fcf-protection=full"
                "-maes"
                "-msha"
                "-O2"
                "-ftree-vectorize"
            )
            ;;

        alderlake)
            flags=(
                "-march=alderlake"
                "-mtune=alderlake"
                "-mavx2"
                "-mshstk"
                "-fcf-protection=full"
                "-maes"
                "-msha"
                "-O2"
                "-ftree-vectorize"
            )
            ;;

        generic|*)
            flags=(
                "-march=x86-64-v3"
                "-mtune=generic"
                "-mavx2"
                "-O2"
            )
            ;;
    esac

    # Combine all flags
    printf '%s\n' "${hardening_flags[@]}" "${flags[@]}"
}

get_linker_flags() {
    echo "-Wl,-z,relro"
    echo "-Wl,-z,now"
    echo "-Wl,-z,noexecstack"
    echo "-Wl,-z,separate-code"
    echo "-Wl,--as-needed"
    echo "-pie"
}

# ============================================================================
# BUILD FUNCTIONS
# ============================================================================

check_dependencies() {
    log_section "Checking Build Dependencies"

    local deps=(
        "git"
        "gcc"
        "g++"
        "make"
        "autoconf"
        "automake"
        "pkg-config"
        "gettext"
        "nodejs"
        "npm"
    )

    local optional_deps=(
        "cargo"     # For Rust sandbox
        "rustc"     # For Rust sandbox
        "python3"   # For monitoring
    )

    local missing=()
    local optional_missing=()

    for dep in "${deps[@]}"; do
        if command -v "$dep" &> /dev/null; then
            log_success "$dep found"
        else
            missing+=("$dep")
            log_fail "$dep not found"
        fi
    done

    for dep in "${optional_deps[@]}"; do
        if command -v "$dep" &> /dev/null; then
            log_success "$dep found (optional)"
        else
            optional_missing+=("$dep")
            log_warn "$dep not found (optional)"
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required dependencies: ${missing[*]}"
        log_info "Install with: apt install ${missing[*]}"
        exit 1
    fi

    if [ ${#optional_missing[@]} -gt 0 ]; then
        log_warn "Some optional features will be disabled"
    fi
}

init_submodules() {
    log_section "Initializing Git Submodules"

    cd "$SCRIPT_DIR"

    if [ ! -f "$COCKPIT_SRC/configure.ac" ]; then
        log_info "Initializing Cockpit submodule..."
        git submodule update --init --recursive 2>&1 | tail -5
        log_success "Submodule initialized"
    else
        log_info "Updating Cockpit submodule..."
        git submodule update --recursive 2>&1 | tail -3 || true
        log_success "Submodule updated"
    fi
}

build_cockpit_core() {
    log_section "Building Cockpit Core"

    cd "$COCKPIT_SRC"

    # Get optimization flags
    local cflags=$(get_optimization_flags "$PROFILE" | tr '\n' ' ')
    local ldflags=$(get_linker_flags | tr '\n' ' ')

    log_debug "CFLAGS: $cflags"
    log_debug "LDFLAGS: $ldflags"

    # Export build environment
    export CFLAGS="$cflags"
    export CXXFLAGS="$cflags"
    export LDFLAGS="$ldflags"
    export NODE_ENV="production"

    # Run autogen if needed
    if [ ! -f "configure" ]; then
        log_info "Running autogen.sh..."
        ./autogen.sh 2>&1 | grep -v "^$" | tail -5
    fi

    # Configure
    log_info "Configuring Cockpit..."
    ./configure \
        --prefix="$PREFIX" \
        --sysconfdir="$PREFIX/etc" \
        --localstatedir="$PREFIX/var" \
        --enable-strict \
        --with-cockpit-user=cockpit-ws \
        2>&1 | tail -10

    # Build
    log_info "Building Cockpit ($BUILD_JOBS jobs)..."
    make -j"$BUILD_JOBS" 2>&1 | tail -20

    log_success "Cockpit core built"
}

build_sandbox() {
    log_section "Building Rust Sandbox"

    if ! command -v cargo &> /dev/null; then
        log_warn "Rust not available, skipping sandbox build"
        return 0
    fi

    # Check for sandbox directory
    if [ ! -f "$SANDBOX_SRC/Cargo.toml" ]; then
        log_warn "Sandbox source not found at $SANDBOX_SRC"
        return 0
    fi

    cd "$SANDBOX_SRC"

    # Build with release optimizations
    log_info "Building Rust sandbox..."

    # Set Rust flags for Meteor Lake
    export RUSTFLAGS="-C target-cpu=native -C opt-level=3"

    cargo build --release 2>&1 | tail -10

    if [ -f "target/release/cockpit-sandbox" ]; then
        log_success "Sandbox built: target/release/cockpit-sandbox"
    else
        log_warn "Sandbox binary not found"
    fi
}

build_plugins() {
    log_section "Building Cockpit Plugins"

    local plugin_manager="$SCRIPT_DIR/IMPLEMENTATION/plugins/plugin_manager.sh"

    if [ ! -f "$plugin_manager" ]; then
        log_warn "Plugin manager not found"
        return 0
    fi

    chmod +x "$plugin_manager"

    case "$PLUGINS" in
        all)
            log_info "Building all official plugins..."
            "$plugin_manager" download-all 2>&1 | tail -20
            "$plugin_manager" build-all 2>&1 | tail -20
            ;;
        minimal)
            log_info "Building minimal plugin set..."
            for plugin in cockpit-machines cockpit-podman cockpit-storaged; do
                "$plugin_manager" download "$plugin" 2>&1 | tail -5
                "$plugin_manager" build "$plugin" 2>&1 | tail -5
            done
            ;;
        none)
            log_info "Skipping plugin builds"
            ;;
        *)
            log_warn "Unknown plugin set: $PLUGINS"
            ;;
    esac

    log_success "Plugin builds complete"
}

build_intel_components() {
    log_section "Building Intel Meteor Lake Components"

    # Make scripts executable
    chmod +x "$METEORLAKE_SRC"/*.sh 2>/dev/null || true
    chmod +x "$METEORLAKE_SRC"/*.py 2>/dev/null || true

    log_info "Intel Meteor Lake optimization module ready"
    log_info "Intel NPU manager ready"

    # Verify Python module syntax
    if command -v python3 &> /dev/null; then
        if python3 -m py_compile "$METEORLAKE_SRC/intel_npu_manager.py" 2>/dev/null; then
            log_success "Intel NPU manager validated"
        else
            log_warn "Intel NPU manager has syntax issues"
        fi
    fi
}

# ============================================================================
# INSTALLATION FUNCTIONS
# ============================================================================

install_all() {
    log_section "Installing CockLocker"

    if [ "$EUID" -ne 0 ]; then
        log_error "Installation requires root privileges"
        exit 1
    fi

    # Create directories
    mkdir -p "$PREFIX"/{bin,lib,libexec,share,etc,var}
    mkdir -p "$PREFIX"/etc/cockpit
    mkdir -p "$PREFIX"/share/cockpit
    mkdir -p "$PREFIX"/monitoring
    mkdir -p /var/log/cockpit-hardened

    # Install Cockpit core
    cd "$COCKPIT_SRC"
    make install 2>&1 | tail -10
    log_success "Cockpit core installed"

    # Install sandbox
    if [ -f "$SANDBOX_SRC/target/release/cockpit-sandbox" ]; then
        cp "$SANDBOX_SRC/target/release/cockpit-sandbox" "$PREFIX/bin/"
        chmod 755 "$PREFIX/bin/cockpit-sandbox"
        log_success "Sandbox installed"
    fi

    # Install Intel components
    mkdir -p "$PREFIX/intel"
    cp "$METEORLAKE_SRC"/*.sh "$PREFIX/intel/" 2>/dev/null || true
    cp "$METEORLAKE_SRC"/*.py "$PREFIX/intel/" 2>/dev/null || true
    chmod +x "$PREFIX/intel"/* 2>/dev/null || true
    log_success "Intel components installed"

    # Install hardened configs
    local configs_dir="$SCRIPT_DIR/IMPLEMENTATION/hardened_configs"
    if [ -d "$configs_dir" ]; then
        cp "$configs_dir"/* "$PREFIX/etc/cockpit/" 2>/dev/null || true
        log_success "Hardened configs installed"
    fi

    # Install monitoring
    local monitoring_dir="$SCRIPT_DIR/IMPLEMENTATION/monitoring"
    if [ -d "$monitoring_dir" ]; then
        cp "$monitoring_dir"/* "$PREFIX/monitoring/" 2>/dev/null || true
        chmod +x "$PREFIX/monitoring"/*.py 2>/dev/null || true
        log_success "Monitoring installed"
    fi

    # Install plugins
    local plugin_manager="$SCRIPT_DIR/IMPLEMENTATION/plugins/plugin_manager.sh"
    if [ -f "$plugin_manager" ]; then
        "$plugin_manager" install-all 2>&1 | tail -10
        log_success "Plugins installed"
    fi

    # Create user
    if ! id -u cockpit-ws &>/dev/null 2>&1; then
        useradd -r -s /sbin/nologin -d /nonexistent cockpit-ws
        log_success "Created cockpit-ws user"
    fi

    # Set permissions
    chown -R root:root "$PREFIX"
    chmod -R 755 "$PREFIX/share"
    chmod -R 750 "$PREFIX/libexec"

    log_success "Installation complete: $PREFIX"
}

install_systemd_services() {
    log_section "Installing systemd Services"

    if [ "$EUID" -ne 0 ]; then
        log_error "Service installation requires root"
        return 1
    fi

    # Main Cockpit service
    cat > /etc/systemd/system/cockpit-hardened.service << EOF
[Unit]
Description=CockLocker - Hardened Cockpit Web Console (Meteor Lake Optimized)
Documentation=https://github.com/SWORDIntel/COCKLOCKER
After=network.target

[Service]
Type=simple
ExecStartPre=$PREFIX/intel/meteorlake_optimizer.sh set_meteorlake_power_profile ai-performance
ExecStart=$PREFIX/libexec/cockpit-ws --port=9090 --address=127.0.0.1
ExecStartPost=$PREFIX/monitoring/security_monitor.py &
Restart=on-failure
RestartSec=10
User=cockpit-ws
Group=cockpit-ws

# Hardening
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$PREFIX/var /var/log/cockpit-hardened
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID

[Install]
WantedBy=multi-user.target
EOF

    # Socket activation
    cat > /etc/systemd/system/cockpit-hardened.socket << EOF
[Unit]
Description=CockLocker - Hardened Cockpit Web Console Socket

[Socket]
ListenStream=9090
BindIPv6Only=ipv6-only

[Install]
WantedBy=sockets.target
EOF

    # Intel NPU monitoring service
    cat > /etc/systemd/system/cockpit-npu-monitor.service << EOF
[Unit]
Description=Intel NPU Power Monitor for CockLocker
After=cockpit-hardened.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $PREFIX/intel/intel_npu_manager.py status --json
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "systemd services installed"

    log_info "Enable with: systemctl enable cockpit-hardened.socket"
    log_info "Start with:  systemctl start cockpit-hardened.socket"
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_build() {
    log_section "Verifying Build"

    local errors=0

    # Check binaries
    local binaries=(
        "$PREFIX/libexec/cockpit-ws"
        "$PREFIX/libexec/cockpit-session"
        "$PREFIX/bin/cockpit-bridge"
    )

    for binary in "${binaries[@]}"; do
        if [ -f "$binary" ]; then
            # Check PIE
            if readelf -h "$binary" 2>/dev/null | grep -q "Type.*DYN"; then
                log_success "$(basename "$binary"): PIE enabled"
            else
                log_fail "$(basename "$binary"): PIE disabled"
                ((errors++))
            fi

            # Check stack canary
            if readelf -s "$binary" 2>/dev/null | grep -q "__stack_chk_fail"; then
                log_success "$(basename "$binary"): Stack canary"
            else
                log_fail "$(basename "$binary"): No stack canary"
                ((errors++))
            fi

            # Check RELRO
            if readelf -l "$binary" 2>/dev/null | grep -q "GNU_RELRO"; then
                log_success "$(basename "$binary"): RELRO"
            else
                log_fail "$(basename "$binary"): No RELRO"
                ((errors++))
            fi
        else
            log_warn "Binary not found: $binary"
        fi
    done

    if [ "$errors" -eq 0 ]; then
        log_success "All security checks passed"
        return 0
    else
        log_fail "$errors security check(s) failed"
        return 1
    fi
}

# ============================================================================
# HELP & MAIN
# ============================================================================

show_help() {
    cat << EOF
CockLocker Feature-Complete Build System
=========================================

USAGE:
    $0 [OPTIONS] [COMMANDS]

OPTIONS:
    --profile=<profile>    CPU optimization profile
                           meteorlake (default), raptorlake, alderlake, generic
    --plugins=<set>        Plugin set: all (default), minimal, none
    --prefix=<path>        Installation prefix (default: /opt/cockpit-hardened)
    --jobs=<n>             Parallel build jobs (default: nproc)
    --debug                Enable debug output

COMMANDS:
    build           Build everything (default)
    install         Install to system (requires root)
    verify          Verify security hardening
    clean           Clean build artifacts
    help            Show this help

PROFILES:
    meteorlake      Intel Meteor Lake (14th gen mobile, NPU/AI)
    raptorlake      Intel Raptor Lake (13th/14th gen)
    alderlake       Intel Alder Lake (12th gen)
    generic         Generic x86-64 (broadest compatibility)

EXAMPLES:
    # Build for Meteor Lake with all plugins
    $0 build

    # Build minimal for Raptor Lake
    $0 --profile=raptorlake --plugins=minimal build

    # Full installation
    sudo $0 install

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --profile=*)
                PROFILE="${1#*=}"
                ;;
            --plugins=*)
                PLUGINS="${1#*=}"
                ;;
            --prefix=*)
                PREFIX="${1#*=}"
                ;;
            --jobs=*)
                BUILD_JOBS="${1#*=}"
                ;;
            --debug)
                DEBUG=1
                ;;
            build|install|verify|clean|help)
                COMMAND="$1"
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
}

main() {
    COMMAND="${COMMAND:-build}"

    log_banner

    case "$COMMAND" in
        build)
            detect_cpu_features
            check_dependencies
            init_submodules
            build_cockpit_core
            build_sandbox
            build_plugins
            build_intel_components
            log_success "Build complete!"
            log_info "Install with: sudo $0 install"
            ;;
        install)
            install_all
            install_systemd_services
            verify_build
            log_success "Installation complete!"
            log_info "Start with: sudo systemctl start cockpit-hardened"
            ;;
        verify)
            verify_build
            ;;
        clean)
            log_info "Cleaning build artifacts..."
            rm -rf "$BUILD_DIR" 2>/dev/null || true
            cd "$COCKPIT_SRC" && make clean 2>/dev/null || true
            cd "$SANDBOX_SRC" && cargo clean 2>/dev/null || true
            log_success "Clean complete"
            ;;
        help)
            show_help
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            show_help
            exit 1
            ;;
    esac
}

parse_args "$@"
main
