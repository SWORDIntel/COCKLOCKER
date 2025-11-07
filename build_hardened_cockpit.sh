#!/bin/bash
# CockLocker - Hardened Cockpit Build Script
# APT-level threat mitigation for Cockpit web management interface
# Modeled after ImageHarden project

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Comprehensive hardening flags modeled after ImageHarden
HARDENING_CFLAGS=(
    # Stack protection
    "-fstack-protector-strong"
    "-fstack-clash-protection"

    # Format string protections
    "-Wformat"
    "-Wformat-security"
    "-Werror=format-security"

    # Fortify source (detect buffer overflows)
    "-D_FORTIFY_SOURCE=3"

    # Position Independent Execution
    "-fPIE"
    "-pie"

    # Control Flow Integrity
    "-fcf-protection=full"

    # Stack canaries
    "-fstack-protector-all"

    # Trap on signed integer overflow
    "-ftrapv"

    # Additional hardening
    "-Wl,-z,relro"
    "-Wl,-z,now"
    "-Wl,-z,noexecstack"
    "-Wl,-z,separate-code"

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

    # Shadow stack (Intel CET)
    "-mshstk"
)

HARDENING_CXXFLAGS=(
    "${HARDENING_CFLAGS[@]}"
    "-D_GLIBCXX_ASSERTIONS"
)

HARDENING_LDFLAGS=(
    "-Wl,-z,relro"
    "-Wl,-z,now"
    "-Wl,-z,noexecstack"
    "-Wl,-z,separate-code"
    "-pie"
)

# Installation directories
PREFIX="/opt/cockpit-hardened"
COCKPIT_DIR="$(pwd)/cockpit"
BUILD_DIR="$(pwd)/build"
SANDBOX_DIR="$(pwd)/sandbox"

log_info "CockLocker - Hardened Cockpit Build System"
log_info "================================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root for installation"
    exit 1
fi

# Check for required dependencies
log_info "Checking dependencies..."
REQUIRED_DEPS=(
    "gcc"
    "g++"
    "clang"
    "make"
    "cmake"
    "autoconf"
    "automake"
    "libtool"
    "pkg-config"
    "git"
    "python3"
    "nodejs"
    "npm"
    "libsystemd-dev"
    "libpolkit-gobject-1-dev"
    "libssh-dev"
    "libkrb5-dev"
    "libpam0g-dev"
    "libglib2.0-dev"
    "libjson-glib-dev"
    "libpcp3-dev"
    "xmlto"
    "gettext"
    "glib-networking"
    "libgnutls28-dev"
)

MISSING_DEPS=()
for dep in "${REQUIRED_DEPS[@]}"; do
    if ! dpkg -l | grep -q "^ii.*$dep"; then
        MISSING_DEPS+=("$dep")
    fi
done

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    log_warn "Missing dependencies: ${MISSING_DEPS[*]}"
    log_info "Installing dependencies..."
    apt-get update
    apt-get install -y "${MISSING_DEPS[@]}"
fi

# Create build directory
log_info "Creating build directory..."
mkdir -p "$BUILD_DIR"
mkdir -p "$PREFIX"
mkdir -p "$SANDBOX_DIR"

# Initialize submodule if needed
if [ ! -f "$COCKPIT_DIR/configure.ac" ]; then
    log_info "Initializing Cockpit submodule..."
    git submodule init
    git submodule update
fi

cd "$COCKPIT_DIR"

# Build with hardening flags
log_info "Configuring Cockpit with hardening flags..."

# Export hardening flags
export CFLAGS="${HARDENING_CFLAGS[*]}"
export CXXFLAGS="${HARDENING_CXXFLAGS[*]}"
export LDFLAGS="${HARDENING_LDFLAGS[*]}"

# Run autogen if configure doesn't exist
if [ ! -f "configure" ]; then
    log_info "Running autogen..."
    ./autogen.sh
fi

# Configure with security options
log_info "Configuring build..."
./configure \
    --prefix="$PREFIX" \
    --sysconfdir="$PREFIX/etc" \
    --localstatedir="$PREFIX/var" \
    --enable-strict \
    --disable-debug \
    --with-cockpit-user=cockpit-hardened \
    --with-cockpit-group=cockpit-hardened \
    --with-selinux-config-type=targeted \
    CFLAGS="${CFLAGS}" \
    CXXFLAGS="${CXXFLAGS}" \
    LDFLAGS="${LDFLAGS}"

# Build
log_info "Building Cockpit with hardening flags..."
make -j$(nproc)

# Install
log_info "Installing hardened Cockpit to $PREFIX..."
make install

# Create dedicated user/group
log_info "Creating dedicated cockpit-hardened user..."
if ! id -u cockpit-hardened >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /nonexistent -M cockpit-hardened
fi

# Set secure permissions
log_info "Setting secure permissions..."
chown -R root:root "$PREFIX"
chmod -R o-rwx "$PREFIX"
chmod 750 "$PREFIX/libexec/cockpit-ws"
chmod 750 "$PREFIX/libexec/cockpit-tls"

# Verify hardening
log_info "Verifying security hardening..."
cd "$PREFIX/libexec"

for binary in cockpit-ws cockpit-tls cockpit-session; do
    if [ -f "$binary" ]; then
        log_info "Checking $binary..."

        # Check for PIE
        if readelf -h "$binary" | grep -q "DYN"; then
            log_info "  ✓ PIE enabled"
        else
            log_warn "  ✗ PIE not enabled"
        fi

        # Check for stack canary
        if readelf -s "$binary" | grep -q "__stack_chk_fail"; then
            log_info "  ✓ Stack canary enabled"
        else
            log_warn "  ✗ Stack canary not found"
        fi

        # Check for RELRO
        if readelf -l "$binary" | grep -q "GNU_RELRO"; then
            log_info "  ✓ RELRO enabled"
        else
            log_warn "  ✗ RELRO not enabled"
        fi

        # Check for NX
        if readelf -l "$binary" | grep -q "GNU_STACK" && ! readelf -l "$binary" | grep "GNU_STACK" | grep -q "RWE"; then
            log_info "  ✓ NX (No-Execute) enabled"
        else
            log_warn "  ✗ NX not enabled"
        fi

        # Check for FORTIFY_SOURCE
        if readelf -s "$binary" | grep -qE "__.*_chk"; then
            log_info "  ✓ FORTIFY_SOURCE detected"
        else
            log_warn "  ✗ FORTIFY_SOURCE not detected"
        fi
    fi
done

cd "$(dirname "$0")"

log_info "================================================"
log_info "Hardened Cockpit build complete!"
log_info "Installation directory: $PREFIX"
log_info "Next steps:"
log_info "  1. Review hardened configuration in hardened_configs/"
log_info "  2. Run the sandboxed launcher: ./cockpit_sandbox_launcher.sh"
log_info "  3. Configure monitoring: ./monitoring/setup_monitoring.sh"
log_info "================================================"
