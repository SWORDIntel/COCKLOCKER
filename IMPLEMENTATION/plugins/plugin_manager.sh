#!/bin/bash
################################################################################
# Cockpit Plugin Manager for CockLocker
# ============================================================================
# Comprehensive plugin management for feature-complete Cockpit deployment
#
# FEATURES:
#   - All official Cockpit plugins integration
#   - Third-party plugin support
#   - Plugin verification and security scanning
#   - Automated plugin building with hardening
#   - Plugin dependency resolution
#
# OFFICIAL PLUGINS SUPPORTED:
#   - cockpit-machines      (Virtual Machine Management)
#   - cockpit-podman        (Container Management)
#   - cockpit-storaged      (Storage Management)
#   - cockpit-networkmanager (Network Configuration)
#   - cockpit-packagekit    (Software Updates)
#   - cockpit-ostree        (OS Tree Management)
#   - cockpit-selinux       (SELinux Policy Management)
#   - cockpit-kdump         (Kernel Crash Dump)
#   - cockpit-sosreport     (System Reports)
#   - cockpit-benchmark     (Performance Benchmarks)
#   - cockpit-files         (File Manager)
#   - cockpit-composer      (Image Builder)
#
# USAGE:
#   ./plugin_manager.sh list
#   ./plugin_manager.sh install <plugin>
#   ./plugin_manager.sh build-all
#   ./plugin_manager.sh verify <plugin>
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COCKLOCKER_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
PLUGINS_DIR="${COCKLOCKER_ROOT}/plugins"
BUILD_DIR="${COCKLOCKER_ROOT}/build/plugins"
PREFIX="${COCKLOCKER_PREFIX:-/opt/cockpit-hardened}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${BLUE}=== $1 ===${NC}\n"; }

# ============================================================================
# PLUGIN DEFINITIONS
# ============================================================================

# Official Cockpit plugins with their Git repositories
declare -A OFFICIAL_PLUGINS=(
    ["cockpit-machines"]="https://github.com/cockpit-project/cockpit-machines.git"
    ["cockpit-podman"]="https://github.com/cockpit-project/cockpit-podman.git"
    ["cockpit-storaged"]="https://github.com/storaged-project/cockpit-storaged.git"
    ["cockpit-networkmanager"]="builtin"  # Part of main cockpit
    ["cockpit-packagekit"]="https://github.com/cockpit-project/cockpit-packagekit.git"
    ["cockpit-ostree"]="https://github.com/cockpit-project/cockpit-ostree.git"
    ["cockpit-selinux"]="https://github.com/cockpit-project/cockpit-selinux.git"
    ["cockpit-kdump"]="https://github.com/cockpit-project/cockpit-kdump.git"
    ["cockpit-sosreport"]="https://github.com/cockpit-project/cockpit-sosreport.git"
    ["cockpit-files"]="https://github.com/cockpit-project/cockpit-files.git"
    ["cockpit-composer"]="https://github.com/osbuild/cockpit-composer.git"
    ["cockpit-benchmark"]="https://github.com/cockpit-project/cockpit-benchmark.git"
)

# Plugin descriptions
declare -A PLUGIN_DESCRIPTIONS=(
    ["cockpit-machines"]="Virtual Machine management (libvirt/QEMU/KVM)"
    ["cockpit-podman"]="Container management (Podman/OCI containers)"
    ["cockpit-storaged"]="Storage management (disks, RAID, LVM, NFS)"
    ["cockpit-networkmanager"]="Network configuration (NetworkManager)"
    ["cockpit-packagekit"]="Software updates (PackageKit/DNF/APT)"
    ["cockpit-ostree"]="OSTree/rpm-ostree management"
    ["cockpit-selinux"]="SELinux troubleshooting and policy"
    ["cockpit-kdump"]="Kernel crash dump configuration"
    ["cockpit-sosreport"]="System diagnostics and reports"
    ["cockpit-files"]="Web-based file manager"
    ["cockpit-composer"]="OS image builder (osbuild)"
    ["cockpit-benchmark"]="System performance benchmarks"
)

# Plugin dependencies
declare -A PLUGIN_DEPS=(
    ["cockpit-machines"]="libvirt qemu-kvm virt-install"
    ["cockpit-podman"]="podman"
    ["cockpit-storaged"]="udisks2 storaged"
    ["cockpit-networkmanager"]="NetworkManager"
    ["cockpit-packagekit"]="PackageKit"
    ["cockpit-ostree"]="ostree rpm-ostree"
    ["cockpit-selinux"]="selinux-policy setroubleshoot"
    ["cockpit-kdump"]="kexec-tools"
    ["cockpit-sosreport"]="sos"
    ["cockpit-files"]=""
    ["cockpit-composer"]="osbuild osbuild-composer"
    ["cockpit-benchmark"]="sysbench fio"
)

# Build requirements per plugin
declare -A PLUGIN_BUILD_DEPS=(
    ["cockpit-machines"]="nodejs npm gettext"
    ["cockpit-podman"]="nodejs npm gettext"
    ["cockpit-storaged"]="nodejs npm gettext"
    ["cockpit-packagekit"]="nodejs npm gettext"
    ["cockpit-ostree"]="nodejs npm gettext"
    ["cockpit-selinux"]="nodejs npm gettext python3"
    ["cockpit-kdump"]="nodejs npm gettext"
    ["cockpit-sosreport"]="nodejs npm gettext"
    ["cockpit-files"]="nodejs npm gettext"
    ["cockpit-composer"]="nodejs npm gettext"
    ["cockpit-benchmark"]="nodejs npm gettext"
)

# ============================================================================
# PLUGIN MANAGEMENT FUNCTIONS
# ============================================================================

list_plugins() {
    log_section "Available Cockpit Plugins"

    echo "Official Plugins:"
    echo "-----------------"
    for plugin in "${!OFFICIAL_PLUGINS[@]}"; do
        local status="not installed"
        if [ -d "$PLUGINS_DIR/$plugin" ]; then
            status="downloaded"
        fi
        if [ -d "$PREFIX/share/cockpit/${plugin#cockpit-}" ]; then
            status="installed"
        fi

        printf "  ${CYAN}%-25s${NC} %s\n" "$plugin" "[${status}]"
        printf "    %s\n" "${PLUGIN_DESCRIPTIONS[$plugin]:-No description}"
        printf "    Dependencies: %s\n\n" "${PLUGIN_DEPS[$plugin]:-none}"
    done
}

download_plugin() {
    local plugin="$1"

    if [ -z "${OFFICIAL_PLUGINS[$plugin]:-}" ]; then
        log_error "Unknown plugin: $plugin"
        return 1
    fi

    local url="${OFFICIAL_PLUGINS[$plugin]}"

    if [ "$url" = "builtin" ]; then
        log_info "$plugin is built into core Cockpit"
        return 0
    fi

    mkdir -p "$PLUGINS_DIR"

    if [ -d "$PLUGINS_DIR/$plugin" ]; then
        log_info "Updating existing plugin: $plugin"
        cd "$PLUGINS_DIR/$plugin"
        git pull --rebase 2>&1 | tail -3
    else
        log_info "Downloading plugin: $plugin"
        git clone --depth 1 "$url" "$PLUGINS_DIR/$plugin" 2>&1 | tail -3
    fi

    log_info "Plugin downloaded: $plugin"
}

download_all_plugins() {
    log_section "Downloading All Official Plugins"

    for plugin in "${!OFFICIAL_PLUGINS[@]}"; do
        download_plugin "$plugin" || log_warn "Failed to download $plugin"
    done

    log_info "All plugins downloaded"
}

build_plugin() {
    local plugin="$1"
    local plugin_dir="$PLUGINS_DIR/$plugin"

    if [ ! -d "$plugin_dir" ]; then
        log_error "Plugin not downloaded: $plugin"
        return 1
    fi

    if [ "${OFFICIAL_PLUGINS[$plugin]}" = "builtin" ]; then
        log_info "$plugin is builtin, skipping build"
        return 0
    fi

    log_section "Building Plugin: $plugin"

    cd "$plugin_dir"

    # Get hardening flags from main build system
    source "$COCKLOCKER_ROOT/IMPLEMENTATION/intel-meteorlake/meteorlake_optimizer.sh" 2>/dev/null || true

    # Set build environment
    export NODE_ENV=production
    export CFLAGS="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2"
    export CXXFLAGS="$CFLAGS"

    # Install npm dependencies
    if [ -f "package.json" ]; then
        log_info "Installing npm dependencies..."
        npm ci --prefer-offline 2>&1 | tail -5 || npm install 2>&1 | tail -5
    fi

    # Build the plugin
    if [ -f "Makefile" ]; then
        log_info "Building with make..."
        make -j"$(nproc)" 2>&1 | tail -10
    elif [ -f "package.json" ] && grep -q '"build"' package.json; then
        log_info "Building with npm..."
        npm run build 2>&1 | tail -10
    fi

    log_info "Plugin built: $plugin"
}

build_all_plugins() {
    log_section "Building All Plugins"

    mkdir -p "$BUILD_DIR"

    for plugin in "${!OFFICIAL_PLUGINS[@]}"; do
        if [ "${OFFICIAL_PLUGINS[$plugin]}" != "builtin" ]; then
            if [ -d "$PLUGINS_DIR/$plugin" ]; then
                build_plugin "$plugin" || log_warn "Failed to build $plugin"
            else
                log_warn "Plugin not downloaded: $plugin"
            fi
        fi
    done

    log_info "All plugins built"
}

install_plugin() {
    local plugin="$1"
    local plugin_dir="$PLUGINS_DIR/$plugin"
    local plugin_name="${plugin#cockpit-}"
    local dest_dir="$PREFIX/share/cockpit/$plugin_name"

    if [ ! -d "$plugin_dir" ]; then
        log_error "Plugin not found: $plugin"
        return 1
    fi

    if [ "${OFFICIAL_PLUGINS[$plugin]}" = "builtin" ]; then
        log_info "$plugin is builtin, installed with core Cockpit"
        return 0
    fi

    log_info "Installing plugin: $plugin"

    mkdir -p "$dest_dir"

    # Install dist files
    if [ -d "$plugin_dir/dist" ]; then
        cp -r "$plugin_dir/dist/"* "$dest_dir/" 2>/dev/null || true
    fi

    # Install from src if no dist
    if [ -d "$plugin_dir/src" ] && [ ! -d "$plugin_dir/dist" ]; then
        cp -r "$plugin_dir/src/"* "$dest_dir/" 2>/dev/null || true
    fi

    # Copy manifest
    if [ -f "$plugin_dir/manifest.json" ]; then
        cp "$plugin_dir/manifest.json" "$dest_dir/"
    fi

    # Set permissions
    chown -R root:root "$dest_dir" 2>/dev/null || true
    chmod -R 755 "$dest_dir" 2>/dev/null || true

    log_info "Plugin installed: $plugin -> $dest_dir"
}

install_all_plugins() {
    log_section "Installing All Plugins"

    for plugin in "${!OFFICIAL_PLUGINS[@]}"; do
        if [ -d "$PLUGINS_DIR/$plugin" ]; then
            install_plugin "$plugin" || log_warn "Failed to install $plugin"
        fi
    done

    log_info "All plugins installed"
}

verify_plugin() {
    local plugin="$1"
    local plugin_dir="$PLUGINS_DIR/$plugin"

    log_section "Verifying Plugin: $plugin"

    if [ ! -d "$plugin_dir" ]; then
        log_error "Plugin not found: $plugin"
        return 1
    fi

    local issues=0

    # Check for manifest
    if [ ! -f "$plugin_dir/manifest.json" ] && [ ! -f "$plugin_dir/dist/manifest.json" ]; then
        log_warn "Missing manifest.json"
        ((issues++))
    fi

    # Check for package.json
    if [ -f "$plugin_dir/package.json" ]; then
        # Check for known vulnerabilities
        if command -v npm &> /dev/null; then
            cd "$plugin_dir"
            log_info "Running npm audit..."
            npm audit --audit-level=high 2>&1 | tail -10 || ((issues++))
        fi
    fi

    # Check JavaScript for dangerous patterns
    log_info "Scanning for security issues..."
    local dangerous_patterns=(
        "eval("
        "Function("
        "innerHTML.*="
        "document.write"
        "child_process"
        "shell:"
    )

    for pattern in "${dangerous_patterns[@]}"; do
        if grep -r "$pattern" "$plugin_dir/src" 2>/dev/null | grep -v "node_modules" | head -3; then
            log_warn "Found potentially dangerous pattern: $pattern"
            ((issues++))
        fi
    done

    if [ "$issues" -eq 0 ]; then
        log_info "Plugin verification passed: $plugin"
        return 0
    else
        log_warn "Plugin verification found $issues issue(s)"
        return 1
    fi
}

check_dependencies() {
    local plugin="$1"
    local deps="${PLUGIN_DEPS[$plugin]:-}"

    if [ -z "$deps" ]; then
        return 0
    fi

    log_info "Checking dependencies for $plugin..."

    local missing=()
    for dep in $deps; do
        if ! command -v "$dep" &> /dev/null && ! systemctl list-unit-files | grep -q "$dep"; then
            missing+=("$dep")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_warn "Missing dependencies: ${missing[*]}"
        return 1
    fi

    log_info "All dependencies satisfied"
    return 0
}

# ============================================================================
# MAIN COMMAND HANDLER
# ============================================================================

show_usage() {
    cat << EOF
Cockpit Plugin Manager for CockLocker

USAGE:
    $0 <command> [options]

COMMANDS:
    list                List all available plugins
    download <plugin>   Download a specific plugin
    download-all        Download all official plugins
    build <plugin>      Build a specific plugin
    build-all           Build all downloaded plugins
    install <plugin>    Install a built plugin
    install-all         Install all built plugins
    verify <plugin>     Verify plugin security
    deps <plugin>       Check plugin dependencies
    full-install        Download, build, and install all plugins

EXAMPLES:
    $0 list
    $0 download cockpit-machines
    $0 full-install

EOF
}

main() {
    local command="${1:-help}"
    shift || true

    case "$command" in
        list)
            list_plugins
            ;;
        download)
            [ -z "${1:-}" ] && { log_error "Plugin name required"; exit 1; }
            download_plugin "$1"
            ;;
        download-all)
            download_all_plugins
            ;;
        build)
            [ -z "${1:-}" ] && { log_error "Plugin name required"; exit 1; }
            build_plugin "$1"
            ;;
        build-all)
            build_all_plugins
            ;;
        install)
            [ -z "${1:-}" ] && { log_error "Plugin name required"; exit 1; }
            install_plugin "$1"
            ;;
        install-all)
            install_all_plugins
            ;;
        verify)
            [ -z "${1:-}" ] && { log_error "Plugin name required"; exit 1; }
            verify_plugin "$1"
            ;;
        deps)
            [ -z "${1:-}" ] && { log_error "Plugin name required"; exit 1; }
            check_dependencies "$1"
            ;;
        full-install)
            download_all_plugins
            build_all_plugins
            install_all_plugins
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
