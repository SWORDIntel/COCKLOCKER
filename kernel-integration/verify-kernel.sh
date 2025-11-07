#!/bin/bash
# CockLocker Kernel Verification Script
# Verify kernel has all required features for CockLocker

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0
WARNINGS=0

check_pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    ((PASSED++))
}

check_fail() {
    echo -e "  ${RED}✗${NC} $1"
    ((FAILED++))
}

check_warn() {
    echo -e "  ${YELLOW}⚠${NC} $1"
    ((WARNINGS++))
}

section() {
    echo ""
    echo -e "${BLUE}==[ $1 ]==${NC}"
}

echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  CockLocker Kernel Verification                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Kernel version
section "Kernel Version"
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

echo "Kernel: $KERNEL_VERSION"

if [ "$KERNEL_MAJOR" -gt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 13 ]); then
    check_pass "Kernel version $KERNEL_VERSION (>= 5.13 required for Landlock)"
else
    check_fail "Kernel version $KERNEL_VERSION (< 5.13, Landlock not supported)"
fi

# Landlock LSM
section "Landlock LSM"
if [ -f /sys/kernel/security/lsm ]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm)
    if echo "$LSM_LIST" | grep -q "landlock"; then
        check_pass "Landlock in active LSM list: $LSM_LIST"

        if [ -f /sys/kernel/security/landlock/version ]; then
            LANDLOCK_VER=$(cat /sys/kernel/security/landlock/version)
            check_pass "Landlock ABI version: $LANDLOCK_VER"
        fi
    else
        check_fail "Landlock not in LSM list: $LSM_LIST"
        check_warn "Add 'lsm=landlock,...' to kernel boot parameters"
    fi
else
    check_fail "/sys/kernel/security/lsm not found"
fi

# seccomp
section "seccomp Support"
if grep -q CONFIG_SECCOMP=y /boot/config-$(uname -r) 2>/dev/null; then
    check_pass "CONFIG_SECCOMP enabled"
else
    check_fail "CONFIG_SECCOMP not enabled in kernel config"
fi

if grep -q CONFIG_SECCOMP_FILTER=y /boot/config-$(uname -r) 2>/dev/null; then
    check_pass "CONFIG_SECCOMP_FILTER enabled"
else
    check_fail "CONFIG_SECCOMP_FILTER not enabled in kernel config"
fi

# Test seccomp at runtime
if perl -e 'syscall(317, 1, 0, 0, 0);' 2>/dev/null; then
    check_pass "seccomp runtime test passed"
else
    check_warn "seccomp runtime test failed (might be restricted)"
fi

# Namespaces
section "Namespace Support"
for ns in cgroup ipc mnt net pid user uts; do
    if [ -e "/proc/self/ns/$ns" ]; then
        check_pass "$ns namespace available"
    else
        check_fail "$ns namespace not available"
    fi
done

# Test user namespace creation
if unshare -U echo "test" &>/dev/null; then
    check_pass "User namespace creation works"
else
    check_warn "User namespace creation failed (might need kernel.unprivileged_userns_clone=1)"
fi

# Control groups
section "Control Groups (cgroups)"
for cgroup in cpu cpuacct devices freezer memory blkio; do
    if [ -d "/sys/fs/cgroup/$cgroup" ] || grep -q "$cgroup" /proc/cgroups 2>/dev/null; then
        check_pass "$cgroup cgroup available"
    else
        check_warn "$cgroup cgroup not found"
    fi
done

# Kernel hardening features
section "Kernel Hardening Features"

declare -A features=(
    ["CONFIG_STACKPROTECTOR_STRONG"]="Stack protector (strong)"
    ["CONFIG_STACKPROTECTOR"]="Stack protector"
    ["CONFIG_RANDOMIZE_BASE"]="KASLR (Address Space Layout Randomization)"
    ["CONFIG_PAGE_TABLE_ISOLATION"]="KPTI (Kernel Page Table Isolation)"
    ["CONFIG_RETPOLINE"]="Retpoline (Spectre v2 mitigation)"
    ["CONFIG_HARDENED_USERCOPY"]="Hardened usercopy"
    ["CONFIG_FORTIFY_SOURCE"]="FORTIFY_SOURCE"
    ["CONFIG_MODULE_SIG_FORCE"]="Module signature enforcement"
    ["CONFIG_SECURITY_LOCKDOWN_LSM"]="Kernel lockdown LSM"
    ["CONFIG_SECURITY_YAMA"]="Yama LSM (ptrace restrictions)"
    ["CONFIG_BPF_JIT_ALWAYS_ON"]="BPF JIT always on"
    ["CONFIG_BPF_UNPRIV_DEFAULT_OFF"]="Unprivileged BPF disabled by default"
)

CONFIG_FILE="/boot/config-$(uname -r)"
if [ -f "$CONFIG_FILE" ]; then
    for feature in "${!features[@]}"; do
        if grep -q "^$feature=y" "$CONFIG_FILE"; then
            check_pass "${features[$feature]}"
        elif grep -q "^# $feature is not set" "$CONFIG_FILE"; then
            check_warn "${features[$feature]} (not enabled)"
        else
            check_warn "${features[$feature]} (unknown)"
        fi
    done
else
    check_warn "Kernel config file not found at $CONFIG_FILE"
fi

# Boot parameters
section "Security Boot Parameters"
CMDLINE=$(cat /proc/cmdline)

if echo "$CMDLINE" | grep -q "lsm="; then
    LSM_PARAM=$(echo "$CMDLINE" | grep -o 'lsm=[^ ]*')
    if echo "$LSM_PARAM" | grep -q "landlock"; then
        check_pass "Landlock in boot parameters: $LSM_PARAM"
    else
        check_warn "Landlock not in boot LSM parameter: $LSM_PARAM"
    fi
else
    check_warn "No explicit LSM parameter in boot command line (using kernel default)"
fi

if echo "$CMDLINE" | grep -q "init_on_alloc=1"; then
    check_pass "init_on_alloc=1 (zero memory on allocation)"
else
    check_warn "init_on_alloc=1 not set"
fi

if echo "$CMDLINE" | grep -q "init_on_free=1"; then
    check_pass "init_on_free=1 (zero memory on free)"
else
    check_warn "init_on_free=1 not set"
fi

if echo "$CMDLINE" | grep -q "pti=on"; then
    check_pass "pti=on (Page Table Isolation)"
else
    check_warn "pti=on not explicitly set (may be enabled by default)"
fi

if echo "$CMDLINE" | grep -q "spectre_v2=on"; then
    check_pass "spectre_v2=on"
else
    check_warn "spectre_v2=on not set (may use auto)"
fi

# Network security
section "Network Security (netfilter)"
if [ -d /proc/sys/net/netfilter ]; then
    check_pass "netfilter support available"
else
    check_fail "netfilter not available"
fi

if command -v iptables &>/dev/null; then
    check_pass "iptables available"
else
    check_warn "iptables not found"
fi

if command -v ip6tables &>/dev/null; then
    check_pass "ip6tables available"
else
    check_warn "ip6tables not found"
fi

# Xen detection (if applicable)
section "Xen Hypervisor (optional)"
if [ -d /proc/xen ]; then
    check_pass "Xen detected"
    if [ -f /proc/xen/capabilities ]; then
        XEN_CAP=$(cat /proc/xen/capabilities)
        echo "  Capabilities: $XEN_CAP"
        if echo "$XEN_CAP" | grep -q "control_d"; then
            check_warn "Running in dom0 (domain 0) - extra security critical"
        fi
    fi
else
    check_warn "Xen not detected (not required unless running on Xen)"
fi

# System capabilities
section "System Capabilities"
if command -v capsh &>/dev/null; then
    check_pass "capsh (libcap) available"
else
    check_warn "capsh not found (install libcap2-bin)"
fi

# Rust toolchain
section "Build Dependencies"
if command -v cargo &>/dev/null; then
    CARGO_VER=$(cargo --version)
    check_pass "Rust/cargo available: $CARGO_VER"
else
    check_fail "Rust/cargo not found (required to build CockLocker sandbox)"
fi

if command -v gcc &>/dev/null; then
    GCC_VER=$(gcc --version | head -n1)
    check_pass "GCC available: $GCC_VER"
else
    check_fail "GCC not found"
fi

if command -v clang &>/dev/null; then
    CLANG_VER=$(clang --version | head -n1)
    check_pass "Clang available: $CLANG_VER"
else
    check_warn "Clang not found (recommended for additional hardening)"
fi

# Summary
section "Verification Summary"
echo ""
echo -e "${GREEN}Passed:${NC}   $PASSED"
echo -e "${YELLOW}Warnings:${NC} $WARNINGS"
echo -e "${RED}Failed:${NC}   $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ Kernel meets all critical requirements for CockLocker${NC}"
    EXIT_CODE=0
elif [ $FAILED -le 3 ]; then
    echo -e "${YELLOW}⚠ Kernel mostly compatible but has some issues${NC}"
    echo "  Review failed checks above and consider rebuilding kernel"
    EXIT_CODE=1
else
    echo -e "${RED}✗ Kernel does not meet CockLocker requirements${NC}"
    echo "  Please rebuild kernel with kernel-integration/kernel.config.fragment"
    EXIT_CODE=2
fi

echo ""
echo "For kernel configuration details, see:"
echo "  - kernel-integration/kernel.config.fragment"
echo "  - KERNEL_CONFIG.md"
echo ""

exit $EXIT_CODE
