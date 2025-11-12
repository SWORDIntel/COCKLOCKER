# CockLocker Master Entry Point Documentation

**Version:** 1.0-enhanced
**Last Updated:** 2025-11-12
**Status:** Production Ready

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Commands Reference](#commands-reference)
4. [CPU SIMD Capabilities](#cpu-simd-capabilities)
5. [Build Workflows](#build-workflows)
6. [Installation & Deployment](#installation--deployment)
7. [Verification & Testing](#verification--testing)
8. [Advanced Configuration](#advanced-configuration)
9. [Troubleshooting](#troubleshooting)
10. [End-to-End Workflows](#end-to-end-workflows)

---

## Overview

`cocklocker.sh` is the **unified master entry point** for the CockLocker APT-level hardening suite. It orchestrates:

- **CPU capability detection** (AVX2/AVX512 SIMD)
- **Standalone hardened Cockpit builds**
- **Kernel build suite integration**
- **System installation and deployment**
- **Security hardening verification**
- **Threat monitoring and testing**

### Key Features

✓ **Intelligent SIMD Detection**: Automatically detects AVX2/AVX512 capabilities
✓ **Flexible Build Options**: Support for AVX2 (recommended), AVX512 (advanced), or baseline
✓ **Single Entry Point**: Replaces multiple build scripts with unified interface
✓ **Well-Documented**: Every command, option, and workflow is documented
✓ **Production-Ready**: Comprehensive error handling and verification
✓ **Kernel-Aware**: Seamless integration with kernel build suites

---

## Quick Start

### 1. Detect Your CPU Capabilities

```bash
./cocklocker.sh detect-cpu
```

**Output Example:**
```
CPU SIMD Capability Detection
═══════════════════════════════════════════════════════════
✓ AVX-512 Foundation (avx512f) detected
✓ AVX2 detected
✓ SSE4.2 detected

Recommendation: AVX-512 (best performance)

Capabilities Summary:
  AVX-512: yes
  AVX2:    yes
  SSE4.2:  yes

Build Recommendation: avx512
```

### 2. Build Hardened Cockpit (Recommended: AVX2)

```bash
# Automatic SIMD selection (best for compatibility)
./cocklocker.sh build --with-simd=auto

# Or explicit AVX2 (recommended)
./cocklocker.sh build --with-simd=avx2
```

### 3. Install to System

```bash
sudo ./cocklocker.sh install
```

### 4. Verify Security Hardening

```bash
./cocklocker.sh verify
```

### 5. Check Installation

```bash
curl -k https://localhost:9090
```

---

## Commands Reference

### `cocklocker.sh detect-cpu`

Detects CPU SIMD capabilities and recommends optimal build configuration.

**Usage:**
```bash
./cocklocker.sh detect-cpu
```

**Output Includes:**
- AVX-512 support status
- AVX2 support status
- SSE4.2 support status
- Build recommendation

**Exit Codes:**
- `0`: Detection successful
- `1`: Error during detection

---

### `cocklocker.sh build`

Builds hardened Cockpit with specified SIMD optimization level.

**Usage:**
```bash
./cocklocker.sh build [OPTIONS]

Options:
  --with-simd=auto     Use best available SIMD (default)
  --with-simd=avx2     Use AVX2 only (recommended for compatibility)
  --with-simd=avx512   Use AVX-512 (requires CPU support)
  --with-simd=none     Disable SIMD optimization
```

**Hardening Applied:**
- Stack protection (`-fstack-protector-strong`, `-fstack-clash-protection`)
- Format string protection (`-Wformat-security`)
- Buffer overflow detection (`-D_FORTIFY_SOURCE=3`)
- Position Independent Execution (`-fPIE`)
- Control Flow Integrity (`-fcf-protection=full`)
- Read-Only Relocations (`-Wl,-z,relro,-z,now`)
- No-Execute Stack (`-Wl,-z,noexecstack`)
- Separate Code Sections (`-Wl,-z,separate-code`)

**Build Stages:**
1. Initialize Cockpit submodule
2. Run `autogen.sh` (if needed)
3. Configure with hardening flags + SIMD optimization
4. Build Cockpit binaries
5. Build Rust sandbox (if Cargo available)

**Time:** ~15-30 minutes (depending on system)

**Exit Codes:**
- `0`: Build successful
- `1`: Build failed (check output)

---

### `cocklocker.sh install`

Installs hardened components to system directory (requires `root`).

**Usage:**
```bash
sudo ./cocklocker.sh install
```

**Installation Steps:**
1. Copy compiled Cockpit binaries to `/opt/cockpit-hardened`
2. Create `cockpit-hardened` system user/group
3. Set secure file permissions (no world-readable)
4. Install sandbox binary
5. Install hardened configuration files
6. Install monitoring system
7. Create systemd service

**Installed Files:**
```
/opt/cockpit-hardened/
├── bin/
│   └── cockpit-sandbox          # Rust sandbox binary
├── libexec/
│   ├── cockpit-ws               # Web service daemon
│   ├── cockpit-tls              # TLS handler
│   └── cockpit-session          # Session manager
├── etc/cockpit/
│   └── cockpit.conf             # Hardened configuration
├── monitoring/
│   └── security_monitor.py      # APT-level threat detection
└── var/                         # Runtime data directory
```

**Systemd Service:**
```bash
# Start service
sudo systemctl start cockpit-hardened

# Enable on boot
sudo systemctl enable cockpit-hardened

# View logs
sudo journalctl -u cockpit-hardened -f
```

---

### `cocklocker.sh verify`

Verifies that installed binaries have all security hardening features enabled.

**Usage:**
```bash
./cocklocker.sh verify
```

**Checks Performed (per binary):**
- ✓ PIE (Position Independent Executable)
- ✓ Stack Canary (`__stack_chk_fail`)
- ✓ RELRO (Read-Only Relocations)
- ✓ NX (No-Execute Stack)
- ✓ FORTIFY_SOURCE

**Example Output:**
```
Security Hardening Verification
═══════════════════════════════════════════════════════════
[INFO] Verifying binaries in: /opt/cockpit-hardened/libexec

[INFO] Hardening verification: cockpit-ws
✓ PIE enabled
✓ Stack canary enabled
✓ RELRO enabled
✓ NX (No-Execute) enabled
✓ FORTIFY_SOURCE enabled

✓ All 3 binaries passed hardening verification
```

---

### `cocklocker.sh kernel-integrate`

Integrates CockLocker as a submodule in kernel build suites.

**Usage:**
```bash
# Called by parent kernel build system
KERNEL_BUILD_CONTEXT=1 ./cocklocker.sh kernel-integrate

# Manual integration with environment
KERNEL_BUILD_CONTEXT=1 \
KERNEL_BUILD_DIR=/usr/src/linux \
KERNEL_VERSION=$(uname -r) \
./cocklocker.sh kernel-integrate
```

**Environment Variables:**
- `KERNEL_BUILD_CONTEXT=1` - Required (signals kernel build context)
- `KERNEL_BUILD_DIR` - Path to kernel source (default: `/usr/src/linux`)
- `KERNEL_VERSION` - Target kernel version (default: `uname -r`)
- `INSTALL_ROOT` - Installation prefix (default: `/`)
- `BUILD_JOBS` - Parallel jobs (default: CPU count)

**Integration Steps:**
1. Verify nested submodule structure
2. Validate kernel configuration
3. Build hardened Cockpit
4. Build Rust sandbox
5. Install configurations
6. Install monitoring
7. Create systemd service
8. Generate integration report

---

### `cocklocker.sh test`

Runs security test suite (fuzzing harness).

**Usage:**
```bash
./cocklocker.sh test
```

**Tests Performed:**
- HTTP endpoint fuzzing (login, terminal)
- Crash detection
- Command injection detection
- Resource monitoring

**Requirements:**
- Python 3
- AFL++ (optional, for advanced fuzzing)

---

### `cocklocker.sh verify`

Displays help message with full usage documentation.

**Usage:**
```bash
./cocklocker.sh help
./cocklocker.sh --help
./cocklocker.sh -h
```

---

### `cocklocker.sh version`

Displays version information.

**Usage:**
```bash
./cocklocker.sh version
```

---

## CPU SIMD Capabilities

### AVX2 (Recommended Default)

**Advantages:**
- ✓ Available on most modern CPUs (Intel: Haswell+ / AMD: Excavator+)
- ✓ Significant performance boost (2x-4x for vectorizable operations)
- ✓ Excellent compatibility across systems
- ✓ Lower power consumption than AVX-512

**Disadvantages:**
- Requires relatively recent CPU (2013+)

**When to Use:**
- **Production deployments** (best balance)
- **High-security systems** needing performance
- **When CPU is uncertain** (safe fallback)

**Build Command:**
```bash
./cocklocker.sh build --with-simd=avx2
```

### AVX-512 (Advanced / Unlocked)

**Advantages:**
- ✓ Best performance for vectorizable operations
- ✓ 512-bit registers enable extreme throughput
- ✓ Future-proof for emerging workloads

**Disadvantages:**
- ✗ Only on newer Intel/AMD systems
- ✗ Higher power consumption (can throttle)
- ✗ May have compatibility issues with some kernels

**When to Use:**
- **High-performance systems** (workstations, servers)
- **When you've verified AVX-512 support**
- **Non-critical security environments**

**Build Command:**
```bash
./cocklocker.sh build --with-simd=avx512
```

### Baseline (No SIMD)

**When to Use:**
- Older CPUs (pre-2010)
- Maximum compatibility needed
- Security over performance

**Build Command:**
```bash
./cocklocker.sh build --with-simd=none
```

### Auto (Recommended)

Automatically detects and uses best available option.

**Build Command:**
```bash
./cocklocker.sh build --with-simd=auto
```

---

## Build Workflows

### Workflow 1: Standalone Build (Recommended)

**Scenario:** Single hardened Cockpit installation on a server.

**Time:** ~20 minutes

**Steps:**
```bash
# 1. Detect CPU capabilities
./cocklocker.sh detect-cpu

# 2. Build with AVX2 (recommended)
./cocklocker.sh build --with-simd=avx2

# 3. Install to system
sudo ./cocklocker.sh install

# 4. Verify hardening
./cocklocker.sh verify

# 5. Start service
sudo systemctl start cockpit-hardened

# 6. Access interface
# https://localhost:9090
```

---

### Workflow 2: Kernel Build Suite Integration

**Scenario:** Integrate CockLocker as nested submodule in kernel build system.

**Time:** ~40 minutes (including kernel build)

**Steps:**
```bash
# 1. Add CockLocker as submodule to kernel suite
cd /path/to/kernel/suite
git submodule add https://github.com/SWORDIntel/COCKLOCKER ./cocklocker

# 2. Initialize submodule
git submodule update --init --recursive

# 3. Call integration script from kernel build
KERNEL_BUILD_CONTEXT=1 \
KERNEL_BUILD_DIR=/usr/src/linux \
KERNEL_VERSION=$(uname -r) \
./cocklocker/cocklocker.sh kernel-integrate

# 4. Verify installation
./cocklocker/cocklocker.sh verify

# 5. Start service
sudo systemctl start cockpit-hardened
```

---

### Workflow 3: Custom SIMD Configuration

**Scenario:** Build with specific SIMD level for compatibility testing.

**Steps:**
```bash
# AVX2 only (maximum compatibility)
./cocklocker.sh build --with-simd=avx2

# AVX-512 (maximum performance)
./cocklocker.sh build --with-simd=avx512

# Baseline (maximum compatibility)
./cocklocker.sh build --with-simd=none
```

---

### Workflow 4: Development & Testing

**Scenario:** Build, test, and iterate during development.

**Steps:**
```bash
# 1. Build with debugging enabled
DEBUG=1 ./cocklocker.sh build --with-simd=avx2

# 2. Run test suite
./cocklocker.sh test

# 3. Install to staging location
COCKLOCKER_PREFIX=/tmp/cockpit-test sudo ./cocklocker.sh install

# 4. Verify hardening of test build
COCKLOCKER_PREFIX=/tmp/cockpit-test ./cocklocker.sh verify
```

---

## Installation & Deployment

### System Requirements

**Minimum:**
- Linux kernel 5.13+ (Landlock LSM)
- 2 GB RAM
- 2 GB disk space
- 2 CPU cores

**Recommended:**
- Linux kernel 6.0+
- 4 GB RAM
- 5 GB disk space
- 4+ CPU cores
- AVX2-capable CPU

### Build Dependencies

**Required:**
```bash
sudo apt-get install -y \
  build-essential \
  git \
  python3 \
  python3-dev \
  nodejs npm \
  libsystemd-dev \
  libpolkit-gobject-1-dev \
  libssh-dev \
  libkrb5-dev \
  libpam0g-dev \
  libglib2.0-dev \
  libjson-glib-dev \
  libpcp3-dev \
  xmlto \
  gettext \
  glib-networking \
  libgnutls28-dev
```

**For Rust Sandbox (recommended):**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Installation Locations

**Production Installation:**
```
/opt/cockpit-hardened/       # Main installation directory
/etc/systemd/system/cockpit-hardened.service
/var/log/cockpit-hardened/   # Log directory
```

**Custom Installation:**
```bash
# Install to custom prefix
COCKLOCKER_PREFIX=/usr/local/cockpit-hardened \
sudo ./cocklocker.sh install
```

### Post-Installation Configuration

**1. Firewall Rules:**
```bash
# By default, only localhost (127.0.0.1) is allowed
# Whitelist additional IPs in /opt/cockpit-hardened/etc/cockpit/firewall-rules.sh
sudo vi /opt/cockpit-hardened/etc/cockpit/firewall-rules.sh
```

**2. SSL Certificates:**
```bash
# Generate self-signed certificate (pre-configured)
# Or provide your own in /opt/cockpit-hardened/etc/cockpit/

sudo cp /path/to/cert.pem /opt/cockpit-hardened/etc/cockpit/
sudo cp /path/to/key.pem /opt/cockpit-hardened/etc/cockpit/
sudo chmod 600 /opt/cockpit-hardened/etc/cockpit/key.pem
```

**3. Service Configuration:**
```bash
# View systemd service
sudo systemctl cat cockpit-hardened

# Edit service settings
sudo systemctl edit cockpit-hardened

# Apply changes
sudo systemctl daemon-reload
```

**4. Enable Threat Monitoring:**
```bash
# Start monitoring daemon
sudo systemctl start cockpit-hardened-monitor

# View alerts
sudo tail -f /var/log/cockpit-hardened/alerts.json
```

---

## Verification & Testing

### Security Verification

**Verify All Binaries:**
```bash
./cocklocker.sh verify
```

**Manual Verification:**
```bash
# Check PIE
readelf -h /opt/cockpit-hardened/libexec/cockpit-ws | grep Type

# Check Stack Canary
readelf -s /opt/cockpit-hardened/libexec/cockpit-ws | grep stack_chk

# Check RELRO
readelf -l /opt/cockpit-hardened/libexec/cockpit-ws | grep RELRO

# Check NX
readelf -l /opt/cockpit-hardened/libexec/cockpit-ws | grep GNU_STACK
```

### Functionality Testing

**Test Web Interface:**
```bash
# Access HTTPS interface (self-signed cert)
curl -k https://localhost:9090

# Test with browser
firefox https://localhost:9090
```

**Test System Limits:**
```bash
# Monitor system behavior under load
watch -n 1 'curl -k https://localhost:9090 2>/dev/null | head -c 100'
```

### Security Testing

**Run Fuzzing Suite:**
```bash
./cocklocker.sh test
```

**Manual Threat Testing:**
```bash
# Test brute force detection (should be blocked after 5 failures)
for i in {1..10}; do
  curl -k -u baduser:badpass https://localhost:9090 2>/dev/null
done

# Check if IP is blocked
sudo iptables -L -n | grep -i "cocklocker"
```

---

## Advanced Configuration

### Environment Variables

**Build Control:**
```bash
# Parallel build jobs
export BUILD_JOBS=8

# Enable verbose debugging
export DEBUG=1

# Force specific SIMD level
export SIMD_LEVEL=avx2
```

**Installation Control:**
```bash
# Custom installation prefix
export COCKLOCKER_PREFIX=/usr/local/cockpit-hardened

# Staged build (DESTDIR)
export INSTALL_ROOT=/tmp/staging

# Kernel integration context
export KERNEL_BUILD_CONTEXT=1
export KERNEL_BUILD_DIR=/usr/src/linux
export KERNEL_VERSION=6.1.0-generic
```

### Modifying Hardening Flags

**To customize hardening flags, edit `cocklocker.sh`:**
```bash
vim cocklocker.sh
# Locate get_hardening_flags() function
# Modify base_flags array as needed
```

**Available Compiler Flags:**
```bash
# Security
-fstack-protector-strong      # Stack canary
-fstack-clash-protection      # Protect against stack clashing
-D_FORTIFY_SOURCE=3           # Buffer overflow detection
-fcf-protection=full          # Control Flow Integrity
-ftrapv                       # Signed integer overflow detection

# Binary hardening
-fPIE                         # Position Independent Executable
-Wl,-z,relro                  # Read-Only Relocations
-Wl,-z,now                    # Immediate binding
-Wl,-z,noexecstack            # Non-executable stack
-Wl,-z,separate-code          # Separate code/data sections

# SIMD
-mavx2                        # AVX2 optimization
-mavx512f                     # AVX-512 Foundation
```

---

## Troubleshooting

### Build Failures

**Issue:** `autogen.sh` not found
```bash
# Solution: Update submodule
git submodule update --init --recursive
./cocklocker.sh build
```

**Issue:** Missing dependencies
```bash
# Install all required packages
sudo apt-get install build-essential git python3 nodejs libsystemd-dev \
  libpolkit-gobject-1-dev libssh-dev libkrb5-dev libpam0g-dev \
  libglib2.0-dev libjson-glib-dev libpcp3-dev xmlto gettext
```

**Issue:** Rust sandbox build fails
```bash
# Ensure Rust is installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Try again
./cocklocker.sh build
```

### Installation Failures

**Issue:** Permission denied (not root)
```bash
# Solution: Use sudo
sudo ./cocklocker.sh install
```

**Issue:** Disk space full
```bash
# Check available space
df -h /opt

# Clean build directory
rm -rf /home/user/COCKLOCKER/build
./cocklocker.sh build
```

### Runtime Issues

**Issue:** Service won't start
```bash
# Check service status
sudo systemctl status cockpit-hardened

# View detailed logs
sudo journalctl -u cockpit-hardened -n 50

# Manually start with debug output
sudo /opt/cockpit-hardened/bin/cockpit-sandbox --help
```

**Issue:** Connection refused on localhost:9090
```bash
# Check if service is running
sudo systemctl status cockpit-hardened

# Check firewall rules
sudo iptables -L -n | grep 9090

# Check port binding
sudo ss -tlnp | grep 9090
```

**Issue:** Threat detection too aggressive (false positives)
```bash
# View alerts
sudo tail -f /var/log/cockpit-hardened/alerts.json

# Adjust sensitivity in security_monitor.py
sudo vim /opt/cockpit-hardened/monitoring/security_monitor.py
```

### CPU/SIMD Issues

**Issue:** AVX2 requested but not detected
```bash
# Check actual CPU capabilities
grep flags /proc/cpuinfo | head -1

# Use baseline instead
./cocklocker.sh build --with-simd=none
```

**Issue:** AVX-512 causes throttling
```bash
# Use AVX2 instead (better power efficiency)
./cocklocker.sh build --with-simd=avx2

# Check CPU throttling
watch -n 1 'cat /proc/cpuinfo | grep MHz'
```

---

## End-to-End Workflows

### Complete Deployment Example

```bash
#!/bin/bash
# Complete end-to-end CockLocker deployment

set -e

# 1. Clone repository
git clone https://github.com/SWORDIntel/COCKLOCKER
cd COCKLOCKER

# 2. Detect CPU capabilities
echo "=== Detecting CPU capabilities ==="
./cocklocker.sh detect-cpu

# 3. Build with AVX2 (recommended)
echo "=== Building hardened Cockpit ==="
./cocklocker.sh build --with-simd=avx2

# 4. Install to system
echo "=== Installing to system ==="
sudo ./cocklocker.sh install

# 5. Verify security hardening
echo "=== Verifying security ==="
./cocklocker.sh verify

# 6. Start service
echo "=== Starting service ==="
sudo systemctl start cockpit-hardened
sudo systemctl enable cockpit-hardened

# 7. Display access information
echo ""
echo "✓ Deployment complete!"
echo ""
echo "Access hardened Cockpit at: https://localhost:9090"
echo "Username: root (or your Linux user)"
echo "Password: Your system password"
echo ""
echo "View logs:"
echo "  sudo journalctl -u cockpit-hardened -f"
echo ""
echo "Verify hardening:"
echo "  ./cocklocker.sh verify"
```

### Integration with Kernel Build Suite

```bash
#!/bin/bash
# Integrate CockLocker into kernel build workflow

cd /path/to/kernel/build/suite

# 1. Add as submodule
git submodule add https://github.com/SWORDIntel/COCKLOCKER ./cocklocker

# 2. In your main Makefile or build script:
# Add this line to integrate CockLocker

export KERNEL_BUILD_CONTEXT=1
export KERNEL_BUILD_DIR=$(pwd)
export KERNEL_VERSION=$(grep "^VERSION" Makefile | awk '{print $NF}')

./cocklocker/cocklocker.sh kernel-integrate

# 3. Verify installation
./cocklocker/cocklocker.sh verify
```

---

## Architecture & Design

### Entry Point Hierarchy

```
cocklocker.sh (MASTER ENTRY POINT)
├── detect-cpu
│   └── [CPU capability detection]
├── build
│   ├── detect_simd_capabilities()
│   ├── build_cockpit()
│   └── build_sandbox()
├── install
│   ├── install_binaries()
│   ├── install_systemd_service()
│   └── [Post-installation setup]
├── kernel-integrate
│   └── kernel-integration/integrate.sh
├── verify
│   └── verify_binary_hardening()
└── test
    └── fuzzing/fuzz_harness.py
```

### Hardening Layers

```
Layer 1: SIMD Optimization    [AVX2/AVX512 for performance]
         ↓
Layer 2: Compilation Hardening [PIE, RELRO, CFI, canaries]
         ↓
Layer 3: Runtime Sandboxing   [seccomp-bpf, Landlock, caps]
         ↓
Layer 4: Threat Monitoring    [APT-level pattern detection]
         ↓
Layer 5: Network Isolation    [Firewall, rate limiting]
```

---

## Support & Resources

- **Repository:** https://github.com/SWORDIntel/COCKLOCKER
- **Documentation:** See `README.md`, `MISSION.md`, `KERNEL_CONFIG.md`
- **Issues:** Report at https://github.com/SWORDIntel/COCKLOCKER/issues
- **Security:** Follow `MISSION.md` for threat model and guarantees

---

## Version History

**v1.0-enhanced** (2025-11-12)
- Unified master entry point
- AVX2/AVX512 detection and optimization
- Comprehensive documentation
- End-to-end workflow support
- Production-ready verification

---

**This document serves as the primary reference for using CockLocker. All features and workflows are fully tested and production-ready.**
