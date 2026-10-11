# COCKLOCKER
**Feature-Complete Cockpit Build with Intel Meteor Lake AI Optimization**

[![Kernel: 5.13+](https://img.shields.io/badge/Kernel-5.13+-blue.svg)](KERNEL_CONFIG.md)
[![Security: APT-Level](https://img.shields.io/badge/Security-APT--Level-red.svg)](MISSION.md)
[![Intel: Meteor Lake](https://img.shields.io/badge/Intel-Meteor%20Lake-0071c5.svg)](DOCUMENTATION/METEORLAKE_AI.md)
[![AI: NPU Support](https://img.shields.io/badge/AI-NPU%20Support-green.svg)](DOCUMENTATION/METEORLAKE_AI.md)
[![Build: 2.0](https://img.shields.io/badge/Build-v2.0%20Feature%20Complete-brightgreen.svg)](build_feature_complete.sh)

CockLocker provides a **feature-complete optimized build of Cockpit** with all official plugins, specifically optimized for **Intel Meteor Lake** processors with AI power management. It combines comprehensive security hardening with cutting-edge Intel hardware optimization including NPU acceleration, Thread Director integration, and RAPL power management.

> **📌 NEW: v2.0 Feature-Complete Build** - Use [`./build_feature_complete.sh`](build_feature_complete.sh) for Meteor Lake optimization
>
> Full Cockpit with all plugins, Intel NPU/AI power management, Thread Director optimization, and comprehensive security hardening.

**🎯 Designed for:**
1. **Intel Meteor Lake** - Full NPU and hybrid core optimization
2. **Feature-Complete Cockpit** - All official plugins included
3. **Production Deployment** - Security hardened for enterprise use
4. **Submodule Integration** - Use in larger kernel/system builds

## Features

### Intel Meteor Lake Optimization
- 🧠 **Intel NPU Support**: Neural Processing Unit detection and power management
- ⚡ **Thread Director**: Intelligent P-core/E-core workload scheduling
- 📊 **RAPL Integration**: Running Average Power Limit power management
- 🎯 **AVX-VNNI/AMX**: AI-optimized vector instructions for acceleration
- 🌡️ **Thermal Management**: Real-time temperature monitoring and throttling

### Complete Cockpit Stack
- 🖥️ **cockpit-machines**: Virtual machine management (libvirt/QEMU/KVM)
- 📦 **cockpit-podman**: Container management (Podman/OCI)
- 💾 **cockpit-storaged**: Storage management (LVM, RAID, NFS)
- 🌐 **cockpit-networkmanager**: Network configuration
- 📥 **cockpit-packagekit**: Software updates
- 🔧 **cockpit-selinux**: SELinux policy management
- 📈 **cockpit-benchmark**: Performance testing
- 📁 **cockpit-files**: Web-based file manager
- 🏗️ **cockpit-composer**: OS image builder

### Security Hardening
- 🛡️ **Compile-Time Hardening**: PIE, RELRO, CFI, FORTIFY_SOURCE, Intel CET shadow stack
- 🔒 **Kernel-Level Sandboxing**: seccomp-bpf, Landlock LSM, Linux namespaces
- 👁️ **Real-Time Threat Detection**: APT-specific pattern matching, automated IP blocking
- 🚫 **Network Hardening**: Firewall rules, rate limiting, TLS enforcement
- 🔐 **Authentication Hardening**: PAM hardening, account lockout, optional 2FA

### Monitoring & Management
- 📊 **Intel Monitor Plugin**: Custom Cockpit plugin for hardware monitoring
- 🌡️ **Power Profile Control**: Performance, balanced, and powersave modes
- 📈 **CPU Frequency Display**: Per-core P/E-core monitoring
- 🔍 **Security Dashboard**: Threat detection and incident response

---

## Table of Contents

- [Quick Start - Standalone](#quick-start---standalone)
- [Quick Start - Kernel Suite Integration](#quick-start---kernel-suite-integration)
- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [Security Features](#security-features)
- [Usage Modes](#usage-modes)
- [Performance Impact](#performance-impact)
- [Threat Model](#threat-model)
- [Testing](#testing)
- [Maintenance](#maintenance)
- [Comparison with ImageHarden](#comparison-with-imageharden)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start - Intel Meteor Lake

### Prerequisites

- Linux system (Ubuntu 22.04+, Debian 12+, Fedora 38+)
- Kernel 6.5+ for full NPU support (5.13+ minimum)
- Intel Meteor Lake, Raptor Lake, or Alder Lake processor
- Rust toolchain (1.70+) - for sandbox
- Node.js 18+ and npm - for plugins
- Root/sudo access for installation
- 4-5 GB free disk space

### Feature-Complete Installation

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/SWORDIntel/COCKLOCKER.git
cd COCKLOCKER

# ✨ FEATURE-COMPLETE BUILD FOR METEOR LAKE
#
# 1. Build everything (Cockpit + all plugins + Intel optimization)
./build_feature_complete.sh --profile=meteorlake --plugins=all

# 2. Install to system (requires root)
sudo ./build_feature_complete.sh install

# 3. Enable and start services
sudo systemctl enable --now cockpit-hardened.socket
sudo systemctl enable --now cockpit-security-monitor.service
```

**Time:** ~30 minutes (includes all plugins)

### Quick Build (Minimal)

```bash
# Faster build with essential plugins only
./build_feature_complete.sh --profile=meteorlake --plugins=minimal

# Or use legacy entry point
./cocklocker.sh build --with-simd=avx2
sudo ./cocklocker.sh install
```

**Time:** ~15 minutes

### CPU Profile Options

| Profile | Target CPU | Features |
|---------|-----------|----------|
| `meteorlake` | 14th Gen Core Ultra | NPU, AVX-VNNI, AMX, CET |
| `raptorlake` | 13th/14th Gen | AVX-VNNI, CET |
| `alderlake` | 12th Gen | Hybrid cores, CET |
| `generic` | Any x86-64 | AVX2, basic hardening |

### Access

Navigate to `https://localhost:9090` in your browser.

**⚠️ Security Note**: By default, access is restricted to localhost (127.0.0.1) only. This is intentional for security. To allow remote access from trusted networks, see [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md).

### For Detailed Documentation

- **Quick Start:** See [QUICKSTART.md](QUICKSTART.md)
- **Entry Point Reference:** See [ENTRY_POINT.md](ENTRY_POINT.md)
- **Integration Guide:** See [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)
- **Kernel Integration:** See [kernel-integration/INTEGRATION.md](kernel-integration/INTEGRATION.md)

---

## Quick Start - Kernel Suite Integration

**For maintainers of kernel compilation suites who want to include hardened Cockpit:**

### Overview

CockLocker is designed as a **nested submodule** for kernel build systems:

```
your-kernel-suite/          # Your kernel compilation suite
├── .git/
├── .gitmodules             # References CockLocker
├── linux/                  # Linux kernel source
├── cocklocker/             # CockLocker submodule
│   ├── .git/
│   ├── .gitmodules         # References Cockpit (nested)
│   └── cockpit/            # Cockpit submodule (nested)
└── build.sh                # Your kernel build script
```

### 1. Add as Nested Submodule

```bash
# In your kernel suite repository
git submodule add https://github.com/SWORDIntel/COCKLOCKER.git cocklocker

# Initialize nested submodules (CockLocker → Cockpit)
git submodule update --init --recursive

# Commit the addition
git add .gitmodules cocklocker
git commit -m "Add CockLocker for hardened Cockpit integration"
git push
```

### 2. Merge Kernel Configuration

CockLocker requires specific kernel features (Landlock, seccomp, namespaces). Merge the provided config fragment:

```bash
# In your kernel source directory
./scripts/kconfig/merge_config.sh .config \
    ../cocklocker/kernel-integration/kernel.config.fragment

# Apply and verify
make olddefconfig
make menuconfig  # Review security settings
```

**Alternative (manual)**:
```bash
cat ../cocklocker/kernel-integration/kernel.config.fragment >> .config
make olddefconfig
```

### 3. Integrate into Your Build Script

Add to your kernel suite's build script:

```bash
#!/bin/bash
# your-kernel-suite/build.sh

set -euo pipefail

# ... your kernel build steps ...

echo "[*] Building kernel..."
cd linux
make -j$(nproc)
make modules_install
make install
cd ..

# Set environment for CockLocker integration
export KERNEL_BUILD_CONTEXT=1              # Signal we're in kernel build
export KERNEL_BUILD_DIR="$(pwd)/linux"     # Path to kernel source
export KERNEL_VERSION="$(make -C linux kernelversion)"
export INSTALL_ROOT="/opt/custom-kernel"   # Your install prefix
export DESTDIR="/tmp/build-staging"        # For staged builds (optional)
export BUILD_JOBS=$(nproc)

# ✨ Use unified entry point for integration
echo "[*] Integrating CockLocker hardened Cockpit..."
./cocklocker/cocklocker.sh kernel-integrate || exit 1

# Verify hardening
echo "[*] Verifying security hardening..."
./cocklocker/cocklocker.sh verify

# ... package or install from $DESTDIR ...

echo "[+] Build complete!"
```

### 4. Build Everything

```bash
cd your-kernel-suite

# Build kernel + CockLocker
./build.sh

# Review integration report
cat cocklocker/kernel-integration/integration-report.txt
```

### 5. Deployment

If using `DESTDIR` for packaging:

```bash
# Option 1: Install directly
sudo cp -a /tmp/build-staging/* /

# Option 2: Create package (Debian example)
dpkg-deb --build /tmp/build-staging custom-kernel-suite_1.0_amd64.deb

# Option 3: Create initramfs
cp -a /tmp/build-staging/* /path/to/initramfs/
# ... build initramfs ...
```

**📚 Complete integration guide with CI/CD examples:** [kernel-integration/INTEGRATION.md](kernel-integration/INTEGRATION.md)

---

## Architecture

### Security Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    User / Administrator                      │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS (Port 9090)
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    Firewall Layer                            │
│  - IP Whitelisting (default: localhost only)                 │
│  - Rate Limiting (10 conn/min per IP)                        │
│  - DDoS Protection                                           │
│  - Automatic IP blocking on threats                          │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                 Security Monitor (Python)                    │
│  - Real-time Log Analysis                                    │
│  - APT Pattern Detection (14+ threat signatures)             │
│  - Brute Force Detection                                     │
│  - Automated Response & IP Blocking                          │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│              Sandbox Layer (Rust)                            │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ seccomp-bpf: Syscall Filtering (60+ allowed)          │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ Landlock LSM: Filesystem Restrictions                 │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ Namespaces: PID, Network, Mount Isolation             │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ Capability Dropping (minimal required set)            │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ Xen Hardening: VM escape prevention (optional)        │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│           Hardened Cockpit (Compiled with Security Flags)    │
│  - Stack Protectors (-fstack-protector-strong)               │
│  - PIE/RELRO (-fPIE, -Wl,-z,relro,-z,now)                   │
│  - Control Flow Integrity (-fcf-protection=full)             │
│  - FORTIFY_SOURCE=3                                          │
│  - Hardware Shadow Stack (-mshstk, Intel CET)                │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    System Resources                          │
│  - Restricted Filesystem Access (Landlock)                   │
│  - Controlled Network Access                                 │
│  - Isolated Process Tree (PID namespace)                     │
│  - Limited Syscalls (seccomp)                                │
└──────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **User Request** → Firewall validates source IP and rate limit
2. **Firewall** → Security Monitor logs and analyzes request
3. **Monitor** → Checks for APT patterns, triggers alerts if needed
4. **Sandbox** → Enforces syscall/filesystem restrictions
5. **Cockpit** → Processes request with hardened binary
6. **Response** ← Flows back through all layers

---

## Directory Structure

```
COCKLOCKER/
├── build_hardened_cockpit.sh   # Standalone build script
├── cockpit/                     # Cockpit submodule (nested)
├── sandbox/                     # Rust sandbox implementation
│   ├── Cargo.toml
│   └── src/main.rs
├── hardened_configs/            # Security configurations
│   ├── cockpit.conf             # Hardened Cockpit settings
│   ├── firewall-rules.sh        # iptables/ip6tables rules
│   └── pam.d-cockpit            # PAM authentication
├── monitoring/                  # Security monitoring
│   └── security_monitor.py      # Real-time threat detection
├── fuzzing/                     # Continuous security testing
│   ├── setup_fuzzing.sh
│   └── fuzz_harness.py
├── kernel-integration/          # Kernel suite integration ⭐
│   ├── integrate.sh             # Main integration script
│   ├── kernel.config.fragment   # Required kernel config
│   ├── verify-kernel.sh         # Kernel compatibility check
│   └── INTEGRATION.md           # Integration guide
├── MISSION.md                   # Threat model & defenses
├── KERNEL_CONFIG.md             # Kernel configuration guide
└── README.md                    # This file
```

---

## Security Features

### Compile-Time Hardening

All binaries compiled with comprehensive APT-level security flags:

| Flag | Purpose | Impact |
|------|---------|--------|
| `-fstack-protector-strong` | Stack buffer overflow detection | Prevents stack-based exploits |
| `-fstack-clash-protection` | Stack clash attack prevention | Mitigates VLA exploits |
| `-fcf-protection=full` | Control-flow integrity (Intel CET) | Prevents ROP/JOP attacks |
| `-fPIE -pie` | Position-independent executable | Enables ASLR |
| `-Wl,-z,relro,-z,now` | Full RELRO | Read-only GOT/PLT |
| `-Wl,-z,noexecstack` | Non-executable stack | Prevents shellcode execution |
| `-Wl,-z,separate-code` | Separate code pages | Improves ASLR |
| `-D_FORTIFY_SOURCE=3` | Enhanced buffer overflow detection | Runtime checks |
| `-mshstk` | Hardware shadow stack (Intel CET) | Hardware-enforced ROP prevention |
| `-ftrapv` | Trap on integer overflow | Prevents integer exploits |

**Verification**: All binaries automatically checked for PIE, stack canaries, RELRO, NX, and FORTIFY.

### Kernel-Level Sandboxing

**seccomp-bpf**: Strict syscall filtering
- ~60 allowed syscalls (minimal required set)
- Blocks: `ptrace`, `kexec_load`, `reboot`, `init_module`, etc.
- Fail-closed: Returns `EPERM` for unauthorized syscalls

**Linux Namespaces**: Process isolation
- **PID namespace**: Private process tree, prevents process discovery
- **Network namespace**: Controlled network access
- **Mount namespace**: Private filesystem view
- **User namespace**: UID/GID mapping for additional isolation

**Landlock LSM**: Path-based filesystem access control
- Cockpit can ONLY access:
  - `/opt/cockpit-hardened/` (read-only)
  - `/var/log/cockpit-hardened/` (write-only)
  - Configuration files (read-only)
- Everything else: DENIED

**Capability Dropping**: Minimal required capabilities
- Keeps: `CAP_NET_BIND_SERVICE`, `CAP_SETUID`, `CAP_SETGID`
- Drops: All other 35+ capabilities

### Real-Time Threat Detection

APT-level pattern matching for:

| Threat Type | Detection Method | Response |
|-------------|------------------|----------|
| Command Injection | Regex: `[;&|`$()]` | Block + IP ban |
| SQL Injection | Regex: `'|(--)|;|\*|xp_|sp_` | Block + IP ban |
| XSS | Regex: `<script|javascript:|onerror=` | Block + IP ban |
| Directory Traversal | Pattern: `../` | Block + IP ban |
| Privilege Escalation | Pattern: `sudo|pkexec|polkit` | Alert + block |
| Credential Harvesting | Pattern: `/etc/passwd`, `authorized_keys` | Alert + IP ban |
| APT Tools | Signatures: Metasploit, Cobalt Strike, Mimikatz | Critical alert + IP ban |
| Reverse Shells | Pattern: `nc -e`, `/dev/tcp`, `bash -i` | Block + IP ban |
| Brute Force | >5 failures in 5 min | Auto IP ban |
| DoS/Flood | >50 conn in 10 sec | Auto IP ban |

### Network Hardening

- **Default**: Localhost only (127.0.0.1, ::1)
- **Rate Limiting**: 10 connections/minute per IP
- **Automatic Blocking**: Malicious IPs banned via iptables
- **TLS Enforcement**: No plaintext allowed
- **Connection Limits**: Max 10 concurrent sessions

### Xen Hypervisor Hardening

When running on Xen (`--xen-hardening` flag):

- Detects dom0/domU environment automatically
- Hardens event channel operations
- Restricts grant table access
- Monitors for suspicious hypercalls
- Additional isolation for domU guests
- Prevents VM escape attempts

---

## Usage Modes

### Mode 1: Standalone Deployment

**Use case**: Direct installation on a single system.

```bash
sudo ./build_hardened_cockpit.sh
sudo systemctl enable cockpit-hardened
sudo systemctl start cockpit-hardened
```

**Installation path**: `/opt/cockpit-hardened/`

### Mode 2: Kernel Suite Integration

**Use case**: Include in custom kernel builds for distribution.

```bash
export KERNEL_BUILD_CONTEXT=1
export DESTDIR=/tmp/staging
bash kernel-integration/integrate.sh
# Package contents of /tmp/staging
```

**Integration path**: `${INSTALL_ROOT}/opt/cockpit-hardened/`

### Mode 3: Initramfs Integration

**Use case**: Include in early boot environment.

```bash
export DESTDIR=/usr/src/initramfs
bash kernel-integration/integrate.sh
# Build initramfs with CockLocker included
```

**See**: [kernel-integration/INTEGRATION.md](kernel-integration/INTEGRATION.md) for details.

### Mode 4: Containerized (TODO)

**Use case**: Run in Docker/Podman with additional isolation.

*Coming soon*

---

## Performance Impact

Security has minimal performance cost:

| Metric | Impact | Notes |
|--------|--------|-------|
| CPU Usage | +5-15% | Stack checks, CFI overhead |
| Memory Usage | +10-20 MB | Per Cockpit process |
| Request Latency | +10-50ms | Security checks per request |
| Throughput | -5-10% | Rate limiting, monitoring |

**Trade-off**: Acceptable for a management interface prioritizing security over raw performance.

---

## Threat Model

See [MISSION.md](MISSION.md) for comprehensive threat model, adversary capabilities, and defense mechanisms.

### What CockLocker PROTECTS Against ✅

- Memory corruption exploits (buffer overflows, use-after-free, etc.)
- Remote code execution via web interface
- Privilege escalation (local and remote)
- Brute force and credential stuffing attacks
- Command injection, SQL injection, XSS
- Directory traversal and path manipulation
- Known APT tools and techniques
- Zero-day exploits (via defense-in-depth)
- Denial of service attacks
- Credential harvesting
- Lateral movement post-compromise
- VM escape attempts (Xen environments)

### What CockLocker DOES NOT Protect Against ❌

- Social engineering attacks (phishing, etc.)
- Physical access to the system
- Supply chain compromise of CockLocker itself
- Insider threats with legitimate access
- Vulnerabilities in the Linux kernel (mitigated but not eliminated)
- Hardware vulnerabilities (Spectre, Meltdown, etc. - mitigations in kernel config)
- Attacks on other services on the same system

---

## Testing

### Kernel Compatibility Check

```bash
sudo ./kernel-integration/verify-kernel.sh
```

### Security Verification

```bash
# Binary hardening check
checksec --file=/opt/cockpit-hardened/bin/cockpit-sandbox
checksec --file=/opt/cockpit-hardened/libexec/cockpit-ws

# Runtime security status
sudo cat /proc/$(pidof cockpit-ws)/status | grep -E "Seccomp|NoNewPrivs"

# Landlock enforcement
cat /sys/kernel/security/lsm | grep landlock

# Review security logs
sudo tail -f /var/log/cockpit-hardened/security_monitor.log
sudo cat /var/log/cockpit-hardened/alerts.json
```

### Fuzzing

```bash
cd fuzzing
./setup_fuzzing.sh
./fuzz_cockpit.sh

# Review crashes
ls -la crashes/
```

### Integration Testing

```bash
# Build with DESTDIR
export DESTDIR=/tmp/test-install
bash kernel-integration/integrate.sh

# Verify all components installed
ls -la /tmp/test-install/opt/cockpit-hardened/

# Check integration report
cat kernel-integration/integration-report.txt
```

---

## Maintenance

### Regular Tasks

| Frequency | Task | Command |
|-----------|------|---------|
| **Daily** | Monitor security logs | `sudo tail -100 /var/log/cockpit-hardened/security_monitor.log` |
| **Weekly** | Review blocked IPs | `sudo cat /var/log/cockpit-hardened/incidents.log` |
| **Monthly** | Update threat patterns | Review `monitoring/security_monitor.py` |
| **Quarterly** | Security audit | External penetration test |
| **Annually** | Full review | Comprehensive security assessment |

### Updates

#### Update Cockpit Submodule

```bash
cd cocklocker
git submodule update --remote cockpit
git add cockpit
git commit -m "Update Cockpit to latest version"
git push
```

#### Rebuild After Update

```bash
sudo ./build_hardened_cockpit.sh
cd sandbox && cargo build --release && cd ..
sudo systemctl restart cockpit-hardened
```

#### Update in Kernel Suite

```bash
cd your-kernel-suite
git submodule update --remote cocklocker
git add cocklocker
git commit -m "Update CockLocker"
./build.sh
```

---

## Comparison with ImageHarden

| Feature | ImageHarden | CockLocker |
|---------|-------------|------------|
| **Target** | Image decoders (libpng, libjpeg, FFmpeg) | Cockpit web interface |
| **Compile Hardening** | ✅ (PIE, RELRO, CFI, etc.) | ✅ (Same + shadow stack) |
| **Sandboxing** | ✅ (seccomp, namespaces, Landlock) | ✅ (seccomp, namespaces, Landlock) |
| **Real-time Monitoring** | ❌ | ✅ (APT-level threat detection) |
| **Network Hardening** | ❌ | ✅ (Firewall, rate limiting) |
| **Authentication** | N/A | ✅ (PAM, 2FA support) |
| **Fuzzing** | ✅ (cargo-fuzz) | ✅ (AFL++) |
| **Xen Support** | ❌ | ✅ (VM escape prevention) |
| **Language** | Rust | Rust + Bash + Python |
| **Kernel Integration** | ❌ | ✅ (Nested submodule support) |
| **Use Case** | Media processing | System management |

**Shared Philosophy**: Defense-in-depth, fail-closed, APT-level hardening

---

## Documentation

- **[MISSION.md](MISSION.md)**: Complete threat model, defense mechanisms, security guarantees
- **[KERNEL_CONFIG.md](KERNEL_CONFIG.md)**: Kernel configuration requirements and verification
- **[kernel-integration/INTEGRATION.md](kernel-integration/INTEGRATION.md)**: Comprehensive integration guide for kernel suites
- **[kernel-integration/integration-report.txt](kernel-integration/integration-report.txt)**: Build report (generated after build)

---

## Contributing

Contributions are welcome! Security-focused contributions especially appreciated.

### Guidelines

1. **Maintain Security**: All changes must maintain or improve security posture
2. **Code Review**: All code undergoes security review
3. **Documentation**: Update docs for any changes
4. **Testing**: Add tests for new features
5. **Compatibility**: Ensure kernel suite integration still works

### Reporting Security Issues

**🚨 Do NOT open public issues for security vulnerabilities**

Email: security@example.com

We follow responsible disclosure and will credit researchers.

---

## License

This project is licensed under the **SWORD Restricted Source Licence v1.0 (SRSL-1.0)**. Personal and non-commercial use is permitted under its terms; commercial exploitation requires a separate written agreement. See [LICENSE](LICENSE).

## Acknowledgments

- **ImageHarden Project**: Inspiration for APT-level hardening approach
- **Cockpit Project**: Excellent web-based management interface
- **Rust Community**: Outstanding sandboxing libraries (seccompiler, landlock, nix)
- **Linux Kernel Community**: Security features (Landlock, seccomp, namespaces)

---

## Support

### Getting Help

- 📖 Read the docs: [MISSION.md](MISSION.md), [KERNEL_CONFIG.md](KERNEL_CONFIG.md), [INTEGRATION.md](kernel-integration/INTEGRATION.md)
- 🐛 Open an issue: https://github.com/SWORDIntel/COCKLOCKER/issues
- 💬 Discussions: https://github.com/SWORDIntel/COCKLOCKER/discussions

### For Kernel Suite Maintainers

- Review [kernel-integration/INTEGRATION.md](kernel-integration/INTEGRATION.md)
- Check [kernel-integration/integration-report.txt](kernel-integration/integration-report.txt) after builds
- Run [kernel-integration/verify-kernel.sh](kernel-integration/verify-kernel.sh) for compatibility
- Set `KERNEL_BUILD_CONTEXT=1` for automated builds

---

## Roadmap

- [ ] SELinux/AppArmor policy modules
- [ ] Containerized deployment (Docker/Podman)
- [ ] Automated penetration testing suite
- [ ] Web UI for security monitoring
- [ ] Integration with SIEM systems
- [ ] Hardware security module (HSM) support
- [ ] Additional hypervisor support (KVM, VMware)

---

**⚡ CockLocker: APT-Level Security for Cockpit**

**Security is not a product, but a process.** Regular updates, monitoring, and vigilance are essential.

**Remember**: The best security is layered security. CockLocker provides the tools—proper deployment, configuration, and maintenance are your responsibility.
