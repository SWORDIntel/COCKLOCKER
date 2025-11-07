# COCKLOCKER
**APT-Level Hardening Suite for Cockpit Web Management Interface**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Kernel: 5.13+](https://img.shields.io/badge/Kernel-5.13+-blue.svg)](KERNEL_CONFIG.md)
[![Security: APT-Level](https://img.shields.io/badge/Security-APT--Level-red.svg)](MISSION.md)
[![Integration: Kernel Suite Ready](https://img.shields.io/badge/Integration-Kernel%20Suite%20Ready-green.svg)](kernel-integration/INTEGRATION.md)

CockLocker provides comprehensive security hardening for Cockpit, implementing defense-in-depth measures against Advanced Persistent Threats (APTs). Inspired by the ImageHarden project, CockLocker combines compile-time hardening, kernel-level sandboxing, real-time threat detection, and Xen hypervisor-specific protections.

**🎯 Designed for dual deployment:**
1. **Standalone**: Deploy hardened Cockpit directly on your system
2. **Kernel Suite Integration**: Include as a nested submodule in kernel compilation projects

## Features

- 🛡️ **Compile-Time Hardening**: Comprehensive security flags (PIE, RELRO, stack protectors, CFI, FORTIFY_SOURCE, shadow stack)
- 🔒 **Kernel-Level Sandboxing**: seccomp-bpf, Linux namespaces, and Landlock LSM
- 👁️ **Real-Time Threat Detection**: APT-specific pattern matching and automated response
- 🚫 **Network Hardening**: Firewall rules, rate limiting, and IP whitelisting
- 🔐 **Authentication Hardening**: PAM configuration, account lockout, optional 2FA
- 🖥️ **Xen Hypervisor Support**: VM escape prevention and inter-VM attack mitigation
- 🔍 **Continuous Fuzzing**: AFL++ integration for vulnerability discovery
- 📊 **Security Monitoring**: Real-time log analysis and incident response
- ⚙️ **Kernel Suite Ready**: Nested submodule support with automated integration scripts
- 📦 **Build Integration**: Non-interactive builds, DESTDIR support, reproducible

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

## Quick Start - Standalone

### Prerequisites

- Debian-based Linux system (Ubuntu 22.04+, Debian 12+)
- Kernel 5.13+ with Landlock support - see [KERNEL_CONFIG.md](KERNEL_CONFIG.md)
- Rust toolchain (1.70+)
- Root/sudo access
- 2GB free disk space (for build)

### Installation

```bash
# Clone with nested submodules (includes Cockpit)
git clone --recurse-submodules https://github.com/SWORDIntel/COCKLOCKER.git
cd COCKLOCKER

# Verify kernel compatibility
sudo ./kernel-integration/verify-kernel.sh

# Build hardened Cockpit
sudo ./build_hardened_cockpit.sh

# Build Rust sandbox
cd sandbox
cargo build --release
cd ..

# Configure firewall (review and customize first!)
sudo ./hardened_configs/firewall-rules.sh

# Install and enable systemd service
sudo cp /opt/cockpit-hardened/etc/systemd/system/cockpit-hardened.service \
        /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cockpit-hardened
sudo systemctl start cockpit-hardened

# Start security monitoring (runs automatically with service)
sudo python3 /opt/cockpit-hardened/monitoring/security_monitor.py &
```

### Access

Navigate to `https://localhost:9090` in your browser.

**⚠️ Security Note**: By default, access is restricted to localhost only. Edit `hardened_configs/firewall-rules.sh` to allow remote access from trusted networks.

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

# Build and integrate CockLocker
echo "[*] Building CockLocker hardened Cockpit..."
bash cocklocker/kernel-integration/integrate.sh

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

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

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
