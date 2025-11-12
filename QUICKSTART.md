# CockLocker Quick Start Guide

**TL;DR:** Get hardened Cockpit running in 5 minutes.

---

## Option 1: Standalone Server (Recommended)

```bash
# Clone repository
git clone https://github.com/SWORDIntel/COCKLOCKER
cd COCKLOCKER

# Detect CPU and build
./cocklocker.sh detect-cpu
./cocklocker.sh build --with-simd=avx2

# Install and start
sudo ./cocklocker.sh install
sudo systemctl start cockpit-hardened

# Access
# https://localhost:9090
```

**Time:** ~20 minutes

---

## Option 2: Kernel Build Suite Integration

```bash
# In kernel build directory
cd /path/to/kernel/suite

# Add CockLocker
git submodule add https://github.com/SWORDIntel/COCKLOCKER ./cocklocker
git submodule update --init --recursive

# Integrate
KERNEL_BUILD_CONTEXT=1 ./cocklocker/cocklocker.sh kernel-integrate

# Verify
./cocklocker/cocklocker.sh verify
```

**Time:** ~40 minutes

---

## Option 3: Docker Container

```bash
# Build container
docker build -t cocklocker:latest .

# Run container
docker run -d \
  --name cockpit-hardened \
  -p 9090:9090 \
  -v /sys/kernel/debug:/sys/kernel/debug \
  cocklocker:latest

# Access
# https://localhost:9090
```

**Time:** ~10 minutes

---

## Verify Installation

```bash
./cocklocker.sh verify
```

All hardening features should be enabled:
- ✓ PIE
- ✓ Stack Canary
- ✓ RELRO
- ✓ NX
- ✓ FORTIFY_SOURCE

---

## Common Commands

```bash
# Detect CPU capabilities
./cocklocker.sh detect-cpu

# Build with specific SIMD
./cocklocker.sh build --with-simd=avx2      # Recommended
./cocklocker.sh build --with-simd=avx512    # High-performance
./cocklocker.sh build --with-simd=none      # Baseline

# Install to system
sudo ./cocklocker.sh install

# Verify security hardening
./cocklocker.sh verify

# Run security tests
./cocklocker.sh test

# View help
./cocklocker.sh help
```

---

## Default Access

- **URL:** https://localhost:9090
- **Username:** root (or your Linux user)
- **Password:** Your system password
- **Network:** localhost only (secure default)

---

## Logs & Monitoring

```bash
# Service logs
sudo journalctl -u cockpit-hardened -f

# Security alerts
sudo tail -f /var/log/cockpit-hardened/alerts.json

# Check firewall rules
sudo iptables -L -n | grep COCKLOCKER
```

---

## Next Steps

1. **Read Full Documentation:**
   - `ENTRY_POINT.md` - Master entry point reference
   - `INTEGRATION_GUIDE.md` - Advanced integration
   - `README.md` - Complete project overview

2. **Customize Configuration:**
   - Edit `/opt/cockpit-hardened/etc/cockpit/cockpit.conf`
   - Modify firewall rules in hardened_configs/
   - Adjust monitoring sensitivity

3. **Deploy to Production:**
   - Use `INTEGRATION_GUIDE.md` for Ansible/Puppet
   - Follow DESTDIR staging for packages
   - Integrate with CI/CD pipeline

---

## Troubleshooting

**Build fails with missing dependencies?**
```bash
# Install all required packages
sudo apt-get install build-essential git python3 nodejs \
  libsystemd-dev libpolkit-gobject-1-dev libssh-dev \
  libkrb5-dev libpam0g-dev libglib2.0-dev \
  libjson-glib-dev libpcp3-dev xmlto gettext
```

**Service won't start?**
```bash
# Check status
sudo systemctl status cockpit-hardened

# View detailed logs
sudo journalctl -u cockpit-hardened -n 50
```

**Can't access localhost:9090?**
```bash
# Verify service is running
sudo systemctl status cockpit-hardened

# Check port binding
sudo ss -tlnp | grep 9090

# Verify firewall rules
sudo iptables -L -n | grep 9090
```

---

## Architecture Overview

```
Layer 5: Network Isolation    [Firewall, rate limiting]
Layer 4: Threat Monitoring    [APT-level pattern detection]
Layer 3: Runtime Sandboxing   [seccomp-bpf, Landlock, capabilities]
Layer 2: Compilation Hardening [PIE, RELRO, CFI, stack canaries]
Layer 1: SIMD Optimization    [AVX2/AVX512 for performance]
```

---

For detailed information, see `ENTRY_POINT.md` and `INTEGRATION_GUIDE.md`.
