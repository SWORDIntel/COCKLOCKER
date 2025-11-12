# CockLocker Integration Guide

**Purpose:** Comprehensive guide for integrating CockLocker with kernel build suites and custom deployment workflows.

**Target Audience:** Build system engineers, kernel maintainers, security teams.

---

## Table of Contents

1. [Quick Integration](#quick-integration)
2. [Module Structure](#module-structure)
3. [Kernel Build Suite Integration](#kernel-build-suite-integration)
4. [Custom Integration Workflows](#custom-integration-workflows)
5. [DESTDIR Staging Builds](#destdir-staging-builds)
6. [CI/CD Integration](#cicd-integration)
7. [Troubleshooting Integration](#troubleshooting-integration)

---

## Quick Integration

### Minimal Integration (3 steps)

```bash
# 1. Add CockLocker as submodule
git submodule add https://github.com/SWORDIntel/COCKLOCKER ./cocklocker

# 2. Initialize submodule
git submodule update --init --recursive

# 3. Run integration
KERNEL_BUILD_CONTEXT=1 ./cocklocker/cocklocker.sh kernel-integrate
```

---

## Module Structure

### Complete CockLocker Organization

```
cocklocker/
├── cocklocker.sh                 ← MASTER ENTRY POINT (primary interface)
├── build_hardened_cockpit.sh     (legacy, use cocklocker.sh)
├── README.md                      (project overview)
├── MISSION.md                     (threat model & guarantees)
├── KERNEL_CONFIG.md               (kernel requirements)
├── ENTRY_POINT.md                 (entry point documentation - READ THIS!)
├── INTEGRATION_GUIDE.md            (this file)
│
├── cockpit/                        (nested submodule)
│   ├── configure.ac
│   ├── src/
│   ├── tools/
│   └── ...
│
├── sandbox/                        (Rust sandbox implementation)
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── target/release/cockpit-sandbox
│
├── hardened_configs/               (Security configurations)
│   ├── cockpit.conf
│   ├── firewall-rules.sh
│   └── pam.d-cockpit
│
├── kernel-integration/             (Kernel suite integration)
│   ├── integrate.sh                (core integration logic)
│   ├── verify-kernel.sh            (kernel validation)
│   ├── kernel.config.fragment      (required kernel features)
│   └── INTEGRATION.md
│
├── monitoring/                     (APT-level threat detection)
│   └── security_monitor.py
│
└── fuzzing/                        (Security test suite)
    ├── fuzz_harness.py
    └── setup_fuzzing.sh
```

### Entry Point Design Philosophy

The **single entry point** (`cocklocker.sh`) provides:

- **Unified Interface**: One command for all operations
- **Auto-Detection**: CPU capabilities, kernel features
- **Flexibility**: Standalone, kernel-integrated, custom workflows
- **Documentation**: Every option is self-documenting
- **Reliability**: Comprehensive error handling

**Why not multiple scripts?**
- Reduces confusion about which script to use
- Maintains consistent interface across workflows
- Easier to maintain and update
- Better for CI/CD automation

---

## Kernel Build Suite Integration

### Architecture: Kernel Suite with Nested CockLocker

```
Your Kernel Build Suite/
├── Makefile                    (calls cocklocker.sh)
├── scripts/
│   └── build.sh                (orchestration script)
├── cocklocker/                 (CockLocker as submodule)
│   ├── cocklocker.sh           ← called by your build system
│   ├── kernel-integration/integrate.sh
│   └── ...
└── kernels/
    └── [kernel sources]
```

### Integration Pattern 1: Direct Make Integration

**In your Makefile:**

```makefile
.PHONY: cocklocker-build

cocklocker-build:
	export KERNEL_BUILD_CONTEXT=1 && \
	export KERNEL_BUILD_DIR=$(KERNEL_DIR) && \
	export KERNEL_VERSION=$(VERSION) && \
	export BUILD_JOBS=$(JOBS) && \
	./cocklocker/cocklocker.sh kernel-integrate

.PHONY: cocklocker-verify

cocklocker-verify:
	./cocklocker/cocklocker.sh verify
```

**Usage:**
```bash
make -j$(nproc) cocklocker-build
make cocklocker-verify
```

---

### Integration Pattern 2: Shell Script Orchestration

**In your build script (build.sh):**

```bash
#!/bin/bash

# Your build variables
KERNEL_BUILD_DIR="/usr/src/linux"
KERNEL_VERSION=$(uname -r)
BUILD_JOBS=$(nproc)

# Export for CockLocker
export KERNEL_BUILD_CONTEXT=1
export KERNEL_BUILD_DIR
export KERNEL_VERSION
export BUILD_JOBS

# Step 1: Build kernel components
echo "Building kernel..."
# [your kernel build steps]

# Step 2: Build and integrate CockLocker
echo "Integrating CockLocker..."
./cocklocker/cocklocker.sh kernel-integrate || exit 1

# Step 3: Verify
echo "Verifying hardening..."
./cocklocker/cocklocker.sh verify || exit 1

echo "Complete!"
```

**Usage:**
```bash
./build.sh
```

---

### Integration Pattern 3: Advanced DESTDIR Staging

**For packaging workflows (Debian, RPM, etc.):**

```bash
#!/bin/bash

# Staging directory
DESTDIR="/tmp/cockpit-hardened-pkg"
INSTALL_ROOT="/"

# Build into staging
mkdir -p "$DESTDIR"

export COCKLOCKER_PREFIX="$INSTALL_ROOT/opt/cockpit-hardened"
export KERNEL_BUILD_CONTEXT=1
export INSTALL_ROOT="$INSTALL_ROOT"

# Build
./cocklocker/cocklocker.sh build

# Install to DESTDIR (via integrate.sh)
DESTDIR="$DESTDIR" \
INSTALL_ROOT="$INSTALL_ROOT" \
./cocklocker/cocklocker.sh kernel-integrate

# Verify in staging
./cocklocker/cocklocker.sh verify

# Create package
cd "$DESTDIR"
tar czf /tmp/cockpit-hardened.tar.gz .
echo "Package created: /tmp/cockpit-hardened.tar.gz"
```

---

## Custom Integration Workflows

### Scenario 1: Standalone Server Deployment

**Goal:** Deploy hardened Cockpit on a single server.

```bash
#!/bin/bash
# deploy-cockpit.sh

set -e

# Clone or update repository
if [ ! -d "./cocklocker" ]; then
    git clone https://github.com/SWORDIntel/COCKLOCKER cocklocker
else
    cd cocklocker && git pull && cd ..
fi

# Run complete workflow
cd cocklocker

# Detect CPU
echo "Step 1: Detecting CPU capabilities..."
./cocklocker.sh detect-cpu

# Build (AVX2 recommended for compatibility)
echo "Step 2: Building hardened Cockpit..."
./cocklocker.sh build --with-simd=avx2

# Install (requires root)
echo "Step 3: Installing to system..."
sudo ./cocklocker.sh install

# Verify
echo "Step 4: Verifying security hardening..."
./cocklocker.sh verify

# Start
echo "Step 5: Starting service..."
sudo systemctl start cockpit-hardened
sudo systemctl enable cockpit-hardened

echo "✓ Deployment complete!"
echo "Access: https://localhost:9090"
```

---

### Scenario 2: Multi-System Deployment with Configuration Management

**Goal:** Deploy to multiple systems with Ansible/Puppet.

**Ansible Playbook:**

```yaml
---
- name: Deploy CockLocker
  hosts: web_servers
  become: yes
  vars:
    simd_level: "avx2"
    install_prefix: "/opt/cockpit-hardened"

  tasks:
    - name: Clone CockLocker repository
      git:
        repo: https://github.com/SWORDIntel/COCKLOCKER
        dest: /opt/src/cocklocker
        version: main

    - name: Detect CPU capabilities
      command: /opt/src/cocklocker/cocklocker.sh detect-cpu
      register: cpu_detection

    - name: Display CPU capabilities
      debug:
        msg: "{{ cpu_detection.stdout_lines }}"

    - name: Build hardened Cockpit
      command: |
        /opt/src/cocklocker/cocklocker.sh build \
        --with-simd={{ simd_level }}
      environment:
        BUILD_JOBS: "{{ ansible_processor_nprocs }}"

    - name: Install CockLocker
      command: /opt/src/cocklocker/cocklocker.sh install
      environment:
        COCKLOCKER_PREFIX: "{{ install_prefix }}"

    - name: Verify hardening
      command: /opt/src/cocklocker/cocklocker.sh verify
      register: verification_result

    - name: Display verification results
      debug:
        msg: "{{ verification_result.stdout_lines }}"

    - name: Start service
      systemd:
        name: cockpit-hardened
        state: started
        enabled: yes

    - name: Verify service is running
      systemd:
        name: cockpit-hardened
      register: service_status

    - name: Display service status
      debug:
        msg: "{{ service_status.status }}"
```

**Usage:**
```bash
ansible-playbook cocklocker-deploy.yaml -i inventory.ini
```

---

## DESTDIR Staging Builds

### Purpose

DESTDIR staging allows building and installing into a temporary directory, useful for:
- Package creation (Debian, RPM, etc.)
- Container image building
- Automated deployment
- Testing before system installation

### Implementation

```bash
#!/bin/bash
# staging-build.sh

set -e

# Configuration
DESTDIR="/tmp/cockpit-staging"
VERSION="1.0"

# Clean previous staging
rm -rf "$DESTDIR"
mkdir -p "$DESTDIR"

# Build CockLocker
cd /path/to/cocklocker

# Step 1: Detect and build
echo "Building for staging..."
./cocklocker.sh build --with-simd=avx2

# Step 2: Install to DESTDIR
echo "Installing to staging directory..."
export COCKLOCKER_PREFIX="/opt/cockpit-hardened"
export INSTALL_ROOT="$DESTDIR"

# Manual staging installation (since install requires root)
mkdir -p "$DESTDIR/opt/cockpit-hardened"
cp -r ./sandbox/target/release/cockpit-sandbox "$DESTDIR/opt/cockpit-hardened/bin/" 2>/dev/null || true
cp -r ./hardened_configs "$DESTDIR/opt/cockpit-hardened/" 2>/dev/null || true
cp -r ./monitoring "$DESTDIR/opt/cockpit-hardened/" 2>/dev/null || true

# Create systemd service in staging
mkdir -p "$DESTDIR/etc/systemd/system"
cat > "$DESTDIR/etc/systemd/system/cockpit-hardened.service" << 'EOF'
[Unit]
Description=CockLocker - Hardened Cockpit
After=network.target

[Service]
Type=simple
ExecStart=/opt/cockpit-hardened/bin/cockpit-sandbox
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Step 3: Verify in staging
echo "Verifying staged installation..."
COCKLOCKER_PREFIX="$DESTDIR/opt/cockpit-hardened" ./cocklocker.sh verify

# Step 4: Create package
echo "Creating tarball..."
cd "$DESTDIR"
tar czf /tmp/cockpit-hardened-${VERSION}.tar.gz .

echo "✓ Staging build complete: /tmp/cockpit-hardened-${VERSION}.tar.gz"
ls -lh /tmp/cockpit-hardened-${VERSION}.tar.gz
```

---

## CI/CD Integration

### GitHub Actions Workflow

**`.github/workflows/cocklocker-build.yaml`:**

```yaml
name: CockLocker Build & Verify

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v3
        with:
          submodules: recursive

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y \
            build-essential git python3 python3-dev \
            nodejs npm libsystemd-dev libpolkit-gobject-1-dev \
            libssh-dev libkrb5-dev libpam0g-dev \
            libglib2.0-dev libjson-glib-dev libpcp3-dev \
            xmlto gettext glib-networking libgnutls28-dev

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Detect CPU capabilities
        run: |
          ./cocklocker.sh detect-cpu

      - name: Build hardened Cockpit
        run: |
          ./cocklocker.sh build --with-simd=avx2

      - name: Run security tests
        run: |
          ./cocklocker.sh test

      - name: Verify hardening
        run: |
          ./cocklocker.sh verify

      - name: Create release artifact
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        run: |
          mkdir -p artifacts
          tar czf artifacts/cocklocker-build.tar.gz \
            sandbox/target/release/ \
            hardened_configs/ \
            monitoring/

      - name: Upload artifacts
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        uses: actions/upload-artifact@v3
        with:
          name: cocklocker-build
          path: artifacts/
```

---

### GitLab CI Integration

**`.gitlab-ci.yml`:**

```yaml
stages:
  - detect
  - build
  - verify
  - test

variables:
  SIMD_LEVEL: "avx2"

detect-cpu:
  stage: detect
  image: ubuntu:latest
  script:
    - apt-get update && apt-get install -y git
    - git submodule update --init --recursive
    - ./cocklocker.sh detect-cpu
  artifacts:
    reports:
      dotenv: cpu_capabilities.env

build-cockpit:
  stage: build
  image: ubuntu:latest
  before_script:
    - apt-get update
    - apt-get install -y build-essential git python3 nodejs npm \
        libsystemd-dev libpolkit-gobject-1-dev libssh-dev \
        libkrb5-dev libpam0g-dev libglib2.0-dev libjson-glib-dev \
        libpcp3-dev xmlto gettext glib-networking libgnutls28-dev
    - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    - source $HOME/.cargo/env
    - git submodule update --init --recursive
  script:
    - ./cocklocker.sh build --with-simd=$SIMD_LEVEL
  artifacts:
    paths:
      - build/
      - sandbox/target/release/

verify-hardening:
  stage: verify
  image: ubuntu:latest
  needs:
    - build-cockpit
  script:
    - apt-get update && apt-get install -y binutils
    - ./cocklocker.sh verify
  artifacts:
    reports:
      junit: verification-results.xml

security-tests:
  stage: test
  image: ubuntu:latest
  needs:
    - build-cockpit
  script:
    - apt-get update && apt-get install -y python3
    - ./cocklocker.sh test
```

---

## Troubleshooting Integration

### Issue: Submodule Not Initialized

**Error:**
```
Error: Cockpit submodule not found
```

**Solution:**
```bash
cd /path/to/cocklocker
git submodule update --init --recursive
```

---

### Issue: Kernel Build Context Not Detected

**Error:**
```
[WARN] Not running in kernel build context, assuming standalone
```

**Solution:**
```bash
# Set KERNEL_BUILD_CONTEXT before calling
export KERNEL_BUILD_CONTEXT=1
./cocklocker.sh kernel-integrate
```

---

### Issue: DESTDIR Installation Fails

**Error:**
```
Permission denied while creating staging directory
```

**Solution:**
```bash
# Ensure DESTDIR parent exists and is writable
mkdir -p "$DESTDIR"
chmod 755 "$DESTDIR"

# Or use /tmp for staging
DESTDIR="/tmp/cockpit-pkg" ./cocklocker.sh install
```

---

### Issue: Verification Shows Missing Hardening

**Error:**
```
✗ PIE not enabled
```

**Solution:**
```bash
# Ensure Cockpit was compiled with hardening flags
./cocklocker.sh build --with-simd=avx2

# Verify compilation environment
export CFLAGS="-fPIE -pie"
export LDFLAGS="-pie"
./cocklocker.sh build
```

---

## Summary: Integration Decision Tree

```
Do you need to:

├─ Deploy standalone server?
│  └─→ ./cocklocker.sh build && sudo ./cocklocker.sh install
│
├─ Integrate with kernel build suite?
│  └─→ KERNEL_BUILD_CONTEXT=1 ./cocklocker.sh kernel-integrate
│
├─ Create packages for distribution?
│  └─→ Use DESTDIR staging build workflow
│
├─ Deploy to multiple systems?
│  └─→ Use Ansible playbook or custom orchestration
│
└─ Integrate into CI/CD pipeline?
   └─→ GitHub Actions or GitLab CI workflow
```

---

**For detailed entry point documentation, see `ENTRY_POINT.md`**
