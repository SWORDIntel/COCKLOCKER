# CockLocker Kernel Integration Guide

This guide explains how to integrate CockLocker as a submodule in a kernel compilation suite.

## Overview

CockLocker is designed to be integrated as a **nested submodule** in kernel build systems. The structure looks like:

```
your-kernel-suite/          # Your kernel compilation suite
├── .git/
├── .gitmodules             # References CockLocker
├── kernel-sources/         # Linux kernel source
├── cocklocker/             # CockLocker submodule (this project)
│   ├── .git/
│   ├── .gitmodules         # References Cockpit
│   └── cockpit/            # Nested Cockpit submodule
└── build.sh                # Your kernel build script
```

## Quick Integration

### 1. Add CockLocker as Submodule

In your kernel suite repository:

```bash
# Add CockLocker
git submodule add https://github.com/yourusername/COCKLOCKER.git cocklocker

# Initialize nested submodules (Cockpit)
git submodule update --init --recursive

# Commit
git add .gitmodules cocklocker
git commit -m "Add CockLocker as submodule for hardened Cockpit"
```

### 2. Integrate Kernel Configuration

Merge CockLocker's kernel requirements into your kernel config:

```bash
cd kernel-sources

# Using kernel's merge_config.sh
./scripts/kconfig/merge_config.sh .config \
    ../cocklocker/kernel-integration/kernel.config.fragment

# Or manually append
cat ../cocklocker/kernel-integration/kernel.config.fragment >> .config
make olddefconfig
```

### 3. Add to Your Build Script

In your kernel suite's build script:

```bash
#!/bin/bash
# your-kernel-suite/build.sh

# ... your kernel build steps ...

# Build CockLocker components
export KERNEL_BUILD_CONTEXT=1
export KERNEL_BUILD_DIR="$(pwd)/kernel-sources"
export KERNEL_VERSION="$(make -C kernel-sources kernelversion)"
export INSTALL_ROOT="/opt/custom-kernel"  # Or your install path
export BUILD_JOBS=$(nproc)

# Run CockLocker integration
bash cocklocker/kernel-integration/integrate.sh

# ... continue with your build ...
```

### 4. Build Everything

```bash
cd your-kernel-suite
./build.sh
```

## Advanced Integration

### Using DESTDIR for Staged Builds

If you're building packages or creating a custom initramfs:

```bash
export DESTDIR="/tmp/kernel-build-staging"
bash cocklocker/kernel-integration/integrate.sh

# Now package contents of $DESTDIR
# Or copy to initramfs
cp -a $DESTDIR/* /path/to/initramfs/
```

### Initramfs Integration

To include CockLocker in your initramfs:

```bash
# Build with DESTDIR
export DESTDIR="/tmp/cocklocker-staging"
bash cocklocker/kernel-integration/integrate.sh

# Copy to initramfs tree
cp -a /tmp/cocklocker-staging/* /usr/src/initramfs/

# Create initramfs
cd /usr/src/initramfs
find . | cpio -H newc -o | gzip > /boot/initramfs-custom.img
```

Add to initramfs init script:

```bash
#!/bin/sh
# /usr/src/initramfs/init

# Mount essential filesystems
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

# Start CockLocker monitoring early
/opt/cockpit-hardened/monitoring/security_monitor.py &

# ... rest of init ...
```

### Makefile Integration

If your kernel suite uses Make:

```makefile
# Makefile snippet

.PHONY: cocklocker
cocklocker:
	@echo "Building CockLocker..."
	export KERNEL_BUILD_CONTEXT=1 && \
	export KERNEL_BUILD_DIR=$(KERNEL_DIR) && \
	export KERNEL_VERSION=$(shell make -C $(KERNEL_DIR) kernelversion) && \
	export INSTALL_ROOT=$(INSTALL_PREFIX) && \
	bash cocklocker/kernel-integration/integrate.sh

kernel: config
	$(MAKE) -C $(KERNEL_DIR) -j$(NPROCS)

all: kernel cocklocker
	@echo "Build complete"

install: all
	$(MAKE) -C $(KERNEL_DIR) install
	systemctl enable cockpit-hardened
```

### CMake Integration

If using CMake:

```cmake
# CMakeLists.txt snippet

add_custom_target(cocklocker
    COMMAND ${CMAKE_COMMAND} -E env
        KERNEL_BUILD_CONTEXT=1
        KERNEL_BUILD_DIR=${KERNEL_SOURCE_DIR}
        KERNEL_VERSION=${KERNEL_VERSION}
        INSTALL_ROOT=${CMAKE_INSTALL_PREFIX}
        bash ${CMAKE_SOURCE_DIR}/cocklocker/kernel-integration/integrate.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building CockLocker hardened Cockpit"
)

add_dependencies(all cocklocker)
```

## Environment Variables

The integration script recognizes these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `KERNEL_BUILD_CONTEXT` | Set to 1 when building in kernel suite | 0 |
| `KERNEL_BUILD_DIR` | Path to kernel source directory | `/usr/src/linux` |
| `KERNEL_VERSION` | Target kernel version | `$(uname -r)` |
| `INSTALL_ROOT` | Installation prefix | `/` |
| `DESTDIR` | Staging directory for builds | (none) |
| `BUILD_JOBS` | Parallel build jobs | `$(nproc)` |
| `COCKLOCKER_ROOT` | CockLocker repository root | (auto-detected) |

## Git Workflows

### Updating CockLocker in Your Suite

```bash
# Update to latest CockLocker
cd your-kernel-suite
git submodule update --remote cocklocker

# Update nested Cockpit submodule
cd cocklocker
git submodule update --remote cockpit
cd ..

# Commit updates
git add cocklocker
git commit -m "Update CockLocker to latest version"
```

### Freezing Specific Versions

```bash
# Pin to specific CockLocker version
cd cocklocker
git checkout v1.0.0  # or specific commit
cd ..

# Update parent to track this version
git add cocklocker
git commit -m "Pin CockLocker to v1.0.0"
```

### Handling Nested Submodules

When cloning your kernel suite:

```bash
# Clone with nested submodules
git clone --recurse-submodules https://github.com/you/kernel-suite.git

# Or if already cloned
git submodule update --init --recursive
```

## Kernel Boot Parameters

Add these to your bootloader configuration (e.g., `/etc/default/grub`):

```
GRUB_CMDLINE_LINUX="lsm=landlock,lockdown,yama,integrity,apparmor \
    lockdown=confidentiality \
    init_on_alloc=1 \
    init_on_free=1 \
    page_alloc.shuffle=1 \
    pti=on \
    spec_store_bypass_disable=seccomp \
    spectre_v2=on \
    mitigations=auto,nosmt"
```

Update GRUB:

```bash
update-grub
reboot
```

## Verification

After kernel build and boot:

### 1. Verify Kernel Features

```bash
# Check Landlock
cat /sys/kernel/security/lsm | grep landlock

# Check seccomp
cat /proc/self/status | grep Seccomp

# Check namespaces
ls -la /proc/self/ns/

# Run full check
bash cocklocker/kernel-integration/verify-kernel.sh
```

### 2. Verify CockLocker Installation

```bash
# Check binaries
ls -la /opt/cockpit-hardened/

# Check service
systemctl status cockpit-hardened

# Check hardening
checksec --file=/opt/cockpit-hardened/bin/cockpit-sandbox

# View integration report
cat cocklocker/kernel-integration/integration-report.txt
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Kernel Build with CockLocker

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          submodules: recursive

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y build-essential bc kmod cpio flex bison \
            libssl-dev libelf-dev libncurses-dev autoconf automake libtool \
            pkg-config nodejs npm

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Build Kernel
        run: |
          cd kernel-sources
          make defconfig
          ./scripts/kconfig/merge_config.sh .config \
            ../cocklocker/kernel-integration/kernel.config.fragment
          make -j$(nproc)

      - name: Build CockLocker
        run: |
          export KERNEL_BUILD_CONTEXT=1
          export DESTDIR=${{ github.workspace }}/staging
          bash cocklocker/kernel-integration/integrate.sh

      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: kernel-with-cocklocker
          path: staging/
```

### GitLab CI Example

```yaml
# .gitlab-ci.yml

stages:
  - build

build_kernel:
  stage: build
  image: ubuntu:22.04
  script:
    - apt-get update
    - apt-get install -y build-essential bc kmod cpio flex bison git curl
    - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    - source $HOME/.cargo/env
    - git submodule update --init --recursive
    - cd kernel-sources && make defconfig
    - ./scripts/kconfig/merge_config.sh .config ../cocklocker/kernel-integration/kernel.config.fragment
    - make -j$(nproc)
    - cd ..
    - export KERNEL_BUILD_CONTEXT=1
    - export DESTDIR=$CI_PROJECT_DIR/staging
    - bash cocklocker/kernel-integration/integrate.sh
  artifacts:
    paths:
      - staging/
    expire_in: 1 week
```

## Packaging

### Creating a Debian Package

```bash
# Build with DESTDIR
export DESTDIR="$(pwd)/debian/tmp"
bash cocklocker/kernel-integration/integrate.sh

# Create debian package structure
mkdir -p debian/DEBIAN
cat > debian/DEBIAN/control << EOF
Package: cocklocker
Version: 1.0.0
Section: admin
Priority: optional
Architecture: amd64
Depends: libc6, libsystemd0
Maintainer: Your Name <you@example.com>
Description: APT-level hardening for Cockpit
 CockLocker provides comprehensive security hardening for Cockpit
EOF

cat > debian/DEBIAN/postinst << EOF
#!/bin/sh
set -e
if [ "\$1" = "configure" ]; then
    systemctl daemon-reload
    systemctl enable cockpit-hardened || true
fi
EOF

chmod 755 debian/DEBIAN/postinst

# Build package
dpkg-deb --build debian cocklocker_1.0.0_amd64.deb
```

### Creating an RPM Package

```spec
# cocklocker.spec

Name:           cocklocker
Version:        1.0.0
Release:        1%{?dist}
Summary:        APT-level hardening for Cockpit

License:        MIT
URL:            https://github.com/yourusername/COCKLOCKER
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc, make, rust, cargo
Requires:       systemd

%description
CockLocker provides comprehensive security hardening for Cockpit

%prep
%setup -q

%build
export KERNEL_BUILD_CONTEXT=1
bash kernel-integration/integrate.sh

%install
# Files already in DESTDIR from build

%post
systemctl daemon-reload
systemctl enable cockpit-hardened

%files
/opt/cockpit-hardened/
/etc/systemd/system/cockpit-hardened.service
/etc/pam.d/cockpit-hardened

%changelog
* Thu Nov 07 2024 Your Name <you@example.com> - 1.0.0-1
- Initial package
```

## Troubleshooting

### Issue: Nested submodule not initialized

**Solution:**
```bash
git submodule update --init --recursive
```

### Issue: Kernel doesn't support Landlock

**Solution:**
Ensure kernel.config.fragment was merged and kernel version is 5.13+

### Issue: Build fails with "cargo not found"

**Solution:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Issue: Permission denied during installation

**Solution:**
Run integration script as root or with sudo

### Issue: systemd service fails to start

**Solution:**
```bash
# Check logs
journalctl -u cockpit-hardened -n 50

# Verify kernel support
bash cocklocker/kernel-integration/verify-kernel.sh

# Check permissions
ls -la /opt/cockpit-hardened/
```

## Best Practices

1. **Pin Versions**: Use specific commits/tags for reproducible builds
2. **Test in VM**: Test kernel + CockLocker in VM before production
3. **Review Reports**: Check integration-report.txt after build
4. **Verify Hardening**: Run checksec on all binaries
5. **Monitor Logs**: Set up log monitoring for /var/log/cockpit-hardened/
6. **Update Regularly**: Keep both kernel and CockLocker updated
7. **Document Changes**: Track customizations to integration script

## Support

For issues specific to kernel integration:
- Check integration-report.txt for build details
- Review kernel-integration/INTEGRATION.md (this file)
- Open issue at https://github.com/yourusername/COCKLOCKER/issues

## References

- [CockLocker README](../README.md)
- [Kernel Configuration Guide](../KERNEL_CONFIG.md)
- [Mission Statement](../MISSION.md)
- [Git Submodules Documentation](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
