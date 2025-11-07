# Kernel Configuration for CockLocker

CockLocker requires specific kernel features for maximum security. This guide covers the necessary kernel configuration options for optimal hardening.

## Minimum Requirements

- **Linux Kernel**: 5.13+ (for Landlock LSM support)
- **Recommended**: 6.0+ (for latest security features)

## Required Kernel Features

### 1. Landlock LSM (Linux Security Module)

Landlock provides path-based filesystem access control.

```
CONFIG_SECURITY_LANDLOCK=y
CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"
```

**Verification**:
```bash
cat /sys/kernel/security/lsm
# Should include "landlock"

# Check Landlock ABI version
ls /sys/kernel/security/landlock/
# Should show: features/ version
```

### 2. seccomp and seccomp-bpf

System call filtering for sandboxing.

```
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
```

**Verification**:
```bash
grep CONFIG_SECCOMP /boot/config-$(uname -r)
```

### 3. Namespaces

Process isolation via kernel namespaces.

```
CONFIG_NAMESPACES=y
CONFIG_UTS_NAMESPACE=y
CONFIG_IPC_NAMESPACE=y
CONFIG_USER_NAMESPACE=y
CONFIG_PID_NAMESPACE=y
CONFIG_NET_NAMESPACE=y
CONFIG_CGROUP_NAMESPACE=y
```

**Verification**:
```bash
ls -la /proc/self/ns/
# Should show: cgroup, ipc, mnt, net, pid, user, uts
```

### 4. Control Groups (cgroups)

Resource limiting and isolation.

```
CONFIG_CGROUPS=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_FREEZER=y
CONFIG_CGROUP_SCHED=y
CONFIG_CPUSETS=y
CONFIG_MEMCG=y
CONFIG_BLK_CGROUP=y
```

### 5. Kernel Hardening Options

Additional security features.

```
# Stack protection
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_STRICT_MODULE_RWX=y

# Kernel address space layout randomization
CONFIG_RANDOMIZE_BASE=y
CONFIG_RANDOMIZE_MEMORY=y

# Kernel page table isolation (Meltdown mitigation)
CONFIG_PAGE_TABLE_ISOLATION=y

# Spectre/Meltdown mitigations
CONFIG_RETPOLINE=y
CONFIG_CPU_SPECTRE_V2=y

# Prevent kernel memory leaks
CONFIG_HARDENED_USERCOPY=y
CONFIG_FORTIFY_SOURCE=y

# Restrict kernel module loading
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_FORCE=y
CONFIG_MODULE_SIG_ALL=y

# Kernel lockdown
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y

# Auditing
CONFIG_AUDIT=y
CONFIG_AUDITSYSCALL=y

# Capabilities
CONFIG_SECURITY_CAPABILITIES=y

# Yama LSM (ptrace restrictions)
CONFIG_SECURITY_YAMA=y

# Integrity subsystem
CONFIG_INTEGRITY=y

# BPF JIT hardening
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y

# Prevent unprivileged BPF
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
```

### 6. Xen Hypervisor Support

For Xen-specific hardening features.

```
CONFIG_XEN=y
CONFIG_XEN_PVH=y
CONFIG_XEN_DOM0=y
CONFIG_XEN_PVHVM=y
CONFIG_XEN_SAVE_RESTORE=y
CONFIG_XEN_GRANT_DEV_ALLOC=m
CONFIG_XEN_PRIVCMD=y
CONFIG_XEN_ACPI_PROCESSOR=m
```

**Verification**:
```bash
# Check if running under Xen
ls -la /proc/xen/
dmesg | grep -i xen
```

## Kernel Boot Parameters

Add these parameters to your bootloader configuration (`/etc/default/grub`):

```
GRUB_CMDLINE_LINUX="lsm=landlock,lockdown,yama,integrity,apparmor \
    lockdown=confidentiality \
    init_on_alloc=1 \
    init_on_free=1 \
    page_alloc.shuffle=1 \
    pti=on \
    spec_store_bypass_disable=seccomp \
    spectre_v2=on \
    mitigations=auto,nosmt \
    slab_nomerge \
    slub_debug=FZP \
    vsyscall=none \
    debugfs=off \
    oops=panic \
    module.sig_enforce=1 \
    extra_latent_entropy"
```

**Apply**:
```bash
sudo update-grub
sudo reboot
```

## Verification Script

Save this as `check_kernel_security.sh`:

```bash
#!/bin/bash
# Check kernel security features

echo "=== Kernel Security Configuration Check ==="
echo

# Check kernel version
echo "[*] Kernel Version:"
uname -r
echo

# Check Landlock
echo "[*] Landlock LSM:"
if grep -q landlock /sys/kernel/security/lsm; then
    echo "  ✓ Enabled"
    echo "  Version: $(cat /sys/kernel/security/landlock/version 2>/dev/null || echo 'N/A')"
else
    echo "  ✗ Not enabled"
fi
echo

# Check seccomp
echo "[*] seccomp:"
if grep -q CONFIG_SECCOMP=y /boot/config-$(uname -r); then
    echo "  ✓ Enabled"
else
    echo "  ✗ Not enabled"
fi
echo

# Check namespaces
echo "[*] Namespaces:"
for ns in cgroup ipc mnt net pid user uts; do
    if [ -e "/proc/self/ns/$ns" ]; then
        echo "  ✓ $ns namespace available"
    else
        echo "  ✗ $ns namespace not available"
    fi
done
echo

# Check security features
echo "[*] Kernel Hardening Features:"
declare -A features=(
    ["CONFIG_STACKPROTECTOR_STRONG"]="Stack protector"
    ["CONFIG_RANDOMIZE_BASE"]="KASLR"
    ["CONFIG_PAGE_TABLE_ISOLATION"]="KPTI"
    ["CONFIG_RETPOLINE"]="Retpoline"
    ["CONFIG_HARDENED_USERCOPY"]="Hardened usercopy"
    ["CONFIG_FORTIFY_SOURCE"]="FORTIFY_SOURCE"
    ["CONFIG_MODULE_SIG_FORCE"]="Module signature enforcement"
)

for feature in "${!features[@]}"; do
    if grep -q "$feature=y" /boot/config-$(uname -r) 2>/dev/null; then
        echo "  ✓ ${features[$feature]}"
    else
        echo "  ✗ ${features[$feature]}"
    fi
done
echo

# Check boot parameters
echo "[*] Security Boot Parameters:"
cmdline=$(cat /proc/cmdline)

if echo "$cmdline" | grep -q "landlock"; then
    echo "  ✓ Landlock in LSM"
else
    echo "  ✗ Landlock not in LSM"
fi

if echo "$cmdline" | grep -q "pti=on"; then
    echo "  ✓ PTI enabled"
else
    echo "  ? PTI status unknown (might be default)"
fi

if echo "$cmdline" | grep -q "spectre_v2=on"; then
    echo "  ✓ Spectre v2 mitigations enabled"
else
    echo "  ? Spectre v2 status unknown"
fi
echo

# Check Xen
echo "[*] Xen Hypervisor:"
if [ -d "/proc/xen" ]; then
    echo "  ✓ Xen detected"
    if [ -f "/proc/xen/capabilities" ]; then
        echo "  Capabilities: $(cat /proc/xen/capabilities)"
    fi
else
    echo "  ✗ Xen not detected"
fi
echo

echo "=== Check Complete ==="
```

## Building a Hardened Kernel

If your distribution's kernel lacks required features:

### 1. Download Kernel Source

```bash
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz
tar xf linux-6.6.tar.xz
cd linux-6.6
```

### 2. Configure Kernel

```bash
# Start with your distribution's config
cp /boot/config-$(uname -r) .config

# Enable new features
make menuconfig

# Or use provided script
make olddefconfig
scripts/config --enable SECURITY_LANDLOCK
scripts/config --enable SECCOMP
scripts/config --enable SECCOMP_FILTER
scripts/config --enable STACKPROTECTOR_STRONG
# ... (enable all required options)
```

### 3. Build and Install

```bash
# Build
make -j$(nproc) bzImage modules

# Install
sudo make modules_install
sudo make install

# Update bootloader
sudo update-grub

# Reboot
sudo reboot
```

## Runtime Verification

After booting with the hardened kernel:

```bash
# Check active LSMs
cat /sys/kernel/security/lsm

# Check kernel lockdown
cat /sys/kernel/security/lockdown

# Check seccomp status
cat /proc/self/status | grep Seccomp

# Check namespace support
ls -la /proc/self/ns/

# Verify boot parameters
cat /proc/cmdline

# Run verification script
chmod +x check_kernel_security.sh
./check_kernel_security.sh
```

## Distribution-Specific Notes

### Ubuntu 22.04+

Ubuntu 22.04 and later include Landlock by default. Verify:

```bash
apt install linux-image-generic-hwe-22.04
# or
apt install linux-image-generic
```

### Debian 12+

Debian 12 (Bookworm) includes Landlock:

```bash
apt install linux-image-amd64
```

### Fedora 37+

Fedora includes most required features by default.

### Arch Linux

```bash
pacman -S linux linux-headers
```

Use the `linux-hardened` kernel for maximum security:

```bash
pacman -S linux-hardened linux-hardened-headers
```

## Troubleshooting

### Landlock Not Available

If Landlock is compiled as a module:

```bash
# Check if module exists
find /lib/modules/$(uname -r) -name landlock

# Load module
sudo modprobe landlock

# Add to autoload
echo "landlock" | sudo tee -a /etc/modules-load.d/landlock.conf
```

### seccomp Not Working

Verify seccomp support:

```bash
grep CONFIG_SECCOMP /boot/config-$(uname -r)

# Test seccomp
perl -e 'syscall(317, 1, 0, 0, 0);' && echo "seccomp supported"
```

### Namespace Creation Fails

Check unprivileged namespace creation:

```bash
# Allow unprivileged user namespaces
sudo sysctl -w kernel.unprivileged_userns_clone=1

# Make permanent
echo "kernel.unprivileged_userns_clone=1" | sudo tee -a /etc/sysctl.d/99-userns.conf
```

## Performance Impact

Enabling all security features has minimal performance impact:

- **KASLR/ASLR**: < 1% overhead
- **Stack protector**: 1-3% overhead
- **KPTI**: 5-30% overhead (Meltdown mitigation, necessary)
- **Retpoline**: 5-10% overhead (Spectre mitigation, necessary)
- **Landlock**: < 1% overhead
- **seccomp**: < 1% overhead

Total expected overhead: 10-40% depending on workload. For a management interface like Cockpit, this is acceptable.

## References

- [Landlock Documentation](https://landlock.io/)
- [seccomp Documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [Kernel Self Protection Project](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)
- [KSPP Recommended Settings](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings)
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html)
