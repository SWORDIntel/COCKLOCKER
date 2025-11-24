# Intel Meteor Lake AI Optimization Guide

## Overview

CockLocker provides comprehensive optimization for Intel Meteor Lake processors (14th Gen Core Ultra), featuring:

- **Intel NPU (Neural Processing Unit)** - Dedicated AI acceleration
- **Thread Director** - Hybrid P-core/E-core intelligent scheduling
- **AVX-VNNI** - AI-optimized vector instructions
- **AMX** - Advanced Matrix Extensions for AI workloads
- **RAPL** - Running Average Power Limit for power management

## Intel Meteor Lake Architecture

### Hybrid Core Architecture

Meteor Lake features Intel's advanced hybrid architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    METEOR LAKE SOC                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  P-Cores (6) │  │  E-Cores (8) │  │   NPU        │      │
│  │  High Perf   │  │  Efficiency  │  │  AI Engine   │      │
│  │  AVX-512     │  │  AVX2        │  │  11 TOPS     │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  GPU (Arc)   │  │  Memory Ctrl │  │  I/O Die     │      │
│  │  Xe Graphics │  │  LPDDR5X     │  │  TB4/USB4    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Performance Cores (P-Cores)
- High-performance cores for demanding workloads
- Support for AVX-512, AVX-VNNI, AMX
- Higher clock speeds (up to 5.1 GHz)
- Used for: Compilation, AI inference, intensive computation

### Efficiency Cores (E-Cores)
- Power-efficient cores for background tasks
- Support for AVX2, SSE4.2
- Lower power consumption
- Used for: Services, monitoring, I/O operations

## Intel NPU (Neural Processing Unit)

### What is the NPU?

The Intel NPU is a dedicated AI accelerator integrated into Meteor Lake processors:

- **11+ TOPS** (Trillion Operations Per Second) AI performance
- Dedicated INT8/FP16 compute engines
- Low power consumption for sustained AI workloads
- OpenVINO integration for AI frameworks

### NPU Features Supported by CockLocker

```bash
# Check NPU status
/opt/cockpit-hardened/intel/intel_npu_manager.py status

# Enable AI acceleration
/opt/cockpit-hardened/intel/intel_npu_manager.py enable-ai

# Set NPU power mode
/opt/cockpit-hardened/intel/intel_npu_manager.py power --power-mode=performance
```

### NPU Power Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `performance` | Maximum AI throughput | Inference, AI workloads |
| `balanced` | Balance power/performance | General usage |
| `powersave` | Minimum power | Battery operation |
| `auto` | Dynamic adjustment | Default |

## Build System Optimization

### Compilation Flags for Meteor Lake

CockLocker applies these optimizations for Meteor Lake:

```bash
# Architecture-specific
-march=meteorlake
-mtune=meteorlake

# SIMD optimizations
-mavx2
-mavxvnni        # AI-optimized vector neural network instructions
-mf16c           # FP16 support for AI
-mfma            # Fused multiply-add

# Security (Intel CET)
-mshstk          # Shadow stack
-fcf-protection=full

# AI floating point
-mfma            # Fused multiply-add acceleration
```

### Building for Meteor Lake

```bash
# Automatic Meteor Lake optimization
./build_feature_complete.sh --profile=meteorlake

# With all plugins
./build_feature_complete.sh --profile=meteorlake --plugins=all

# Manual CPU detection
./cocklocker.sh detect-cpu
```

## Thread Director Integration

### What is Thread Director?

Intel Thread Director is hardware-level thread scheduling that:

- Monitors workload characteristics in real-time
- Routes threads to optimal core type (P or E)
- Works with Linux kernel scheduler (5.18+)
- Improves both performance and power efficiency

### CockLocker Thread Director Configuration

```bash
# Pre-start script configures Thread Director
/opt/cockpit-hardened/scripts/pre-start.sh

# Manual configuration
source /opt/cockpit-hardened/intel/meteorlake_optimizer.sh
configure_thread_director "ai-intensive"
```

### Workload Hints

| Hint | Governor | E-PP | Best For |
|------|----------|------|----------|
| `ai-intensive` | performance | performance | AI inference |
| `balanced` | schedutil | balance_performance | General |
| `background` | powersave | power | Services |

## RAPL Power Management

### Power Domains

CockLocker monitors these RAPL domains:

```
Package (PKG)  - Total CPU package power
Core           - CPU core power
Uncore         - Memory controller, cache
DRAM           - Memory power
GT (GPU)       - Graphics power (if applicable)
```

### Power Limit Configuration

```bash
# View current power limits
cat /sys/class/powercap/intel-rapl/intel-rapl:0/constraint_0_power_limit_uw

# Set via CockLocker (watts to microwatts)
source /opt/cockpit-hardened/intel/meteorlake_optimizer.sh
configure_rapl_limits "performance"  # No limit
configure_rapl_limits "balanced"     # Default TDP
configure_rapl_limits "powersave"    # 75% TDP
```

## Cockpit Intel Monitor Plugin

### Features

The custom Intel Monitor plugin provides:

1. **Real-time CPU monitoring**
   - Per-core frequency display
   - P-core vs E-core visualization
   - Temperature monitoring

2. **NPU status dashboard**
   - Detection status
   - Power mode control
   - Driver information

3. **Power profile management**
   - One-click profile switching
   - RAPL power visualization
   - Current power consumption

4. **CPU feature detection**
   - AVX2, AVX-512, AVX-VNNI
   - AMX, Intel CET status

### Accessing the Plugin

After installation:
```
https://127.0.0.1:9090/intel-monitor/
```

## AI Workload Optimization

### Recommended Configuration for AI

```bash
# 1. Enable AI power profile
/opt/cockpit-hardened/intel/intel_npu_manager.py enable-ai

# 2. Set performance power profile
source /opt/cockpit-hardened/intel/meteorlake_optimizer.sh
set_meteorlake_power_profile "ai-performance"

# 3. Verify configuration
./cocklocker.sh verify
```

### OpenVINO Integration

For AI inference workloads:

```bash
# Install OpenVINO runtime
# (Package depends on distribution)

# CockLocker auto-detects OpenVINO NPU plugin
/opt/cockpit-hardened/intel/intel_npu_manager.py status
```

## Kernel Requirements

### Required Kernel Features

For full Meteor Lake support, ensure kernel has:

```
CONFIG_INTEL_IDLE=y           # P-state driver
CONFIG_X86_INTEL_PSTATE=y     # Intel P-state
CONFIG_INTEL_RAPL=m           # RAPL power capping
CONFIG_ACCEL=m                # NPU accelerator class
CONFIG_INTEL_VPU=m            # Intel VPU driver
CONFIG_SCHED_MC=y             # Multi-core scheduling
```

### Minimum Kernel Version

- **Linux 6.2+** - Basic Meteor Lake support
- **Linux 6.5+** - NPU driver support
- **Linux 6.7+** - Full Thread Director hints

## Performance Tuning

### For Maximum AI Performance

```bash
# 1. Disable power saving
echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 2. Set EPP to performance
echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference

# 3. Disable turbo limits (if thermal headroom allows)
echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
```

### For Power Efficiency

```bash
# Use CockLocker power profile
set_meteorlake_power_profile "powersave"

# This automatically:
# - Sets governors to powersave
# - Limits P-state maximum
# - Configures NPU to low power
```

## Troubleshooting

### NPU Not Detected

1. Check kernel version (6.5+ required)
2. Verify NPU driver: `lsmod | grep intel_vpu`
3. Check PCI device: `lspci | grep -i neural`
4. Install Intel compute runtime

### Thread Director Not Working

1. Verify kernel 5.18+
2. Check intel_pstate driver: `cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver`
3. Enable hybrid scheduling: `echo 1 > /sys/kernel/debug/sched/itd_enable`

### High Power Consumption

1. Check for stuck high-frequency cores
2. Verify E-cores are active
3. Check NPU power mode
4. Review RAPL limits

## Benchmarking

### CPU Performance

```bash
# P-core stress test
stress-ng --cpu 6 --cpu-method matrixprod -t 60s

# E-core efficiency test
taskset -c 6-13 stress-ng --cpu 8 -t 60s
```

### NPU Performance

```bash
# Requires OpenVINO
benchmark_app -m model.xml -d NPU -niter 100
```

## References

- [Intel Meteor Lake Architecture](https://www.intel.com/content/www/us/en/products/platforms/details/meteor-lake.html)
- [Intel NPU Documentation](https://github.com/intel/linux-npu-driver)
- [OpenVINO Toolkit](https://docs.openvino.ai/)
- [Linux Kernel Intel Documentation](https://www.kernel.org/doc/html/latest/admin-guide/pm/intel_pstate.html)
