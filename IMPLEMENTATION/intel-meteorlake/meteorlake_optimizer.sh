#!/bin/bash
################################################################################
# Intel Meteor Lake Optimization Module for CockLocker
# ============================================================================
# Provides comprehensive optimization for Intel Meteor Lake processors
# including NPU (AI Engine), Thread Director, and Power Management
#
# FEATURES:
#   - Intel NPU (Neural Processing Unit) detection and configuration
#   - Intel Thread Director optimization (P-cores/E-cores scheduling)
#   - RAPL (Running Average Power Limit) power management
#   - Intel AMX (Advanced Matrix Extensions) support
#   - Meteor Lake specific compiler flags
#   - AI workload acceleration support
#
# USAGE:
#   source meteorlake_optimizer.sh
#   detect_meteorlake_features
#   get_meteorlake_build_flags
################################################################################

set -euo pipefail

# ============================================================================
# INTEL METEOR LAKE CPU DETECTION
# ============================================================================

# Intel Meteor Lake CPU Family IDs
METEORLAKE_MODELS=(
    "0xAA"   # Meteor Lake-M (Mobile)
    "0xAB"   # Meteor Lake-P (Performance Mobile)
    "0xAC"   # Meteor Lake-S (Desktop)
    "0xAD"   # Meteor Lake-H (High Performance)
)

# Detect if running on Meteor Lake
is_meteorlake_cpu() {
    local vendor=$(grep -m1 "vendor_id" /proc/cpuinfo | cut -d: -f2 | tr -d ' ')
    local family=$(grep -m1 "cpu family" /proc/cpuinfo | cut -d: -f2 | tr -d ' ')
    local model=$(grep -m1 "model" /proc/cpuinfo | cut -d: -f2 | tr -d ' ')

    if [ "$vendor" = "GenuineIntel" ] && [ "$family" = "6" ]; then
        # Meteor Lake is model 170 (0xAA) and variants
        if [ "$model" -ge 170 ] && [ "$model" -le 175 ]; then
            return 0
        fi
    fi
    return 1
}

# Get Intel CPU generation name
get_intel_cpu_generation() {
    local model=$(grep -m1 "model" /proc/cpuinfo | cut -d: -f2 | tr -d ' ')

    case "$model" in
        170|171|172|173|174|175) echo "meteorlake" ;;
        183|184|185|186|187)     echo "raptorlake" ;;
        151|152|153|154|155)     echo "alderlake" ;;
        *)                        echo "generic" ;;
    esac
}

# ============================================================================
# INTEL NPU (NEURAL PROCESSING UNIT) SUPPORT
# ============================================================================

# Detect Intel NPU presence
detect_intel_npu() {
    local npu_detected=false
    local npu_type=""
    local npu_driver=""

    # Check for Intel NPU device via PCI
    if lspci 2>/dev/null | grep -qi "neural\|NPU\|VPU"; then
        npu_detected=true
        npu_type="dedicated"
    fi

    # Check for Meteor Lake integrated NPU (VPU)
    if lspci 2>/dev/null | grep -qi "Intel.*Visual\|Intel.*VPU"; then
        npu_detected=true
        npu_type="integrated"
    fi

    # Check for Intel NPU driver
    if [ -d "/sys/class/accel" ] || [ -d "/sys/class/misc/intel_vpu" ]; then
        npu_driver="loaded"
    fi

    # Check for OpenVINO NPU support
    if [ -f "/opt/intel/openvino/runtime/lib/intel64/libopenvino_intel_npu_plugin.so" ]; then
        npu_driver="openvino"
    fi

    echo "NPU_DETECTED=$npu_detected"
    echo "NPU_TYPE=$npu_type"
    echo "NPU_DRIVER=$npu_driver"
}

# Configure NPU power management
configure_npu_power() {
    local npu_power_mode="${1:-balanced}"

    # NPU power modes: performance, balanced, powersave
    case "$npu_power_mode" in
        performance)
            # Maximum AI throughput
            echo "high" > /sys/class/accel/accel0/power_mode 2>/dev/null || true
            ;;
        balanced)
            # Balance between power and performance
            echo "auto" > /sys/class/accel/accel0/power_mode 2>/dev/null || true
            ;;
        powersave)
            # Minimize power consumption
            echo "low" > /sys/class/accel/accel0/power_mode 2>/dev/null || true
            ;;
    esac
}

# ============================================================================
# INTEL THREAD DIRECTOR OPTIMIZATION
# ============================================================================

# Detect hybrid architecture (P-cores + E-cores)
detect_hybrid_cores() {
    local p_cores=0
    local e_cores=0
    local total_cores=$(nproc)

    # Check for hybrid topology
    if [ -f "/sys/devices/system/cpu/cpu0/topology/core_type" ]; then
        for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
            if [ -f "$cpu/topology/core_type" ]; then
                core_type=$(cat "$cpu/topology/core_type" 2>/dev/null || echo "unknown")
                case "$core_type" in
                    0|"performance") ((p_cores++)) ;;
                    1|"efficiency")  ((e_cores++)) ;;
                esac
            fi
        done
    else
        # Fallback: Estimate from total cores (Meteor Lake typical config)
        # Usually 6 P-cores + 8 E-cores = 14 cores
        p_cores=$((total_cores * 40 / 100))
        e_cores=$((total_cores - p_cores))
    fi

    echo "P_CORES=$p_cores"
    echo "E_CORES=$e_cores"
    echo "TOTAL_CORES=$total_cores"
    echo "HYBRID_ARCHITECTURE=$([ $e_cores -gt 0 ] && echo 'yes' || echo 'no')"
}

# Set Thread Director scheduling hints
configure_thread_director() {
    local workload_type="${1:-balanced}"

    # Intel Thread Director workload hints
    # Available in Linux 5.18+ with intel_pstate driver

    local governor="schedutil"
    local energy_perf="balance_performance"

    case "$workload_type" in
        "ai-intensive")
            # Favor P-cores for AI workloads
            governor="performance"
            energy_perf="performance"
            ;;
        "background")
            # Favor E-cores for background tasks
            governor="powersave"
            energy_perf="power"
            ;;
        "balanced"|*)
            governor="schedutil"
            energy_perf="balance_performance"
            ;;
    esac

    # Apply settings
    for cpu in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
        echo "$governor" > "$cpu" 2>/dev/null || true
    done

    for epp in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/energy_performance_preference; do
        echo "$energy_perf" > "$epp" 2>/dev/null || true
    done
}

# ============================================================================
# INTEL RAPL POWER MANAGEMENT
# ============================================================================

# Detect RAPL domains
detect_rapl_domains() {
    local rapl_dir="/sys/class/powercap/intel-rapl"

    if [ ! -d "$rapl_dir" ]; then
        echo "RAPL_AVAILABLE=no"
        return
    fi

    echo "RAPL_AVAILABLE=yes"

    for domain in "$rapl_dir"/intel-rapl:*; do
        if [ -d "$domain" ]; then
            local name=$(cat "$domain/name" 2>/dev/null || echo "unknown")
            local energy=$(cat "$domain/energy_uj" 2>/dev/null || echo "0")
            local max_energy=$(cat "$domain/max_energy_range_uj" 2>/dev/null || echo "0")

            echo "RAPL_DOMAIN_${name^^}=yes"
            echo "RAPL_ENERGY_${name^^}=$energy"
        fi
    done
}

# Configure RAPL power limits
configure_rapl_limits() {
    local power_mode="${1:-balanced}"
    local rapl_dir="/sys/class/powercap/intel-rapl"

    if [ ! -d "$rapl_dir" ]; then
        return 1
    fi

    local package_power_limit=""

    case "$power_mode" in
        "performance")
            # Allow maximum power (no limit)
            package_power_limit="0"
            ;;
        "balanced")
            # Default TDP
            package_power_limit=""  # Use default
            ;;
        "powersave")
            # Reduce to 75% of TDP
            local max_power=$(cat "$rapl_dir/intel-rapl:0/constraint_0_max_power_uw" 2>/dev/null || echo "0")
            if [ "$max_power" -gt 0 ]; then
                package_power_limit=$((max_power * 75 / 100))
            fi
            ;;
    esac

    if [ -n "$package_power_limit" ] && [ "$package_power_limit" != "0" ]; then
        echo "$package_power_limit" > "$rapl_dir/intel-rapl:0/constraint_0_power_limit_uw" 2>/dev/null || true
    fi
}

# ============================================================================
# INTEL AMX (ADVANCED MATRIX EXTENSIONS) SUPPORT
# ============================================================================

# Detect AMX support
detect_amx_support() {
    local cpu_flags=$(grep -m1 "flags" /proc/cpuinfo | cut -d: -f2)

    local amx_bf16="no"
    local amx_int8="no"
    local amx_tile="no"

    if echo "$cpu_flags" | grep -q "amx_bf16"; then
        amx_bf16="yes"
    fi

    if echo "$cpu_flags" | grep -q "amx_int8"; then
        amx_int8="yes"
    fi

    if echo "$cpu_flags" | grep -q "amx_tile"; then
        amx_tile="yes"
    fi

    echo "AMX_BF16=$amx_bf16"
    echo "AMX_INT8=$amx_int8"
    echo "AMX_TILE=$amx_tile"
    echo "AMX_AVAILABLE=$([ "$amx_tile" = "yes" ] && echo 'yes' || echo 'no')"
}

# ============================================================================
# METEOR LAKE SPECIFIC BUILD FLAGS
# ============================================================================

get_meteorlake_build_flags() {
    local optimization_level="${1:-balanced}"
    local flags=()

    # Base architecture flag for Meteor Lake
    flags+=("-march=meteorlake" "-mtune=meteorlake")

    # SIMD extensions available on Meteor Lake
    flags+=("-mavx2" "-mavx" "-msse4.2" "-msse4.1")

    # Advanced Vector Extensions (AVX-VNNI for AI)
    flags+=("-mavxvnni" "-mavxvnniint8")

    # Intel CET (Control-flow Enforcement Technology)
    flags+=("-fcf-protection=full" "-mshstk")

    # FP16 support for AI workloads
    flags+=("-mf16c")

    # BMI2 for bit manipulation
    flags+=("-mbmi2" "-mbmi")

    # AES-NI for encryption
    flags+=("-maes")

    # SHA extensions
    flags+=("-msha")

    case "$optimization_level" in
        "performance")
            flags+=("-O3" "-ffast-math" "-funroll-loops")
            flags+=("-ftree-vectorize" "-fvect-cost-model=unlimited")
            ;;
        "balanced")
            flags+=("-O2" "-ftree-vectorize")
            ;;
        "size")
            flags+=("-Os" "-ffunction-sections" "-fdata-sections")
            ;;
        "security")
            flags+=("-O2" "-fstack-protector-strong" "-D_FORTIFY_SOURCE=3")
            flags+=("-fstack-clash-protection")
            ;;
    esac

    # LTO (Link Time Optimization) for better performance
    if [ "$optimization_level" = "performance" ]; then
        flags+=("-flto=auto")
    fi

    printf '%s\n' "${flags[@]}"
}

# Get linker flags for Meteor Lake
get_meteorlake_ldflags() {
    local flags=(
        "-Wl,-z,relro"
        "-Wl,-z,now"
        "-Wl,-z,noexecstack"
        "-Wl,-z,separate-code"
        "-Wl,--as-needed"
    )

    printf '%s\n' "${flags[@]}"
}

# ============================================================================
# FEATURE DETECTION SUMMARY
# ============================================================================

detect_meteorlake_features() {
    echo "========================================"
    echo "Intel Meteor Lake Feature Detection"
    echo "========================================"
    echo ""

    # CPU Generation
    local gen=$(get_intel_cpu_generation)
    echo "CPU Generation: $gen"

    if is_meteorlake_cpu; then
        echo "Meteor Lake Detected: YES"
    else
        echo "Meteor Lake Detected: NO (will use generic Intel optimizations)"
    fi
    echo ""

    # Hybrid Architecture
    echo "--- Hybrid Architecture (Thread Director) ---"
    detect_hybrid_cores
    echo ""

    # NPU Detection
    echo "--- Neural Processing Unit (NPU) ---"
    detect_intel_npu
    echo ""

    # AMX Support
    echo "--- Advanced Matrix Extensions (AMX) ---"
    detect_amx_support
    echo ""

    # RAPL Power Management
    echo "--- RAPL Power Management ---"
    detect_rapl_domains
    echo ""

    # CPU Flags
    echo "--- Relevant CPU Flags ---"
    local flags=$(grep -m1 "flags" /proc/cpuinfo | cut -d: -f2)
    echo "AVX2: $(echo "$flags" | grep -q 'avx2' && echo 'yes' || echo 'no')"
    echo "AVX512: $(echo "$flags" | grep -q 'avx512' && echo 'yes' || echo 'no')"
    echo "AVX-VNNI: $(echo "$flags" | grep -q 'avx_vnni' && echo 'yes' || echo 'no')"
    echo "SHA-NI: $(echo "$flags" | grep -q 'sha_ni' && echo 'yes' || echo 'no')"
    echo "AES-NI: $(echo "$flags" | grep -q 'aes' && echo 'yes' || echo 'no')"
    echo ""
}

# ============================================================================
# POWER PROFILE MANAGEMENT
# ============================================================================

# Power profiles optimized for different workloads
set_meteorlake_power_profile() {
    local profile="${1:-balanced}"

    echo "Setting Meteor Lake power profile: $profile"

    case "$profile" in
        "ai-performance")
            # Maximum AI/ML performance
            configure_thread_director "ai-intensive"
            configure_rapl_limits "performance"
            configure_npu_power "performance"
            ;;
        "performance")
            # Maximum general performance
            configure_thread_director "ai-intensive"
            configure_rapl_limits "performance"
            ;;
        "balanced")
            # Balance between power and performance
            configure_thread_director "balanced"
            configure_rapl_limits "balanced"
            configure_npu_power "balanced"
            ;;
        "powersave")
            # Maximum power efficiency
            configure_thread_director "background"
            configure_rapl_limits "powersave"
            configure_npu_power "powersave"
            ;;
    esac
}

# Export functions for use by main build script
export -f is_meteorlake_cpu
export -f get_intel_cpu_generation
export -f detect_intel_npu
export -f detect_hybrid_cores
export -f detect_amx_support
export -f detect_rapl_domains
export -f get_meteorlake_build_flags
export -f get_meteorlake_ldflags
export -f detect_meteorlake_features
export -f set_meteorlake_power_profile
