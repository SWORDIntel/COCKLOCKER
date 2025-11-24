#!/usr/bin/env python3
"""
Intel NPU (Neural Processing Unit) Manager for CockLocker
==========================================================

Provides comprehensive NPU management for Intel Meteor Lake and newer CPUs:
- NPU device detection and status monitoring
- Power management and thermal control
- AI workload scheduling and optimization
- OpenVINO integration support
- Real-time performance metrics

USAGE:
    from intel_npu_manager import IntelNPUManager
    npu = IntelNPUManager()
    npu.detect_npu()
    npu.get_npu_status()
"""

import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('intel_npu_manager')


class NPUPowerMode(Enum):
    """NPU Power management modes"""
    PERFORMANCE = "performance"
    BALANCED = "balanced"
    POWERSAVE = "powersave"
    AUTO = "auto"


class NPUStatus(Enum):
    """NPU device status"""
    AVAILABLE = "available"
    BUSY = "busy"
    IDLE = "idle"
    DISABLED = "disabled"
    NOT_FOUND = "not_found"
    ERROR = "error"


@dataclass
class NPUDevice:
    """NPU device information"""
    device_id: str
    vendor_id: str
    name: str
    driver: str
    status: NPUStatus
    power_mode: NPUPowerMode
    temperature: Optional[float] = None
    power_usage: Optional[float] = None
    utilization: Optional[float] = None
    memory_total: Optional[int] = None
    memory_used: Optional[int] = None
    firmware_version: Optional[str] = None


@dataclass
class NPUMetrics:
    """NPU performance metrics"""
    inference_count: int = 0
    inference_latency_ms: float = 0.0
    throughput_fps: float = 0.0
    power_efficiency: float = 0.0  # inferences per watt
    memory_bandwidth: float = 0.0  # GB/s


class IntelNPUManager:
    """
    Intel NPU Manager for Meteor Lake and newer processors

    Provides detection, configuration, and monitoring of Intel NPU devices.
    Supports both integrated (Meteor Lake) and discrete NPU accelerators.
    """

    # Intel NPU PCI vendor/device IDs
    INTEL_VENDOR_ID = "8086"
    NPU_DEVICE_IDS = {
        "7d1d": "Meteor Lake NPU",
        "643e": "Arrow Lake NPU",
        "a74f": "Intel VPU",
    }

    # Sysfs paths for NPU management
    ACCEL_CLASS_PATH = Path("/sys/class/accel")
    DRM_CLASS_PATH = Path("/sys/class/drm")
    MISC_CLASS_PATH = Path("/sys/class/misc")
    POWERCAP_PATH = Path("/sys/class/powercap/intel-rapl")

    def __init__(self):
        self.devices: List[NPUDevice] = []
        self.metrics: Dict[str, NPUMetrics] = {}
        self._detect_npu_devices()

    def _detect_npu_devices(self) -> None:
        """Detect all Intel NPU devices in the system"""
        self.devices.clear()

        # Method 1: Check /sys/class/accel (Linux 6.1+)
        self._detect_via_accel_class()

        # Method 2: Check PCI devices
        self._detect_via_pci()

        # Method 3: Check for OpenVINO NPU plugin
        self._detect_via_openvino()

        logger.info(f"Detected {len(self.devices)} NPU device(s)")

    def _detect_via_accel_class(self) -> None:
        """Detect NPU via /sys/class/accel (accelerator class)"""
        if not self.ACCEL_CLASS_PATH.exists():
            return

        for accel_dev in self.ACCEL_CLASS_PATH.iterdir():
            if accel_dev.is_dir():
                device = self._read_accel_device(accel_dev)
                if device:
                    self.devices.append(device)

    def _read_accel_device(self, accel_path: Path) -> Optional[NPUDevice]:
        """Read accelerator device information"""
        try:
            device_id = accel_path.name

            # Read device properties
            vendor_path = accel_path / "device" / "vendor"
            vendor = self._read_sysfs_file(vendor_path, "0x8086")

            # Check if Intel device
            if "8086" not in vendor:
                return None

            driver_path = accel_path / "device" / "driver"
            driver = driver_path.resolve().name if driver_path.exists() else "unknown"

            # Get device name
            name = "Intel NPU"
            for dev_id, dev_name in self.NPU_DEVICE_IDS.items():
                if dev_id in device_id.lower():
                    name = dev_name
                    break

            # Read power mode
            power_mode = self._read_power_mode(accel_path)

            # Read thermal information
            temperature = self._read_temperature(accel_path)

            return NPUDevice(
                device_id=device_id,
                vendor_id=vendor.strip(),
                name=name,
                driver=driver,
                status=NPUStatus.AVAILABLE,
                power_mode=power_mode,
                temperature=temperature
            )
        except Exception as e:
            logger.debug(f"Error reading accel device: {e}")
            return None

    def _detect_via_pci(self) -> None:
        """Detect NPU via PCI device enumeration"""
        try:
            result = subprocess.run(
                ["lspci", "-nn", "-d", f"{self.INTEL_VENDOR_ID}:"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    line_lower = line.lower()
                    if any(kw in line_lower for kw in ['npu', 'vpu', 'neural', 'ai']):
                        # Extract device ID from lspci output
                        for dev_id, dev_name in self.NPU_DEVICE_IDS.items():
                            if dev_id in line_lower:
                                if not any(d.device_id == dev_id for d in self.devices):
                                    self.devices.append(NPUDevice(
                                        device_id=dev_id,
                                        vendor_id=self.INTEL_VENDOR_ID,
                                        name=dev_name,
                                        driver="pci",
                                        status=NPUStatus.AVAILABLE,
                                        power_mode=NPUPowerMode.AUTO
                                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def _detect_via_openvino(self) -> None:
        """Detect NPU via OpenVINO runtime"""
        openvino_paths = [
            "/opt/intel/openvino/runtime/lib/intel64",
            "/usr/lib/x86_64-linux-gnu/openvino",
            "/usr/local/lib/openvino"
        ]

        for ov_path in openvino_paths:
            npu_plugin = Path(ov_path) / "libopenvino_intel_npu_plugin.so"
            if npu_plugin.exists():
                if not any(d.driver == "openvino" for d in self.devices):
                    self.devices.append(NPUDevice(
                        device_id="openvino_npu",
                        vendor_id=self.INTEL_VENDOR_ID,
                        name="Intel NPU (OpenVINO)",
                        driver="openvino",
                        status=NPUStatus.AVAILABLE,
                        power_mode=NPUPowerMode.AUTO
                    ))
                break

    def _read_sysfs_file(self, path: Path, default: str = "") -> str:
        """Read a sysfs file safely"""
        try:
            if path.exists():
                return path.read_text().strip()
        except (PermissionError, IOError):
            pass
        return default

    def _read_power_mode(self, device_path: Path) -> NPUPowerMode:
        """Read current NPU power mode"""
        power_mode_path = device_path / "power_mode"
        mode_str = self._read_sysfs_file(power_mode_path, "auto")

        mode_map = {
            "performance": NPUPowerMode.PERFORMANCE,
            "high": NPUPowerMode.PERFORMANCE,
            "balanced": NPUPowerMode.BALANCED,
            "auto": NPUPowerMode.AUTO,
            "powersave": NPUPowerMode.POWERSAVE,
            "low": NPUPowerMode.POWERSAVE,
        }
        return mode_map.get(mode_str.lower(), NPUPowerMode.AUTO)

    def _read_temperature(self, device_path: Path) -> Optional[float]:
        """Read NPU temperature in Celsius"""
        temp_paths = [
            device_path / "hwmon" / "hwmon0" / "temp1_input",
            device_path / "device" / "hwmon" / "hwmon0" / "temp1_input",
        ]

        for temp_path in temp_paths:
            temp_str = self._read_sysfs_file(temp_path)
            if temp_str:
                try:
                    return float(temp_str) / 1000.0  # Convert from millidegrees
                except ValueError:
                    pass
        return None

    def get_npu_status(self) -> Dict:
        """Get current status of all NPU devices"""
        status = {
            "devices": [asdict(d) for d in self.devices],
            "total_devices": len(self.devices),
            "available": any(d.status == NPUStatus.AVAILABLE for d in self.devices),
            "system_info": self._get_system_info()
        }

        # Convert enums to strings for JSON serialization
        for device in status["devices"]:
            device["status"] = device["status"].value
            device["power_mode"] = device["power_mode"].value

        return status

    def _get_system_info(self) -> Dict:
        """Get system information relevant to NPU"""
        info = {
            "kernel_version": os.uname().release,
            "driver_loaded": False,
            "openvino_available": False,
            "rapl_available": self.POWERCAP_PATH.exists()
        }

        # Check for Intel NPU driver
        driver_path = Path("/sys/module/intel_vpu")
        info["driver_loaded"] = driver_path.exists()

        # Check for OpenVINO
        try:
            import openvino
            info["openvino_available"] = True
            info["openvino_version"] = openvino.__version__
        except ImportError:
            pass

        return info

    def set_power_mode(self, mode: NPUPowerMode, device_index: int = 0) -> bool:
        """Set NPU power mode"""
        if device_index >= len(self.devices):
            logger.error(f"Invalid device index: {device_index}")
            return False

        device = self.devices[device_index]
        accel_path = self.ACCEL_CLASS_PATH / device.device_id
        power_mode_path = accel_path / "power_mode"

        mode_map = {
            NPUPowerMode.PERFORMANCE: "high",
            NPUPowerMode.BALANCED: "auto",
            NPUPowerMode.POWERSAVE: "low",
            NPUPowerMode.AUTO: "auto"
        }

        try:
            if power_mode_path.exists():
                power_mode_path.write_text(mode_map[mode])
                device.power_mode = mode
                logger.info(f"Set NPU power mode to {mode.value}")
                return True
        except (PermissionError, IOError) as e:
            logger.error(f"Failed to set power mode: {e}")

        return False

    def get_power_consumption(self) -> Optional[float]:
        """Get current NPU power consumption in watts"""
        if not self.POWERCAP_PATH.exists():
            return None

        try:
            # Read from RAPL NPU domain if available
            for rapl_domain in self.POWERCAP_PATH.iterdir():
                name_path = rapl_domain / "name"
                if name_path.exists():
                    name = name_path.read_text().strip()
                    if "npu" in name.lower() or "vpu" in name.lower():
                        energy_path = rapl_domain / "energy_uj"
                        if energy_path.exists():
                            energy_uj = int(energy_path.read_text().strip())
                            return energy_uj / 1_000_000.0  # Convert to watts
        except (PermissionError, IOError, ValueError):
            pass

        return None

    def get_metrics(self, device_index: int = 0) -> Optional[NPUMetrics]:
        """Get NPU performance metrics"""
        if device_index >= len(self.devices):
            return None

        device = self.devices[device_index]

        # Try to read metrics from sysfs or driver interface
        metrics = NPUMetrics()

        # This would be populated by actual NPU driver metrics
        # For now, return placeholder structure
        return metrics

    def enable_ai_acceleration(self) -> bool:
        """Enable AI acceleration features"""
        success = True

        # Set all NPUs to performance mode
        for i, device in enumerate(self.devices):
            if device.status == NPUStatus.AVAILABLE:
                if not self.set_power_mode(NPUPowerMode.PERFORMANCE, i):
                    success = False

        # Enable Intel Thread Director AI hints (if available)
        itd_path = Path("/sys/kernel/debug/sched/itd_enable")
        if itd_path.exists():
            try:
                itd_path.write_text("1")
            except (PermissionError, IOError):
                pass

        return success

    def to_json(self) -> str:
        """Export NPU status as JSON"""
        return json.dumps(self.get_npu_status(), indent=2)


class IntelPowerManager:
    """
    Intel Power Management for Meteor Lake

    Manages CPU and NPU power states using RAPL and P-state drivers.
    """

    RAPL_PATH = Path("/sys/class/powercap/intel-rapl")
    PSTATE_PATH = Path("/sys/devices/system/cpu/intel_pstate")

    def __init__(self):
        self.rapl_available = self.RAPL_PATH.exists()
        self.pstate_available = self.PSTATE_PATH.exists()

    def get_power_domains(self) -> Dict:
        """Get all RAPL power domains"""
        domains = {}

        if not self.rapl_available:
            return domains

        for domain_path in self.RAPL_PATH.iterdir():
            if domain_path.is_dir() and domain_path.name.startswith("intel-rapl:"):
                name_path = domain_path / "name"
                if name_path.exists():
                    name = name_path.read_text().strip()
                    domains[name] = {
                        "path": str(domain_path),
                        "energy_uj": self._read_int(domain_path / "energy_uj"),
                        "max_energy_uj": self._read_int(domain_path / "max_energy_range_uj"),
                        "power_limit_uw": self._read_int(domain_path / "constraint_0_power_limit_uw"),
                        "max_power_uw": self._read_int(domain_path / "constraint_0_max_power_uw"),
                    }

        return domains

    def _read_int(self, path: Path) -> int:
        """Read integer from sysfs file"""
        try:
            if path.exists():
                return int(path.read_text().strip())
        except (ValueError, PermissionError, IOError):
            pass
        return 0

    def set_power_limit(self, domain: str, limit_watts: float) -> bool:
        """Set RAPL power limit for a domain"""
        for domain_path in self.RAPL_PATH.iterdir():
            name_path = domain_path / "name"
            if name_path.exists() and name_path.read_text().strip() == domain:
                limit_path = domain_path / "constraint_0_power_limit_uw"
                try:
                    limit_path.write_text(str(int(limit_watts * 1_000_000)))
                    return True
                except (PermissionError, IOError):
                    pass
        return False

    def get_cpu_frequency_info(self) -> Dict:
        """Get CPU frequency information"""
        info = {
            "min_freq_mhz": 0,
            "max_freq_mhz": 0,
            "current_freq_mhz": 0,
            "governor": "unknown"
        }

        cpu0_path = Path("/sys/devices/system/cpu/cpu0/cpufreq")
        if cpu0_path.exists():
            info["min_freq_mhz"] = self._read_int(cpu0_path / "scaling_min_freq") // 1000
            info["max_freq_mhz"] = self._read_int(cpu0_path / "scaling_max_freq") // 1000
            info["current_freq_mhz"] = self._read_int(cpu0_path / "scaling_cur_freq") // 1000

            gov_path = cpu0_path / "scaling_governor"
            if gov_path.exists():
                try:
                    info["governor"] = gov_path.read_text().strip()
                except:
                    pass

        return info

    def set_performance_profile(self, profile: str) -> bool:
        """
        Set system performance profile

        Profiles:
        - performance: Maximum performance, higher power
        - balanced: Balance between performance and power
        - powersave: Minimum power consumption
        """
        if not self.pstate_available:
            return False

        settings = {
            "performance": {"min_perf_pct": 80, "max_perf_pct": 100, "no_turbo": 0},
            "balanced": {"min_perf_pct": 30, "max_perf_pct": 100, "no_turbo": 0},
            "powersave": {"min_perf_pct": 10, "max_perf_pct": 60, "no_turbo": 1}
        }

        if profile not in settings:
            return False

        config = settings[profile]

        try:
            for key, value in config.items():
                path = self.PSTATE_PATH / key
                if path.exists():
                    path.write_text(str(value))
            return True
        except (PermissionError, IOError):
            return False


def main():
    """Main entry point for NPU manager CLI"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Intel NPU Manager for Meteor Lake"
    )
    parser.add_argument(
        "command",
        choices=["status", "detect", "power", "metrics", "enable-ai"],
        help="Command to execute"
    )
    parser.add_argument(
        "--power-mode",
        choices=["performance", "balanced", "powersave", "auto"],
        default="auto",
        help="Power mode for 'power' command"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    args = parser.parse_args()

    npu_manager = IntelNPUManager()
    power_manager = IntelPowerManager()

    if args.command == "status":
        status = npu_manager.get_npu_status()
        if args.json:
            print(json.dumps(status, indent=2))
        else:
            print("Intel NPU Status")
            print("=" * 40)
            print(f"Total devices: {status['total_devices']}")
            print(f"NPU Available: {status['available']}")
            for device in status['devices']:
                print(f"\n  Device: {device['name']}")
                print(f"    ID: {device['device_id']}")
                print(f"    Driver: {device['driver']}")
                print(f"    Status: {device['status']}")
                print(f"    Power Mode: {device['power_mode']}")
                if device.get('temperature'):
                    print(f"    Temperature: {device['temperature']:.1f}C")

    elif args.command == "detect":
        npu_manager._detect_npu_devices()
        print(f"Detected {len(npu_manager.devices)} NPU device(s)")

    elif args.command == "power":
        mode = NPUPowerMode(args.power_mode)
        if npu_manager.set_power_mode(mode):
            print(f"Power mode set to: {args.power_mode}")
        else:
            print("Failed to set power mode (may require root)")
            sys.exit(1)

    elif args.command == "metrics":
        metrics = npu_manager.get_metrics()
        if metrics:
            if args.json:
                print(json.dumps(asdict(metrics), indent=2))
            else:
                print("NPU Metrics")
                print(f"  Inference count: {metrics.inference_count}")
                print(f"  Latency: {metrics.inference_latency_ms:.2f}ms")
                print(f"  Throughput: {metrics.throughput_fps:.1f} FPS")

    elif args.command == "enable-ai":
        if npu_manager.enable_ai_acceleration():
            print("AI acceleration enabled")
        else:
            print("Failed to enable AI acceleration")
            sys.exit(1)


if __name__ == "__main__":
    main()
