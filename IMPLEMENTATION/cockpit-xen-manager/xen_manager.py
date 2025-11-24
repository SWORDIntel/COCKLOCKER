#!/usr/bin/env python3
"""
Xen Hypervisor Manager Backend for CockLocker
==============================================

Provides comprehensive Xen hypervisor management:
- VM lifecycle management (create, start, stop, pause, destroy)
- Resource monitoring and metrics
- Configuration management
- Live migration support
- Snapshot management

USAGE:
    python3 xen_manager.py <command> [options]

COMMANDS:
    list            List all domains
    info            Get hypervisor info
    create          Create a new VM
    start           Start a VM
    stop            Stop a VM
    pause           Pause a VM
    unpause         Resume a paused VM
    destroy         Forcefully destroy a VM
    migrate         Live migrate a VM
    snapshot        Create/restore snapshots
    metrics         Get VM metrics
"""

import os
import sys
import json
import subprocess
import shlex
import logging
import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from enum import Enum
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('xen_manager')


class VMState(Enum):
    """Xen domain states"""
    RUNNING = 'running'
    BLOCKED = 'blocked'
    PAUSED = 'paused'
    SHUTDOWN = 'shutdown'
    CRASHED = 'crashed'
    DYING = 'dying'
    UNKNOWN = 'unknown'


class VMType(Enum):
    """Xen VM types"""
    PV = 'pv'           # Paravirtualized
    HVM = 'hvm'         # Hardware Virtual Machine
    PVH = 'pvh'         # PV with HVM container


@dataclass
class XenDomain:
    """Represents a Xen domain (VM)"""
    name: str
    domid: int
    memory: int  # MB
    vcpus: int
    state: VMState
    cpu_time: float  # seconds
    uuid: Optional[str] = None
    vm_type: VMType = VMType.PV


@dataclass
class XenHostInfo:
    """Xen hypervisor host information"""
    xen_version: str
    xen_caps: str
    total_memory: int  # MB
    free_memory: int   # MB
    nr_cpus: int
    cores_per_socket: int
    threads_per_core: int
    scheduler: str
    xen_uptime: int    # seconds
    virt_caps: List[str]


@dataclass
class VMConfig:
    """VM configuration for creation"""
    name: str
    memory: int = 2048
    vcpus: int = 2
    vm_type: VMType = VMType.PV
    kernel: Optional[str] = None
    ramdisk: Optional[str] = None
    cmdline: Optional[str] = None
    disk: Optional[str] = None
    disk_size_gb: int = 20
    cdrom: Optional[str] = None
    network_bridge: str = 'xenbr0'
    vnc: bool = True
    vnc_listen: str = '0.0.0.0'
    autostart: bool = False
    extra_config: Optional[Dict] = None


class XenManager:
    """
    Xen Hypervisor Management Interface

    Provides a Python interface to the xl toolstack for managing
    Xen domains (VMs).
    """

    XL_PATH = '/usr/sbin/xl'
    CONFIG_DIR = Path('/etc/xen')
    IMAGE_DIR = Path('/var/lib/xen/images')

    def __init__(self):
        self.check_xen_available()

    def check_xen_available(self) -> bool:
        """Check if Xen and xl toolstack are available"""
        try:
            result = subprocess.run(
                ['xl', 'info'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _run_xl(self, args: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run xl command with arguments"""
        cmd = ['xl'] + args
        logger.debug(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if check and result.returncode != 0:
                raise XenError(f"xl {args[0]} failed: {result.stderr}")

            return result
        except subprocess.TimeoutExpired:
            raise XenError(f"xl {args[0]} timed out")

    def get_host_info(self) -> XenHostInfo:
        """Get Xen hypervisor information"""
        result = self._run_xl(['info'])
        info = {}

        for line in result.stdout.strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip()] = value.strip()

        return XenHostInfo(
            xen_version=info.get('xen_version', ''),
            xen_caps=info.get('xen_caps', ''),
            total_memory=int(info.get('total_memory', 0)),
            free_memory=int(info.get('free_memory', 0)),
            nr_cpus=int(info.get('nr_cpus', 0)),
            cores_per_socket=int(info.get('cores_per_socket', 0)),
            threads_per_core=int(info.get('threads_per_core', 0)),
            scheduler=info.get('xen_scheduler', ''),
            xen_uptime=int(info.get('xen_uptime', 0)),
            virt_caps=info.get('virt_caps', '').split()
        )

    def list_domains(self) -> List[XenDomain]:
        """List all Xen domains"""
        result = self._run_xl(['list'])
        domains = []

        lines = result.stdout.strip().split('\n')[1:]  # Skip header

        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                state_char = parts[4][0].lower() if parts[4] else 'r'
                state_map = {
                    'r': VMState.RUNNING,
                    'b': VMState.BLOCKED,
                    'p': VMState.PAUSED,
                    's': VMState.SHUTDOWN,
                    'c': VMState.CRASHED,
                    'd': VMState.DYING,
                    '-': VMState.RUNNING
                }

                domains.append(XenDomain(
                    name=parts[0],
                    domid=int(parts[1]),
                    memory=int(parts[2]),
                    vcpus=int(parts[3]),
                    state=state_map.get(state_char, VMState.UNKNOWN),
                    cpu_time=float(parts[5])
                ))

        return domains

    def get_domain(self, name: str) -> Optional[XenDomain]:
        """Get a specific domain by name"""
        for domain in self.list_domains():
            if domain.name == name:
                return domain
        return None

    def create_domain(self, config: VMConfig) -> bool:
        """Create and optionally start a new domain"""
        # Generate configuration file
        config_content = self._generate_config(config)
        config_path = self.CONFIG_DIR / f"{config.name}.cfg"

        # Write config file
        config_path.write_text(config_content)
        logger.info(f"Configuration written to {config_path}")

        # Create disk image if specified
        if config.disk:
            disk_path = Path(config.disk)
            if not disk_path.exists():
                self._create_disk_image(disk_path, config.disk_size_gb)

        # Start VM if autostart
        if config.autostart:
            return self.start_domain(config.name)

        return True

    def _generate_config(self, config: VMConfig) -> str:
        """Generate Xen domain configuration"""
        lines = [
            f'# Xen Domain Configuration: {config.name}',
            f'# Generated by CockLocker Xen Manager',
            '',
            f'name = "{config.name}"',
            f'memory = {config.memory}',
            f'vcpus = {config.vcpus}',
        ]

        # VM type specific settings
        if config.vm_type == VMType.HVM:
            lines.extend([
                'type = "hvm"',
                'builder = "hvm"',
            ])
            if config.cdrom:
                lines.append(f'cdrom = "{config.cdrom}"')
                lines.append('boot = "dc"')  # Boot from CD then disk
            if config.vnc:
                lines.append('vnc = 1')
                lines.append(f'vnclisten = "{config.vnc_listen}"')
                lines.append('vncpasswd = ""')
            lines.append('stdvga = 1')
            lines.append('serial = "pty"')
        elif config.vm_type == VMType.PVH:
            lines.append('type = "pvh"')
            if config.kernel:
                lines.append(f'kernel = "{config.kernel}"')
        else:  # PV
            lines.append('type = "pv"')
            if config.kernel:
                lines.append(f'kernel = "{config.kernel}"')
            if config.ramdisk:
                lines.append(f'ramdisk = "{config.ramdisk}"')
            if config.cmdline:
                lines.append(f'extra = "{config.cmdline}"')

        # Disk configuration
        if config.disk:
            disk_format = 'raw'
            if config.disk.endswith('.qcow2'):
                disk_format = 'qcow2'
            lines.append(f"disk = ['{config.disk},{disk_format},xvda,rw']")

        # Network configuration
        lines.append(f"vif = ['bridge={config.network_bridge}']")

        # Extra configuration
        if config.extra_config:
            for key, value in config.extra_config.items():
                if isinstance(value, str):
                    lines.append(f'{key} = "{value}"')
                elif isinstance(value, bool):
                    lines.append(f'{key} = {1 if value else 0}')
                else:
                    lines.append(f'{key} = {value}')

        return '\n'.join(lines) + '\n'

    def _create_disk_image(self, path: Path, size_gb: int) -> None:
        """Create a sparse disk image"""
        path.parent.mkdir(parents=True, exist_ok=True)

        # Use truncate for sparse file
        subprocess.run(
            ['truncate', '-s', f'{size_gb}G', str(path)],
            check=True
        )
        logger.info(f"Created disk image: {path} ({size_gb}GB)")

    def start_domain(self, name: str) -> bool:
        """Start a domain from configuration"""
        config_path = self.CONFIG_DIR / f"{name}.cfg"

        if not config_path.exists():
            raise XenError(f"Configuration not found: {config_path}")

        self._run_xl(['create', str(config_path)])
        logger.info(f"Domain {name} started")
        return True

    def shutdown_domain(self, name: str, force: bool = False) -> bool:
        """Shutdown a domain gracefully or forcefully"""
        cmd = ['shutdown']
        if force:
            cmd.append('-F')
        cmd.append(name)

        self._run_xl(cmd)
        logger.info(f"Domain {name} shutdown initiated")
        return True

    def destroy_domain(self, name: str) -> bool:
        """Forcefully destroy a domain"""
        self._run_xl(['destroy', name])
        logger.info(f"Domain {name} destroyed")
        return True

    def pause_domain(self, name: str) -> bool:
        """Pause a running domain"""
        self._run_xl(['pause', name])
        logger.info(f"Domain {name} paused")
        return True

    def unpause_domain(self, name: str) -> bool:
        """Unpause a paused domain"""
        self._run_xl(['unpause', name])
        logger.info(f"Domain {name} resumed")
        return True

    def reboot_domain(self, name: str) -> bool:
        """Reboot a domain"""
        self._run_xl(['reboot', name])
        logger.info(f"Domain {name} rebooting")
        return True

    def save_domain(self, name: str, save_file: str) -> bool:
        """Save domain state to file"""
        self._run_xl(['save', name, save_file])
        logger.info(f"Domain {name} saved to {save_file}")
        return True

    def restore_domain(self, save_file: str) -> bool:
        """Restore domain from saved state"""
        self._run_xl(['restore', save_file])
        logger.info(f"Domain restored from {save_file}")
        return True

    def migrate_domain(self, name: str, target_host: str, live: bool = True) -> bool:
        """Migrate domain to another host"""
        cmd = ['migrate']
        if live:
            cmd.append('-l')
        cmd.extend([name, target_host])

        self._run_xl(cmd, check=True)
        logger.info(f"Domain {name} migrated to {target_host}")
        return True

    def get_domain_console(self, name: str) -> str:
        """Get domain console output"""
        result = self._run_xl(['console', name], check=False)
        return result.stdout

    def set_domain_vcpus(self, name: str, vcpus: int) -> bool:
        """Set number of vCPUs for a domain"""
        self._run_xl(['vcpu-set', name, str(vcpus)])
        logger.info(f"Domain {name} vCPUs set to {vcpus}")
        return True

    def set_domain_memory(self, name: str, memory_mb: int) -> bool:
        """Set memory for a domain"""
        self._run_xl(['mem-set', name, str(memory_mb)])
        logger.info(f"Domain {name} memory set to {memory_mb}MB")
        return True

    def get_top_stats(self) -> str:
        """Get xentop-like statistics"""
        result = self._run_xl(['top', '-b', '-i', '1'])
        return result.stdout

    def get_dmesg(self) -> str:
        """Get Xen dmesg output"""
        result = self._run_xl(['dmesg'])
        return result.stdout

    def list_networks(self) -> List[str]:
        """List available network bridges"""
        result = subprocess.run(
            ['ip', 'link', 'show', 'type', 'bridge'],
            capture_output=True,
            text=True
        )
        bridges = []
        for line in result.stdout.split('\n'):
            match = re.match(r'\d+:\s+(\w+):', line)
            if match:
                bridges.append(match.group(1))
        return bridges

    def create_network_bridge(self, name: str = 'xenbr0', interface: str = 'eth0') -> bool:
        """Create a network bridge for Xen"""
        commands = [
            ['ip', 'link', 'add', 'name', name, 'type', 'bridge'],
            ['ip', 'link', 'set', interface, 'master', name],
            ['ip', 'link', 'set', name, 'up'],
            ['ip', 'link', 'set', interface, 'up'],
        ]

        for cmd in commands:
            subprocess.run(cmd, check=True)

        logger.info(f"Created bridge {name} with {interface}")
        return True

    def to_json(self, obj) -> str:
        """Convert object to JSON"""
        if hasattr(obj, '__dict__'):
            return json.dumps(asdict(obj), indent=2, default=str)
        elif isinstance(obj, list):
            return json.dumps([asdict(o) if hasattr(o, '__dict__') else o for o in obj],
                            indent=2, default=str)
        return json.dumps(obj, indent=2, default=str)


class XenError(Exception):
    """Xen operation error"""
    pass


def main():
    """CLI interface for Xen Manager"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Xen Hypervisor Manager for CockLocker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # List command
    subparsers.add_parser('list', help='List all domains')

    # Info command
    subparsers.add_parser('info', help='Get hypervisor info')

    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new VM')
    create_parser.add_argument('name', help='VM name')
    create_parser.add_argument('--memory', type=int, default=2048, help='Memory in MB')
    create_parser.add_argument('--vcpus', type=int, default=2, help='Number of vCPUs')
    create_parser.add_argument('--type', choices=['pv', 'hvm', 'pvh'], default='pv')
    create_parser.add_argument('--disk', help='Disk image path')
    create_parser.add_argument('--disk-size', type=int, default=20, help='Disk size in GB')
    create_parser.add_argument('--kernel', help='Kernel path (PV)')
    create_parser.add_argument('--cdrom', help='CDROM ISO path (HVM)')
    create_parser.add_argument('--bridge', default='xenbr0', help='Network bridge')
    create_parser.add_argument('--start', action='store_true', help='Start after creation')

    # Start command
    start_parser = subparsers.add_parser('start', help='Start a VM')
    start_parser.add_argument('name', help='VM name')

    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Stop a VM')
    stop_parser.add_argument('name', help='VM name')
    stop_parser.add_argument('--force', action='store_true', help='Force shutdown')

    # Pause command
    pause_parser = subparsers.add_parser('pause', help='Pause a VM')
    pause_parser.add_argument('name', help='VM name')

    # Unpause command
    unpause_parser = subparsers.add_parser('unpause', help='Unpause a VM')
    unpause_parser.add_argument('name', help='VM name')

    # Destroy command
    destroy_parser = subparsers.add_parser('destroy', help='Destroy a VM')
    destroy_parser.add_argument('name', help='VM name')

    # Migrate command
    migrate_parser = subparsers.add_parser('migrate', help='Migrate a VM')
    migrate_parser.add_argument('name', help='VM name')
    migrate_parser.add_argument('target', help='Target host')
    migrate_parser.add_argument('--no-live', action='store_true', help='Offline migration')

    # Metrics command
    subparsers.add_parser('metrics', help='Get VM metrics')

    # Dmesg command
    subparsers.add_parser('dmesg', help='Get Xen dmesg')

    # Common options
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        manager = XenManager()
    except Exception as e:
        print(f"Error: Xen hypervisor not available: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.command == 'list':
            domains = manager.list_domains()
            if args.json:
                print(manager.to_json(domains))
            else:
                print(f"{'Name':<20} {'ID':<6} {'Mem':<8} {'vCPUs':<6} {'State':<10} {'CPU Time':<10}")
                print('-' * 70)
                for d in domains:
                    print(f"{d.name:<20} {d.domid:<6} {d.memory:<8} {d.vcpus:<6} "
                          f"{d.state.value:<10} {d.cpu_time:<10.1f}")

        elif args.command == 'info':
            info = manager.get_host_info()
            if args.json:
                print(manager.to_json(info))
            else:
                print("Xen Hypervisor Information")
                print("=" * 40)
                print(f"Xen Version:     {info.xen_version}")
                print(f"CPUs:            {info.nr_cpus}")
                print(f"Total Memory:    {info.total_memory} MB")
                print(f"Free Memory:     {info.free_memory} MB")
                print(f"Scheduler:       {info.scheduler}")
                print(f"Uptime:          {info.xen_uptime} seconds")
                print(f"Capabilities:    {', '.join(info.virt_caps)}")

        elif args.command == 'create':
            vm_type = {'pv': VMType.PV, 'hvm': VMType.HVM, 'pvh': VMType.PVH}[args.type]
            config = VMConfig(
                name=args.name,
                memory=args.memory,
                vcpus=args.vcpus,
                vm_type=vm_type,
                disk=args.disk,
                disk_size_gb=args.disk_size,
                kernel=args.kernel,
                cdrom=args.cdrom,
                network_bridge=args.bridge,
                autostart=args.start
            )
            manager.create_domain(config)
            print(f"Domain '{args.name}' created" + (" and started" if args.start else ""))

        elif args.command == 'start':
            manager.start_domain(args.name)
            print(f"Domain '{args.name}' started")

        elif args.command == 'stop':
            manager.shutdown_domain(args.name, force=args.force)
            print(f"Domain '{args.name}' shutdown initiated")

        elif args.command == 'pause':
            manager.pause_domain(args.name)
            print(f"Domain '{args.name}' paused")

        elif args.command == 'unpause':
            manager.unpause_domain(args.name)
            print(f"Domain '{args.name}' resumed")

        elif args.command == 'destroy':
            manager.destroy_domain(args.name)
            print(f"Domain '{args.name}' destroyed")

        elif args.command == 'migrate':
            manager.migrate_domain(args.name, args.target, live=not args.no_live)
            print(f"Domain '{args.name}' migrated to {args.target}")

        elif args.command == 'metrics':
            print(manager.get_top_stats())

        elif args.command == 'dmesg':
            print(manager.get_dmesg())

        else:
            parser.print_help()
            sys.exit(1)

    except XenError as e:
        print(f"Xen Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
