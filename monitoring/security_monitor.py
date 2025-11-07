#!/usr/bin/env python3
"""
CockLocker Security Monitor
Real-time threat detection and response for hardened Cockpit
Inspired by ImageHarden's monitoring approach
"""

import os
import re
import sys
import time
import json
import signal
import logging
import threading
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Set, Optional
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/cockpit-hardened/security_monitor.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('CockLocker-Monitor')


class ThreatDetector:
    """APT-level threat detection engine"""

    def __init__(self):
        self.failed_logins: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.suspicious_ips: Set[str] = set()
        self.connection_rates: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.blocked_ips: Set[str] = set()

        # APT indicators
        self.apt_patterns = [
            # Command injection attempts
            (re.compile(r'[;&|`$()]'), 'Command injection attempt'),
            (re.compile(r'\.\./'), 'Directory traversal attempt'),

            # SQL injection patterns
            (re.compile(r"('|(--)|;|\*|xp_|sp_)", re.IGNORECASE), 'SQL injection attempt'),

            # XSS patterns
            (re.compile(r'<script|javascript:|onerror=|onload=', re.IGNORECASE), 'XSS attempt'),

            # Privilege escalation attempts
            (re.compile(r'sudo|su\s|pkexec|polkit', re.IGNORECASE), 'Privilege escalation attempt'),

            # Credential harvesting
            (re.compile(r'/etc/(passwd|shadow)|authorized_keys'), 'Credential harvesting attempt'),

            # Known APT tools
            (re.compile(r'metasploit|meterpreter|cobalt.*strike|mimikatz', re.IGNORECASE), 'APT tool detected'),

            # Reverse shells
            (re.compile(r'nc\s+-.*e|/dev/tcp|bash\s+-i', re.IGNORECASE), 'Reverse shell attempt'),
        ]

        logger.info("ThreatDetector initialized with APT-level detection patterns")

    def analyze_log_entry(self, log_line: str, source_ip: Optional[str] = None) -> Optional[Dict]:
        """Analyze log entry for threats"""

        for pattern, threat_type in self.apt_patterns:
            if pattern.search(log_line):
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'threat_type': threat_type,
                    'severity': 'CRITICAL',
                    'source_ip': source_ip,
                    'log_entry': log_line,
                    'action': 'blocked'
                }
                logger.critical(f"THREAT DETECTED: {threat_type} from {source_ip}")
                return alert

        return None

    def check_brute_force(self, ip: str) -> bool:
        """Detect brute force attacks"""
        now = time.time()
        self.failed_logins[ip].append(now)

        # Check for more than 5 failed attempts in 5 minutes
        recent_failures = [t for t in self.failed_logins[ip] if now - t < 300]

        if len(recent_failures) > 5:
            if ip not in self.blocked_ips:
                logger.critical(f"BRUTE FORCE DETECTED from {ip} - BLOCKING")
                self.blocked_ips.add(ip)
                self.block_ip(ip)
            return True

        return False

    def check_connection_rate(self, ip: str) -> bool:
        """Detect connection flooding (DoS)"""
        now = time.time()
        self.connection_rates[ip].append(now)

        # Check for more than 50 connections in 10 seconds
        recent_connections = [t for t in self.connection_rates[ip] if now - t < 10]

        if len(recent_connections) > 50:
            if ip not in self.blocked_ips:
                logger.critical(f"CONNECTION FLOOD DETECTED from {ip} - BLOCKING")
                self.blocked_ips.add(ip)
                self.block_ip(ip)
            return True

        return False

    def block_ip(self, ip: str):
        """Block malicious IP using iptables"""
        try:
            if ':' in ip:
                # IPv6
                subprocess.run(['ip6tables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                             check=True, capture_output=True)
            else:
                # IPv4
                subprocess.run(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                             check=True, capture_output=True)

            logger.info(f"Successfully blocked IP: {ip}")

            # Log to incident file
            with open('/var/log/cockpit-hardened/incidents.log', 'a') as f:
                f.write(f"{datetime.now().isoformat()} - BLOCKED IP: {ip}\n")

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip}: {e}")


class LogMonitor:
    """Monitor Cockpit logs for security events"""

    def __init__(self, detector: ThreatDetector):
        self.detector = detector
        self.log_files = [
            '/var/log/cockpit-hardened/access.log',
            '/var/log/cockpit-hardened/error.log',
            '/var/log/cockpit-hardened/auth.log',
            '/var/log/auth.log',
            '/var/log/syslog',
        ]
        self.running = False

    def extract_ip(self, log_line: str) -> Optional[str]:
        """Extract IP address from log line"""
        # Match IPv4
        ipv4_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_line)
        if ipv4_match:
            return ipv4_match.group(0)

        # Match IPv6
        ipv6_match = re.search(r'\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b', log_line)
        if ipv6_match:
            return ipv6_match.group(0)

        return None

    def monitor_file(self, filepath: Path):
        """Monitor a single log file"""
        if not filepath.exists():
            logger.warning(f"Log file not found: {filepath}")
            return

        logger.info(f"Monitoring: {filepath}")

        try:
            with open(filepath, 'r') as f:
                # Seek to end of file
                f.seek(0, 2)

                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue

                    # Extract IP and analyze
                    source_ip = self.extract_ip(line)

                    # Check for authentication failures
                    if 'authentication failure' in line.lower() or 'failed password' in line.lower():
                        if source_ip:
                            self.detector.check_brute_force(source_ip)

                    # Check for suspicious patterns
                    alert = self.detector.analyze_log_entry(line, source_ip)
                    if alert:
                        self.handle_alert(alert)

                    # Check connection rate
                    if 'connection from' in line.lower() and source_ip:
                        self.detector.check_connection_rate(source_ip)

        except Exception as e:
            logger.error(f"Error monitoring {filepath}: {e}")

    def handle_alert(self, alert: Dict):
        """Handle security alert"""
        logger.critical(f"SECURITY ALERT: {json.dumps(alert, indent=2)}")

        # Write to alerts file
        alerts_file = Path('/var/log/cockpit-hardened/alerts.json')
        try:
            existing_alerts = []
            if alerts_file.exists():
                with open(alerts_file, 'r') as f:
                    existing_alerts = json.load(f)

            existing_alerts.append(alert)

            with open(alerts_file, 'w') as f:
                json.dump(existing_alerts, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to write alert: {e}")

        # Block source IP if present
        if alert.get('source_ip'):
            self.detector.block_ip(alert['source_ip'])

    def start(self):
        """Start monitoring all log files"""
        self.running = True
        threads = []

        for log_file in self.log_files:
            path = Path(log_file)
            thread = threading.Thread(target=self.monitor_file, args=(path,))
            thread.daemon = True
            thread.start()
            threads.append(thread)

        logger.info(f"Log monitoring started for {len(threads)} files")

        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down log monitor...")
            self.running = False

        for thread in threads:
            thread.join(timeout=5)


class SystemMonitor:
    """Monitor system resources and detect anomalies"""

    def __init__(self):
        self.baseline_cpu = 0.0
        self.baseline_memory = 0.0
        self.running = False

    def get_cockpit_processes(self) -> List[Dict]:
        """Get all Cockpit-related processes"""
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                check=True
            )

            processes = []
            for line in result.stdout.split('\n'):
                if 'cockpit' in line.lower():
                    parts = line.split()
                    if len(parts) >= 11:
                        processes.append({
                            'user': parts[0],
                            'pid': parts[1],
                            'cpu': float(parts[2]),
                            'mem': float(parts[3]),
                            'command': ' '.join(parts[10:])
                        })

            return processes

        except Exception as e:
            logger.error(f"Failed to get processes: {e}")
            return []

    def check_resource_anomalies(self):
        """Detect resource usage anomalies"""
        processes = self.get_cockpit_processes()

        for proc in processes:
            # Check for excessive CPU usage
            if proc['cpu'] > 80.0:
                logger.warning(f"HIGH CPU usage detected: {proc['command']} using {proc['cpu']}%")

            # Check for excessive memory usage
            if proc['mem'] > 50.0:
                logger.warning(f"HIGH MEMORY usage detected: {proc['command']} using {proc['mem']}%")

    def monitor(self):
        """Start system monitoring"""
        self.running = True
        logger.info("System monitoring started")

        while self.running:
            try:
                self.check_resource_anomalies()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"System monitoring error: {e}")

    def start(self):
        """Start monitoring in background thread"""
        thread = threading.Thread(target=self.monitor)
        thread.daemon = True
        thread.start()


def main():
    """Main entry point"""
    logger.info("=" * 60)
    logger.info("CockLocker Security Monitor - APT-level Threat Detection")
    logger.info("=" * 60)

    # Check if running as root
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        sys.exit(1)

    # Create log directory
    log_dir = Path('/var/log/cockpit-hardened')
    log_dir.mkdir(parents=True, exist_ok=True)

    # Initialize components
    detector = ThreatDetector()
    log_monitor = LogMonitor(detector)
    system_monitor = SystemMonitor()

    # Setup signal handlers
    def signal_handler(sig, frame):
        logger.info("Received shutdown signal")
        log_monitor.running = False
        system_monitor.running = False
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start monitoring
    system_monitor.start()
    log_monitor.start()


if __name__ == '__main__':
    main()
