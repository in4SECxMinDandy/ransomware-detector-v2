"""
network_monitor.py
==================
Task 6: Network Traffic Analysis (v2.4).

Analyzes network traffic for C2 beacon patterns and DGA domains.
Features:
  - Monitor process connections
  - Detect DGA domains using entropy analysis
  - Detect C2 beacon patterns
  - Check against offline threat intelligence (Feodo blocklist)

Usage:
    analyzer = NetworkAnalyzer()
    connections = analyzer.monitor_process_connections(pid)
"""

import os
import json
import socket
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import defaultdict

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

import numpy as np

logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    """
    Network Traffic Analyzer for ransomware detection.
    Monitors network connections and detects C2 indicators.
    """

    FEODO_BLOCKLIST = "data/threat_intel/feodo_ips.json"
    DGA_ENTROPY_THRESHOLD = 3.5
    BEACON_COVARIANCE_MAX = 0.10

    # Common legitimate ports (we care about rare ports)
    COMMON_PORTS = {80, 443, 8080, 53, 22, 21, 25, 110, 143, 993, 995}

    # C2 Detection Heuristics
    C2_INDICATORS = {
        "dga_domain": "Domain entropy >= 3.5",
        "beacon_pattern": "Regular interval connections (CoV < 0.10)",
        "rare_port": "Outbound to port not in common_ports",
        "known_bad_ip": "IP in Feodo/abuse.ch blocklist",
    }

    def __init__(self):
        """Initialize NetworkAnalyzer."""
        self._threat_intel = self._load_threat_intel()
        self._connection_history: Dict[int, List[Dict]] = defaultdict(list)
        self._monitored_pids: set = set()

    def _load_threat_intel(self) -> set:
        """Load offline threat intelligence blocklist."""
        if not os.path.exists(self.FEODO_BLOCKLIST):
            logger.warning(f"Threat intel file not found: {self.FEODO_BLOCKLIST}")
            return set()

        try:
            with open(self.FEODO_BLOCKLIST, "r") as f:
                data = json.load(f)
                ips = data.get("ips", [])
                logger.info(f"Loaded {len(ips)} threat intel IPs")
                return set(ips)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load threat intel: {e}")
            return set()

    def monitor_process_connections(self, pid: int) -> List[Dict[str, Any]]:
        """
        Monitor all connections for a specific PID.

        Args:
            pid: Process ID to monitor

        Returns:
            List of connection dictionaries
        """
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available - cannot monitor connections")
            return []

        connections = []

        try:
            proc = psutil.Process(pid)
            for conn in proc.connections():
                try:
                    remote_addr = conn.raddr
                    if remote_addr:
                        conn_info = {
                            "pid": pid,
                            "process_name": proc.name(),
                            "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                            "remote_addr": f"{remote_addr.ip}:{remote_addr.port}",
                            "remote_ip": remote_addr.ip,
                            "remote_port": remote_addr.port,
                            "status": conn.status,
                            "family": str(conn.family),
                            "type": str(conn.type),
                            "timestamp": datetime.now().isoformat(),
                        }
                        connections.append(conn_info)

                        # Record for beacon detection
                        self._record_connection(pid, conn_info)

                except Exception as e:
                    logger.warning(f"Error processing connection: {e}")

        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
        except psutil.AccessDenied:
            logger.error(f"Access denied for process {pid}")
        except Exception as e:
            logger.error(f"Error monitoring connections for {pid}: {e}")

        return connections

    def _record_connection(self, pid: int, conn_info: Dict[str, Any]):
        """Record connection for beacon detection."""
        self._connection_history[pid].append({
            "remote_ip": conn_info.get("remote_ip"),
            "remote_port": conn_info.get("remote_port"),
            "timestamp": datetime.now(),
        })

        # Keep only last 100 connections per PID
        if len(self._connection_history[pid]) > 100:
            self._connection_history[pid] = self._connection_history[pid][-100:]

    def detect_dga_domain(self, domain: str) -> bool:
        """
        Detect DGA (Domain Generation Algorithm) domains.
        Uses Shannon entropy of domain label.

        Args:
            domain: Domain name to check

        Returns:
            True if likely DGA domain
        """
        if not domain:
            return False

        # Remove TLD
        parts = domain.split(".")
        if len(parts) < 2:
            return False

        label = parts[-2]  # Use the main label before TLD

        # Calculate Shannon entropy
        entropy = self._calculate_entropy(label)

        if entropy >= self.DGA_ENTROPY_THRESHOLD:
            logger.warning(f"DGA domain detected: {domain} (entropy={entropy:.2f})")
            return True

        return False

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        arr = np.frombuffer(text.lower().encode(), dtype=np.uint8)
        freq = np.bincount(arr, minlength=256)
        prob = freq[freq > 0] / len(arr)
        entropy = -np.sum(prob * np.log2(prob))
        # Normalize: divide by log2(256) = 8 (max entropy for byte text)
        normalized = entropy / 8.0
        return normalized

    def detect_beacon(self, connection_timestamps: List[float]) -> bool:
        """
        Detect C2 beacon patterns.
        Checks for regular interval connections (low coefficient of variation).

        Args:
            connection_timestamps: List of connection timestamps (as Unix timestamps)

        Returns:
            True if beacon pattern detected
        """
        if len(connection_timestamps) < 3:
            return False

        # Calculate intervals between connections
        intervals = []
        for i in range(1, len(connection_timestamps)):
            interval = connection_timestamps[i] - connection_timestamps[i-1]
            intervals.append(interval)

        if not intervals:
            return False

        # Calculate mean and standard deviation
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval == 0:
            return False

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5

        # Calculate coefficient of variation
        covariance = std_dev / mean_interval

        if covariance < self.BEACON_COVARIANCE_MAX:
            logger.warning(f"Beacon pattern detected (CoV={covariance:.4f})")
            return True

        return False

    def check_threat_intel(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Check IP against offline blocklist.

        Args:
            ip: IP address to check

        Returns:
            Match info dict or None if not found
        """
        if not ip:
            return None

        if ip in self._threat_intel:
            logger.warning(f"Known malicious IP detected: {ip}")
            return {
                "ip": ip,
                "source": "Feodo Tracker",
                "timestamp": datetime.now().isoformat(),
            }

        return None

    def analyze_connections(self, connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze a list of connections for C2 indicators.

        Args:
            connections: List of connection dictionaries

        Returns:
            Analysis results with indicators
        """
        indicators = []
        suspicious_connections = []

        for conn in connections:
            ip = conn.get("remote_ip", "")
            port = conn.get("remote_port", 0)
            domain = self._resolve_ip_to_domain(ip) if ip else ""

            # Check indicators
            if self.check_threat_intel(ip):
                indicators.append({
                    "type": "known_bad_ip",
                    "description": f"IP in blocklist: {ip}",
                    "connection": conn,
                })
                suspicious_connections.append(conn)
                continue

            # Check rare ports
            if port not in self.COMMON_PORTS:
                indicators.append({
                    "type": "rare_port",
                    "description": f"Rare port {port} to {ip}",
                    "connection": conn,
                })

            # Check DGA domains
            if domain and self.detect_dga_domain(domain):
                indicators.append({
                    "type": "dga_domain",
                    "description": f"DGA domain: {domain}",
                    "connection": conn,
                })
                suspicious_connections.append(conn)

        # Check for beacon patterns
        pid_connections = self._connection_history.get(connections[0].get("pid", 0), [])
        if len(pid_connections) >= 3:
            timestamps = [c["timestamp"] for c in pid_connections if isinstance(c["timestamp"], datetime)]
            if self.detect_beacon([t.timestamp() for t in timestamps]):
                indicators.append({
                    "type": "beacon_pattern",
                    "description": "Regular connection intervals detected",
                    "connection": None,
                })

        return {
            "total_connections": len(connections),
            "suspicious_connections": len(suspicious_connections),
            "indicators": indicators,
            "risk_level": self._calculate_risk_level(indicators),
        }

    def _resolve_ip_to_domain(self, ip: str) -> Optional[str]:
        """Resolve IP to domain name (reverse DNS)."""
        if not ip:
            return None
        try:
            domain, _, _ = socket.gethostbyaddr(ip)
            return domain
        except (socket.herror, socket.gaierror, OSError):
            return None
        except Exception:
            return None

    def _calculate_risk_level(self, indicators: List[Dict]) -> str:
        """Calculate risk level based on indicators."""
        if not indicators:
            return "SAFE"

        indicator_types = [i["type"] for i in indicators]

        if "known_bad_ip" in indicator_types or "dga_domain" in indicator_types:
            return "CRITICAL"
        elif "beacon_pattern" in indicator_types:
            return "HIGH"
        elif "rare_port" in indicator_types:
            return "MEDIUM"
        else:
            return "LOW"

    def get_all_connections(self) -> List[Dict[str, Any]]:
        """Get all network connections on the system."""
        if not PSUTIL_AVAILABLE:
            return []

        connections = []

        try:
            for conn in psutil.net_connections():
                try:
                    if conn.raddr:
                        conn_info = {
                            "pid": conn.pid,
                            "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                            "remote_ip": conn.raddr.ip,
                            "remote_port": conn.raddr.port,
                            "status": conn.status,
                            "family": str(conn.family),
                            "type": str(conn.type),
                        }
                        connections.append(conn_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as e:
            logger.error("Error getting all connections: %s", e)

        return connections

    def get_connection_summary(self) -> Dict[str, Any]:
        """Get summary of all monitored connections."""
        summary = {
            "monitored_pids": len(self._monitored_pids),
            "total_connections": sum(len(v) for v in self._connection_history.values()),
            "unique_ips": len(set(
                c["remote_ip"]
                for conns in self._connection_history.values()
                for c in conns
                if c.get("remote_ip")
            )),
        }
        return summary


def create_default_feodo_blocklist():
    """Create a default empty Feodo blocklist file."""
    data = {
        "updated": datetime.now().strftime("%Y-%m-%d"),
        "source": "abuse.ch Feodo Tracker",
        "description": "Offline blocklist for known C2 IPs",
        "ips": [],
    }

    os.makedirs(os.path.dirname(NetworkAnalyzer.FEODO_BLOCKLIST), exist_ok=True)

    with open(NetworkAnalyzer.FEODO_BLOCKLIST, "w") as f:
        json.dump(data, f, indent=2)

    logger.info(f"Created default blocklist at: {NetworkAnalyzer.FEODO_BLOCKLIST}")
