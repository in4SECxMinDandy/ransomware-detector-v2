"""
process_monitor.py
==================
Process Behavior Detection Module cho ransomware detection.

Chức năng:
  - Theo dõi process đang truy cập file
  - Phát hiện patterns bất thường:
    - Mass file encryption (nhiều file bị mã hóa cùng lúc)
    - Extension changes (.doc → .locked, .encrypted...)
    - Rapid file operations (tần suất ghi file cao bất thường)
    - Suspicious process behavior (process không known benign)

Yêu cầu:
  - psutil: lấy thông tin process
  - pywin32: Windows API cho process monitoring (Windows only)

Detection Patterns:
  1. ENCRYPTION_BURST: > 10 files modified trong 30 giây bởi cùng process
  2. EXTENSION_CHANGE: file extension thay đổi sang suspicious extensions
  3. RAPID_OPS: > 5 files/second được tạo/sửa
  4. SUSPICIOUS_PROCESS: process không known benign programs
"""

import os
import time
import threading
import collections
import logging
from typing import Dict, List, Optional, Callable, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Setup logger
logger = logging.getLogger(__name__)

# Suspicious file extensions (ransomware thường đổi sang extensions này)
SUSPICIOUS_EXTENSIONS = {
    ".locked", ".locky", ".crypt", ".crypted", ".enc", ".encrypted",
    ".crypto", ".zepto", ".cerber", ".ryuk", ".conti", ".revil",
    ".lockbit", ".blackcat", ".alphv", ".wncry", ".wallet", ".key",
    ".cryptor", ".crypt1", ".encrypted", ".locked1", ".lock",
    ".encode", ".encr", ".encryptedRSA", ".encryted", ".cryp",
    ".crypz", ".crypt32", ".cryptz", ".encrypted AES256",
    ".haque", ".akira", ".bianlian", "medusa", ".cl0p", ".play",
    ".rhysida", ".qilin", ".8lock8", ".neo", ".makop", ".suncrypt",
}

# Known benign programs - các process này thường tạo/modify file an toàn
KNOWN_BENIGN_PROCESSES = {
    # Editors
    "notepad.exe", "code.exe", "devenv.exe", "sublime_text.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "notepad++.exe", "atom.exe", "vim.exe", "nano.exe",
    # Browsers
    "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe",
    # System
    "explorer.exe", "cmd.exe", "powershell.exe", "conhost.exe",
    "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
    # IDEs
    "pycharm64.exe", "rider64.exe", "webstorm64.exe", "idea64.exe",
    # Download/Compression
    "winrar.exe", "7z.exe", "7zFM.exe", "7zG.exe",
    "download.exe", "internet download manager.exe", "idman.exe",
    # Media
    "vlc.exe", "wmplayer.exe", "foobar2000.exe", "spotify.exe",
    # Others
    "git.exe", "python.exe", "pythonw.exe", "java.exe", "node.exe",
}

# Known file extensions (không phải ransomware)
KNOWN_EXTENSIONS = {
    ".doc", ".docx", ".pdf", ".txt", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".html", ".css", ".js", ".ts", ".py", ".java", ".cpp", ".c", ".h",
    ".exe", ".dll", ".sys", ".msi",
    ".json", ".xml", ".yaml", ".yml", ".toml",
    ".sql", ".db", ".sqlite",
}

# Dynamic Behavior Detection Thresholds (Task 1)
RENAME_BURST_THRESHOLD = 5
RENAME_BURST_WINDOW = 10  # seconds
MASS_IO_THRESHOLD_MBPS = 50
MASS_IO_DURATION = 5  # seconds


class BehaviorType(Enum):
    """Loại behavior đáng ngờ."""
    ENCRYPTION_BURST = "encryption_burst"      # Nhiều file bị mã hóa nhanh
    EXTENSION_CHANGE = "extension_change"      # Đổi extension sang suspicious
    RAPID_OPS = "rapid_ops"                    # Tần suất thao tác file cao bất thường
    SUSPICIOUS_PROCESS = "suspicious_process" # Process không known benign
    HIGH_ENTROPY_WRITE = "high_entropy_write"  # Ghi file có entropy cao
    FILE_RENAME_BURST = "file_rename_burst"   # Task 1: Nhiều file rename nhanh
    MASS_IO_ANOMALY = "mass_io_anomaly"       # Task 1: IO rate cao bất thường


@dataclass
class ProcessInfo:
    """Thông tin về một process."""
    pid: int
    name: str
    path: str = ""
    command_line: str = ""
    started: Optional[datetime] = None
    is_system: bool = False
    is_benign: bool = False


@dataclass
class FileEvent:
    """Sự kiện file."""
    path: str
    event_type: str  # "created", "modified", "renamed"
    timestamp: datetime
    pid: Optional[int] = None
    process_name: str = ""
    old_path: str = ""  # Cho renamed events
    entropy: float = 0.0
    size: int = 0


@dataclass
class BehaviorAlert:
    """Alert về behavior đáng ngờ."""
    behavior_type: BehaviorType
    process: ProcessInfo
    files: List[str]
    timestamp: datetime
    severity: str  # "low", "medium", "high", "critical"
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "behavior_type": self.behavior_type.value,
            "process_name": self.process.name,
            "process_pid": self.process.pid,
            "process_path": self.process.path,
            "files": self.files,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "description": self.description,
            "file_count": len(self.files),
        }


class ProcessMonitor:
    """
    Monitor process behavior để phát hiện ransomware activity.

    Usage:
        monitor = ProcessMonitor()
        monitor.on_behavior = lambda alert: print(f"ALERT: {alert.description}")
        monitor.start()
        ...
        monitor.stop()
    """

    def __init__(self):
        self._running = False
        self._lock = threading.Lock()

        # File events buffer per process
        self._process_events: Dict[int, List[FileEvent]] = collections.defaultdict(list)
        self._all_events: List[FileEvent] = []

        # Extension change tracking
        self._extension_changes: Dict[str, str] = {}  # old_path -> new_path

        # Rename burst tracking (Task 1)
        self._rename_events: Dict[int, List[FileEvent]] = collections.defaultdict(list)

        # IO tracking for MASS_IO_ANOMALY (Task 1)
        self._io_samples: Dict[int, List[Dict[str, Any]]] = collections.defaultdict(list)
        self._last_io_counters: Dict[int, Dict[str, int]] = {}
        self._last_io_time: Dict[int, float] = {}

        # Alerts
        self.alerts: List[BehaviorAlert] = []

        # Statistics
        self.total_events = 0
        self.total_alerts = 0

        # Callbacks
        self.on_behavior: Optional[Callable[[BehaviorAlert], None]] = None
        self.on_process_detected: Optional[Callable[[ProcessInfo, FileEvent], None]] = None

        # Thresholds
        self.encryption_burst_threshold = 10  # files trong 30s
        self.encryption_burst_window = 30  # seconds
        self.rapid_ops_threshold = 5  # files/second
        self.rapid_ops_window = 10  # seconds

        # Dynamic behavior thresholds (Task 1)
        self.rename_burst_threshold = RENAME_BURST_THRESHOLD
        self.rename_burst_window = RENAME_BURST_WINDOW
        self.mass_io_threshold_mbps = MASS_IO_THRESHOLD_MBPS
        self.mass_io_duration = MASS_IO_DURATION

        # Dynamic Signal Aggregator (Task 1)
        self._signal_aggregator = DynamicSignalAggregator()

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self):
        """Bắt đầu monitor."""
        self._running = True
        self._process_events.clear()
        self._all_events.clear()
        self.alerts.clear()
        self.total_events = 0
        self.total_alerts = 0

    def stop(self):
        """Dừng monitor."""
        self._running = False

    def record_event(self, event: FileEvent):
        """
        Ghi nhận một file event.
        Gọi từ watchdog callback hoặc watchdog_monitor.
        """
        if not self._running:
            return

        with self._lock:
            self.total_events += 1
            self._all_events.append(event)

            # Lấy thông tin process
            process = self._get_process_info(event.pid) if event.pid else None

            if event.event_type == "renamed":
                # Track extension changes
                self._track_extension_change(event)
                # Task 1: Track rename events for FILE_RENAME_BURST detection
                self._track_rename_event(event)

            # Lưu event theo process
            if event.pid:
                self._process_events[event.pid].append(event)

            # Check for behaviors
            if process:
                self._check_encryption_burst(process)
                self._check_rapid_ops(process)
                self._check_suspicious_process(process, event)
                # Task 1: Check for dynamic behavior patterns
                self._check_file_rename_burst(process)
                self._check_mass_io_anomaly(process)
                self._check_high_entropy_write(process, event)

                if self.on_process_detected:
                    self.on_process_detected(process, event)

    def _get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Lấy thông tin process từ PID."""
        if not PSUTIL_AVAILABLE or pid is None:
            return None

        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()

            try:
                exe_path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                exe_path = ""
            except OSError:
                exe_path = ""

            try:
                cmdline = proc.cmdline()
                cmd_str = " ".join(cmdline) if cmdline else ""
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                cmd_str = ""
            except OSError:
                cmd_str = ""

            try:
                ppid = proc.ppid()
                is_system = ppid == 0 or name in ("system", "smss.exe")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                is_system = False

            info = ProcessInfo(
                pid=pid,
                name=name,
                path=exe_path,
                command_line=cmd_str,
                is_system=is_system,
                is_benign=name.lower() in KNOWN_BENIGN_PROCESSES,
            )

            try:
                info.started = datetime.fromtimestamp(proc.create_time())
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                info.started = None
            except ValueError:
                info.started = None

            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception:
            return None

    def _track_extension_change(self, event: FileEvent):
        """Theo dõi thay đổi extension."""
        if event.old_path and event.path:
            old_ext = os.path.splitext(event.old_path)[1].lower()
            new_ext = os.path.splitext(event.path)[1].lower()

            # Nếu đổi sang suspicious extension
            if new_ext in SUSPICIOUS_EXTENSIONS:
                self._create_alert(
                    behavior_type=BehaviorType.EXTENSION_CHANGE,
                    process=ProcessInfo(pid=event.pid or 0, name=event.process_name),
                    files=[event.old_path, event.path],
                    severity="critical",
                    description=f"Suspicious extension change: {old_ext} → {new_ext}",
                    metadata={"old_extension": old_ext, "new_extension": new_ext}
                )

    def _check_encryption_burst(self, process: ProcessInfo):
        """Phát hiện burst of encryption (nhiều file bị mã hóa nhanh)."""
        if process.is_benign or process.is_system:
            return

        events = self._process_events.get(process.pid, [])
        if len(events) < self.encryption_burst_threshold:
            return

        # Lọc các events trong window
        now = datetime.now()
        window_start = now - timedelta(seconds=self.encryption_burst_window)
        recent_events = [e for e in events if e.timestamp > window_start]

        if len(recent_events) >= self.encryption_burst_threshold:
            # Check if files have high entropy (encrypted)
            high_entropy_files = [e.path for e in recent_events if e.entropy > 7.0]

            if len(high_entropy_files) >= self.encryption_burst_threshold // 2:
                self._create_alert(
                    behavior_type=BehaviorType.ENCRYPTION_BURST,
                    process=process,
                    files=[e.path for e in recent_events[:20]],  # Limit to 20
                    severity="critical",
                    description=f"Mass encryption detected: {len(recent_events)} files trong {self.encryption_burst_window}s",
                    metadata={
                        "file_count": len(recent_events),
                        "window_seconds": self.encryption_burst_window,
                        "high_entropy_count": len(high_entropy_files)
                    }
                )

    def _check_rapid_ops(self, process: ProcessInfo):
        """Phát hiện rapid file operations."""
        if process.is_benign or process.is_system:
            return

        events = self._process_events.get(process.pid, [])
        if len(events) < self.rapid_ops_threshold:
            return

        now = datetime.now()
        window_start = now - timedelta(seconds=self.rapid_ops_window)
        recent_events = [e for e in events if e.timestamp > window_start]

        ops_per_second = len(recent_events) / self.rapid_ops_window

        if ops_per_second >= self.rapid_ops_threshold:
            self._create_alert(
                behavior_type=BehaviorType.RAPID_OPS,
                process=process,
                files=[e.path for e in recent_events[:10]],
                severity="high",
                description=f"Rapid file operations: {ops_per_second:.1f} files/second",
                metadata={
                    "ops_per_second": round(ops_per_second, 2),
                    "window_seconds": self.rapid_ops_window,
                }
            )

    def _check_suspicious_process(self, process: ProcessInfo, event: FileEvent):
        """Phát hiện suspicious process."""
        if process.is_benign or process.is_system:
            return

        # Check if process path is suspicious
        suspicious_paths = ["temp", "appdata\\local\\temp", "downloads"]
        path_lower = process.path.lower()

        if any(s in path_lower for s in suspicious_paths):
            # Process chạy từ temp/downloads - có thể là malware
            if event.entropy > 7.0:  # Và đang ghi file entropy cao
                self._create_alert(
                    behavior_type=BehaviorType.SUSPICIOUS_PROCESS,
                    process=process,
                    files=[event.path],
                    severity="high",
                    description=f"Suspicious process from temp: {process.name}",
                    metadata={
                        "process_path": process.path,
                        "command_line": process.command_line,
                    }
                )

    def _check_high_entropy_write(self, process: ProcessInfo, event: FileEvent):
        """Phát hiện ghi file có entropy cao."""
        if process.is_benign or process.is_system:
            return

        if event.entropy >= 7.5:
            self._create_alert(
                behavior_type=BehaviorType.HIGH_ENTROPY_WRITE,
                process=process,
                files=[event.path],
                severity="medium",
                description=f"High entropy file write: {event.entropy:.2f}",
                metadata={
                    "entropy": event.entropy,
                    "file_size": event.size,
                }
            )

    def _track_rename_event(self, event: FileEvent):
        """Task 1: Track rename events for FILE_RENAME_BURST detection."""
        if event.pid and event.event_type == "renamed":
            self._rename_events[event.pid].append(event)

    def _check_file_rename_burst(self, process: ProcessInfo):
        """
        Task 1: Phát hiện FILE_RENAME_BURST pattern.
        Trigger: >= 5 files renamed within 10 seconds by same PID.
        """
        if process.is_benign or process.is_system:
            return

        rename_events = self._rename_events.get(process.pid, [])
        if len(rename_events) < self.rename_burst_threshold:
            return

        # Lọc các events trong window
        now = datetime.now()
        window_start = now - timedelta(seconds=self.rename_burst_window)
        recent_renames = [e for e in rename_events if e.timestamp > window_start]

        if len(recent_renames) >= self.rename_burst_threshold:
            # Check if new extension is NOT in KNOWN_EXTENSIONS
            suspicious_renames = []
            known_renames = []
            for e in recent_renames:
                if e.path:
                    new_ext = os.path.splitext(e.path)[1].lower()
                    if new_ext and new_ext not in KNOWN_EXTENSIONS:
                        suspicious_renames.append(e)
                    else:
                        known_renames.append(e)

            # Severity: CRITICAL if new extension NOT in KNOWN_EXTENSIONS
            severity = "critical" if suspicious_renames else "high"

            self._create_alert(
                behavior_type=BehaviorType.FILE_RENAME_BURST,
                process=process,
                files=[e.path for e in recent_renames[:20]],
                severity=severity,
                description=f"Mass rename detected: {len(recent_renames)} files in {self.rename_burst_window}s",
                metadata={
                    "file_count": len(recent_renames),
                    "window_seconds": self.rename_burst_window,
                    "suspicious_extensions": len(suspicious_renames),
                    "known_extensions": len(known_renames),
                }
            )

    def _check_mass_io_anomaly(self, process: ProcessInfo):
        """
        Task 1: Phát hiện MASS_IO_ANOMALY pattern.
        Trigger: Process write rate > 50 MB/s sustained for 5 seconds.
        Uses psutil.Process(pid).io_counters() to measure.
        """
        if not PSUTIL_AVAILABLE:
            return
        if process.is_benign or process.is_system:
            return

        try:
            proc = psutil.Process(process.pid)
            io_counters = proc.io_counters()
            current_time = time.time()

            # First sample - just record
            if process.pid not in self._last_io_time:
                self._last_io_counters[process.pid] = {
                    "write_bytes": io_counters.write_bytes,
                    "read_bytes": io_counters.read_bytes,
                }
                self._last_io_time[process.pid] = current_time
                return

            # Calculate delta
            last_time = self._last_io_time[process.pid]
            last_counters = self._last_io_counters[process.pid]

            time_delta = current_time - last_time
            if time_delta < 1.0:  # Need at least 1 second between samples
                return

            write_delta = io_counters.write_bytes - last_counters["write_bytes"]
            write_mbps = (write_delta / (1024 * 1024)) / time_delta

            # Record sample
            self._io_samples[process.pid].append({
                "timestamp": current_time,
                "write_mbps": write_mbps,
                "write_bytes": write_delta,
                "time_delta": time_delta,
            })

            # Keep only recent samples
            window_start = current_time - self.mass_io_duration
            self._io_samples[process.pid] = [
                s for s in self._io_samples[process.pid]
                if s["timestamp"] > window_start
            ]

            # Check sustained high IO
            samples = self._io_samples[process.pid]
            if len(samples) >= 2:
                avg_write_mbps = sum(s["write_mbps"] for s in samples) / len(samples)
                # Check if sustained above threshold
                sustained_high = all(s["write_mbps"] >= self.mass_io_threshold_mbps for s in samples)

                if sustained_high and avg_write_mbps >= self.mass_io_threshold_mbps:
                    self._create_alert(
                        behavior_type=BehaviorType.MASS_IO_ANOMALY,
                        process=process,
                        files=[],
                        severity="critical",
                        description=f"Mass I/O anomaly: {avg_write_mbps:.1f} MB/s sustained for {len(samples)} samples",
                        metadata={
                            "avg_write_mbps": round(avg_write_mbps, 2),
                            "max_write_mbps": max(s["write_mbps"] for s in samples),
                            "sample_count": len(samples),
                            "duration_seconds": time_delta * len(samples),
                        }
                    )
                    # Clear samples after alert to prevent repeated alerts
                    self._io_samples[process.pid].clear()

            # Update last counters
            self._last_io_counters[process.pid] = {
                "write_bytes": io_counters.write_bytes,
                "read_bytes": io_counters.read_bytes,
            }
            self._last_io_time[process.pid] = current_time

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    def record_io_sample(self, pid: int, write_bytes: int, read_bytes: int):
        """
        Task 1: Record IO sample for external monitoring.
        Can be called by watchdog_monitor to provide IO data.
        """
        if not self._running:
            return

        with self._lock:
            current_time = time.time()

            if pid not in self._last_io_time:
                self._last_io_counters[pid] = {"write_bytes": write_bytes, "read_bytes": read_bytes}
                self._last_io_time[pid] = current_time
                return

            last_time = self._last_io_time[pid]
            last_counters = self._last_io_counters[pid]

            time_delta = current_time - last_time
            if time_delta < 1.0:
                return

            write_delta = write_bytes - last_counters["write_bytes"]
            read_delta = read_bytes - last_counters["read_bytes"]
            write_mbps = (write_delta / (1024 * 1024)) / time_delta
            read_mbps = (read_delta / (1024 * 1024)) / time_delta

            self._io_samples[pid].append({
                "timestamp": current_time,
                "write_mbps": write_mbps,
                "read_mbps": read_mbps,
                "write_bytes": write_delta,
                "read_bytes": read_delta,
                "time_delta": time_delta,
            })

            # Keep only recent samples
            window_start = current_time - self.mass_io_duration
            self._io_samples[pid] = [
                s for s in self._io_samples[pid]
                if s["timestamp"] > window_start
            ]

            # Check sustained high IO
            samples = self._io_samples[pid]
            if len(samples) >= 2:
                avg_write_mbps = sum(s["write_mbps"] for s in samples) / len(samples)
                sustained_high = all(s["write_mbps"] >= self.mass_io_threshold_mbps for s in samples)

                if sustained_high and avg_write_mbps >= self.mass_io_threshold_mbps:
                    process = self._get_process_info(pid)
                    if process:
                        self._create_alert(
                            behavior_type=BehaviorType.MASS_IO_ANOMALY,
                            process=process,
                            files=[],
                            severity="critical",
                            description=f"Mass I/O anomaly: {avg_write_mbps:.1f} MB/s sustained",
                            metadata={
                                "avg_write_mbps": round(avg_write_mbps, 2),
                                "max_write_mbps": max(s["write_mbps"] for s in samples),
                            }
                        )
                    self._io_samples[pid].clear()

            self._last_io_counters[pid] = {"write_bytes": write_bytes, "read_bytes": read_bytes}
            self._last_io_time[pid] = current_time

    def _create_alert(
        self,
        behavior_type: BehaviorType,
        process: ProcessInfo,
        files: List[str],
        severity: str,
        description: str,
        metadata: Dict[str, Any] = None
    ):
        """Tạo alert mới."""
        # Prevent duplicate alerts for same process in short time
        recent_alerts = [a for a in self.alerts[-10:]
                        if a.process.pid == process.pid
                        and a.behavior_type == behavior_type
                        and (datetime.now() - a.timestamp).total_seconds() < 60]

        if recent_alerts:
            return  # Already alerted recently

        alert = BehaviorAlert(
            behavior_type=behavior_type,
            process=process,
            files=files,
            timestamp=datetime.now(),
            severity=severity,
            description=description,
            metadata=metadata or {}
        )

        # After creating alert, update signal aggregator
        self._update_signal_aggregator(behavior_type, process, severity)

        self.total_alerts += 1

        if self.on_behavior:
            self.on_behavior(alert)

    def get_process_stats(self, pid: int) -> Dict[str, Any]:
        """Lấy statistics cho một process."""
        events = self._process_events.get(pid, [])

        extensions = set()
        for e in events:
            ext = os.path.splitext(e.path)[1].lower()
            if ext:
                extensions.add(ext)

        entropy_values = [e.entropy for e in events if e.entropy > 0]

        return {
            "pid": pid,
            "event_count": len(events),
            "unique_extensions": list(extensions),
            "avg_entropy": sum(entropy_values) / len(entropy_values) if entropy_values else 0,
            "max_entropy": max(entropy_values) if entropy_values else 0,
            "first_event": events[0].timestamp.isoformat() if events else None,
            "last_event": events[-1].timestamp.isoformat() if events else None,
        }

    def get_all_stats(self) -> Dict[str, Any]:
        """Lấy tất cả statistics."""
        return {
            "total_events": self.total_events,
            "total_alerts": self.total_alerts,
            "unique_processes": len(self._process_events),
            "alerts_by_type": self._count_alerts_by_type(),
            "signal_aggregator": self._signal_aggregator.get_signal_stats(),
        }

    def _count_alerts_by_type(self) -> Dict[str, int]:
        """Đếm alerts theo type."""
        counts = {bt.value: 0 for bt in BehaviorType}
        for alert in self.alerts:
            counts[alert.behavior_type.value] += 1
        return counts

    def _update_signal_aggregator(self, behavior_type: BehaviorType, process: ProcessInfo, severity: str):
        """Update signal aggregator with new behavior detection."""
        signal_name = behavior_type.value
        self._signal_aggregator.record_signal(signal_name, severity)


class DynamicSignalAggregator:
    """
    Task 1: Aggregator for dynamic behavior signals.
    Computes composite threat score from multiple behavior patterns.

    Usage:
        aggregator = DynamicSignalAggregator()
        score = aggregator.compute_score(["FILE_RENAME_BURST", "MASS_IO_ANOMALY"])
        if score > aggregator.CRITICAL_THRESHOLD:
            print("CRITICAL THREAT DETECTED!")
    """

    WEIGHTS = {
        "FILE_RENAME_BURST": 0.40,
        "MASS_IO_ANOMALY": 0.40,
        "ENCRYPTION_BURST": 0.30,
        "EXTENSION_CHANGE": 0.25,
        "RAPID_OPS": 0.20,
        "SUSPICIOUS_PROCESS": 0.15,
        "HIGH_ENTROPY_WRITE": 0.10,
        "OTHER": 0.10,
    }
    CRITICAL_THRESHOLD = 0.70

    def __init__(self):
        self._signal_history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def compute_score(self, active_signals: List[str]) -> float:
        """
        Compute composite score from active signals.
        Returns score from 0.0 to 1.0.
        Score > 0.70 = CRITICAL.

        Args:
            active_signals: List of signal type names (e.g., ["FILE_RENAME_BURST", "MASS_IO_ANOMALY"])

        Returns:
            Composite threat score (0.0 - 1.0)
        """
        if not active_signals:
            return 0.0

        score = 0.0
        signal_count = 0

        for signal in active_signals:
            weight = self.WEIGHTS.get(signal, self.WEIGHTS["OTHER"])
            score += weight
            signal_count += 1

        normalized_score = min(score, 1.0)

        with self._lock:
            self._signal_history.append({
                "timestamp": datetime.now(),
                "signals": active_signals,
                "score": normalized_score,
            })
            if len(self._signal_history) > 100:
                self._signal_history = self._signal_history[-100:]

        return normalized_score

    def record_signal(self, signal_type: str, severity: str = "medium"):
        """
        Record a new signal with its severity.
        
        Args:
            signal_type: Type of signal (e.g., "FILE_RENAME_BURST")
            severity: One of "critical", "high", "medium", "low"
        """
        # Apply severity multiplier
        multiplier = 1.5 if severity == "critical" else 1.25 if severity == "high" else 1.0
        
        # Record signal
        self.compute_score([signal_type])
        
        # Store with severity in history
        with self._lock:
            if self._signal_history:
                self._signal_history[-1]["severity"] = severity
                self._signal_history[-1]["multiplier"] = multiplier

    def compute_score_from_alerts(self, alerts: List[BehaviorAlert]) -> float:
        """
        Compute score from a list of BehaviorAlert objects.

        Args:
            alerts: List of BehaviorAlert objects

        Returns:
            Composite threat score (0.0 - 1.0)
        """
        if not alerts:
            return 0.0

        # Get unique signal types from alerts
        signal_types = list(set(alert.behavior_type.value for alert in alerts))

        # Apply severity multipliers
        severity_multiplier = 1.0
        has_critical = any(alert.severity == "critical" for alert in alerts)
        has_high = any(alert.severity == "high" for alert in alerts)

        if has_critical:
            severity_multiplier = 1.5
        elif has_high:
            severity_multiplier = 1.25

        score = self.compute_score(signal_types) * severity_multiplier
        return min(score, 1.0)

    def is_critical(self, active_signals: List[str]) -> bool:
        """Check if active signals indicate critical threat."""
        return self.compute_score(active_signals) >= self.CRITICAL_THRESHOLD

    def get_signal_stats(self) -> Dict[str, Any]:
        """Get statistics about recorded signals."""
        with self._lock:
            if not self._signal_history:
                return {
                    "total_records": 0,
                    "avg_score": 0.0,
                    "critical_count": 0,
                    "recent_scores": [],
                }

            scores = [r["score"] for r in self._signal_history]
            critical_count = sum(1 for s in scores if s >= self.CRITICAL_THRESHOLD)

            return {
                "total_records": len(self._signal_history),
                "avg_score": sum(scores) / len(scores),
                "max_score": max(scores),
                "critical_count": critical_count,
                "recent_scores": scores[-10:],
            }

    def clear_history(self):
        """Clear signal history."""
        with self._lock:
            self._signal_history.clear()


# Singleton instance
_monitor: Optional[ProcessMonitor] = None


def get_process_monitor() -> ProcessMonitor:
    """Lấy singleton ProcessMonitor instance."""
    global _monitor
    if _monitor is None:
        _monitor = ProcessMonitor()
    return _monitor
