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
from typing import Dict, List, Optional, Callable, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

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


class BehaviorType(Enum):
    """Loại behavior đáng ngờ."""
    ENCRYPTION_BURST = "encryption_burst"      # Nhiều file bị mã hóa nhanh
    EXTENSION_CHANGE = "extension_change"      # Đổi extension sang suspicious
    RAPID_OPS = "rapid_ops"                    # Tần suất thao tác file cao bất thường
    SUSPICIOUS_PROCESS = "suspicious_process" # Process không known benign
    HIGH_ENTROPY_WRITE = "high_entropy_write"  # Ghi file có entropy cao


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

            # Lưu event theo process
            if event.pid:
                self._process_events[event.pid].append(event)

            # Check for behaviors
            if process:
                self._check_encryption_burst(process)
                self._check_rapid_ops(process)
                self._check_suspicious_process(process, event)

                if self.on_process_detected:
                    self.on_process_detected(process, event)

    def _get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Lấy thông tin process từ PID."""
        if not PSUTIL_AVAILABLE or pid is None:
            return None

        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()

            info = ProcessInfo(
                pid=pid,
                name=name,
                path=proc.exe() or "",
                command_line=" ".join(proc.cmdline()) if proc.cmdline() else "",
                is_system=proc.ppid() == 0 or name in ("system", "smss.exe"),
                is_benign=name.lower() in KNOWN_BENIGN_PROCESSES,
            )

            # Thử lấy thời gian bắt đầu
            try:
                info.started = datetime.fromtimestamp(proc.create_time())
            except:
                pass

            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
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

        self.alerts.append(alert)
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
        }

    def _count_alerts_by_type(self) -> Dict[str, int]:
        """Đếm alerts theo type."""
        counts = {bt.value: 0 for bt in BehaviorType}
        for alert in self.alerts:
            counts[alert.behavior_type.value] += 1
        return counts


# Singleton instance
_monitor: Optional[ProcessMonitor] = None


def get_process_monitor() -> ProcessMonitor:
    """Lấy singleton ProcessMonitor instance."""
    global _monitor
    if _monitor is None:
        _monitor = ProcessMonitor()
    return _monitor
