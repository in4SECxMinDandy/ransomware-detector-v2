"""
watchdog_monitor.py
====================
Real-time Protection Module sử dụng watchdog library.

Theo dõi các sự kiện:
  - FileCreatedEvent  : file mới được tạo
  - FileModifiedEvent : file hiện có bị chỉnh sửa

Khi có sự kiện:
  1. Đưa file vào queue phân tích
  2. Worker thread lấy từ queue, trích xuất features
  3. Gọi ML Engine dự đoán
  4. Nếu threat được phát hiện → trigger alert callback

Alert levels:
  - CRITICAL (>=85%): cảnh báo khẩn cấp, ghi log ngay lập tức
  - HIGH (>=65%):     cảnh báo cao
  - MEDIUM (>=45%):   cảnh báo trung bình

Debounce: 2 giây cooldown mỗi file để tránh spam khi ransomware ghi liên tục.

Entropy Burst Detection (v2.4):
  - Tính Shannon entropy sau mỗi sự kiện ON_MODIFIED
  - Ngưỡng: entropy > 7.5 trên 5 file liên tiếp trong vòng 30 giây
  - Khi phát hiện → gọi auto_responder + ghi logs/entropy_alerts.log
"""

import os
import time
import queue
import threading
import platform
import logging
from typing import Callable, Optional, List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileSystemEvent
)
from core.feature_extractor import extract_features
from core.ml_engine import get_engine
from core.scanner import SKIP_EXTENSIONS, MIN_FILE_SIZE, MAX_FILE_SIZE, ScanResult
from core.process_monitor import (
    get_process_monitor, FileEvent, BehaviorAlert
)
from core.notifications import get_notifier

PID_LOOKUP_COOLDOWN_SECONDS = 1.0
PID_LOOKUP_CACHE_TTL_SECONDS = 5.0
INTERNAL_PROJECT_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "logs",
    "quarantine",
    "data",
    "models",
    "datasets",
    "venv",
}


def _normalize_path(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


PROJECT_ROOT = _normalize_path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEBOUNCE_SECONDS  = 2.0   # Cooldown mỗi file
QUEUE_MAX_SIZE    = 500   # Tối đa 500 events trong queue
WORKER_THREADS    = 3     # Số worker thread phân tích song song
ALERT_THRESHOLD   = 0.45  # Ngưỡng xác suất để kích hoạt alert


class ThreatEvent:
    """Sự kiện đe dọa được phát hiện."""
    def __init__(self, result: ScanResult, event_type: str):
        self.result      = result
        self.event_type  = event_type  # "created" hoặc "modified"
        self.detected_at = datetime.now()
        self.timestamp   = self.detected_at.isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp":   self.timestamp,
            "event_type":  self.event_type,
            "path":        self.result.path,
            "filename":    self.result.filename,
            "probability": round(self.result.probability, 4),
            "risk_level":  self.result.risk_level,
            "entropy":     round(self.result.entropy, 4),
        }


class _EventHandler(FileSystemEventHandler):
    """Internal event handler gửi events vào queue."""

    def __init__(
        self,
        file_queue: queue.Queue,
        debounce_cache: Dict[str, float],
        ignored_roots: Optional[List[str]] = None,
    ):
        super().__init__()
        self._queue         = file_queue
        self._debounce      = debounce_cache
        self._debounce_lock = threading.Lock()
        self._ignored_roots = [_normalize_path(path) for path in (ignored_roots or [])]

    def _is_ignored_path(self, path: str) -> bool:
        normalized = _normalize_path(path)
        return any(
            normalized == root or normalized.startswith(root + os.sep)
            for root in self._ignored_roots
        )

    def _should_process(self, path: str) -> bool:
        """Kiểm tra debounce và filter."""
        if self._is_ignored_path(path):
            return False
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext in SKIP_EXTENSIONS:
            return False
        try:
            size = os.path.getsize(path)
            if not (MIN_FILE_SIZE <= size <= MAX_FILE_SIZE):
                return False
        except OSError:
            return False

        now = time.time()
        with self._debounce_lock:
            last = self._debounce.get(path, 0)
            if now - last < DEBOUNCE_SECONDS:
                return False
            self._debounce[path] = now

        return True

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        if self._should_process(event.src_path):
            try:
                self._queue.put_nowait(("created", event.src_path))
            except queue.Full:
                pass

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        if self._should_process(event.src_path):
            try:
                self._queue.put_nowait(("modified", event.src_path))
            except queue.Full:
                pass


class RealTimeMonitor:
    """
    Real-time filesystem monitor với ML-based threat detection.

    Usage:
        monitor = RealTimeMonitor()
        monitor.on_threat = lambda t: print(f"THREAT: {t.result.path}")
        monitor.start("/path/to/watch")
        ...
        monitor.stop()
    """

    def __init__(self):
        self._observer:   Optional[Observer]      = None
        self._workers:    List[threading.Thread]  = []
        self._queue:      queue.Queue             = queue.Queue(maxsize=QUEUE_MAX_SIZE)
        self._debounce:   Dict[str, float]        = {}
        self._stop_event: threading.Event         = threading.Event()
        self._is_running: bool                    = False
        self._lock:       threading.Lock          = threading.Lock()
        self._observer_ready_event: threading.Event = threading.Event()
        self._watch_directory: str                = ""
        self._watch_recursive: bool               = True
        self._pid_lookup_cache: Dict[str, tuple[float, Optional[int]]] = {}
        self._last_pid_lookup_at: float           = 0.0

        # History của các threats đã phát hiện
        self.threat_history: List[ThreatEvent]    = []
        self.total_analyzed: int                  = 0
        self.total_threats:  int                  = 0

        # Process Monitor (v2.2)
        self._process_monitor = get_process_monitor()

        # Notifications (v2.2)
        self._notifier = get_notifier()

        # Callbacks
        self.on_threat:   Optional[Callable[[ThreatEvent], None]] = None
        self.on_analyzed: Optional[Callable[[ScanResult, str], None]] = None
        self.on_behavior: Optional[Callable[[BehaviorAlert], None]] = None
        self.on_entropy_alert: Optional[Callable[[Dict[str, Any]], None]] = None

        # ─── Entropy Burst Detection (v2.4) ────────────────────────────────
        self._entropy_history: List[Dict[str, Any]] = []  # [{file, entropy, timestamp}]
        self._entropy_lock: threading.Lock = threading.Lock()
        # Thresholds (có thể override qua config)
        self._entropy_threshold: float = 7.5
        self._entropy_consecutive: int = 5
        self._entropy_window_seconds: float = 30.0
        self._entropy_alert_log_path: str = "logs/entropy_alerts.log"
        self._entropy_alert_logged: bool = False  # Tránh spam log

    @property
    def is_running(self) -> bool:
        return self._is_running

    def start(self, watch_directory: str, recursive: bool = True) -> bool:
        """
        Bắt đầu giám sát thư mục.

        Returns True nếu thành công.
        """
        if self._is_running:
            return False

        if not os.path.isdir(watch_directory):
            return False

        # Đảm bảo ML engine đã load
        engine = get_engine()
        if not engine.is_loaded():
            return False

        self._stop_event.clear()
        self._debounce.clear()
        self._pid_lookup_cache.clear()
        self._last_pid_lookup_at = 0.0
        self.threat_history.clear()
        self.total_analyzed = 0
        self.total_threats  = 0

        # Khởi động Process Monitor (v2.2)
        self._process_monitor.start()
        self._process_monitor.on_behavior = self._handle_behavior_alert

        # Khởi động worker threads
        self._workers = []
        for _ in range(WORKER_THREADS):
            t = threading.Thread(target=self._worker_loop, daemon=True)
            t.start()
            self._workers.append(t)

        # Khởi động watchdog observer trong thread riêng; không chờ trên luồng gọi
        # (schedule(recursive=True) trên thư mục lớn có thể mất rất lâu → tránh chặn GUI)
        self._watch_directory = watch_directory
        self._watch_recursive = recursive
        self._observer_ready_event = threading.Event()
        t = threading.Thread(target=self._observer_start_thread, daemon=True)
        t.start()
        self._is_running = True
        return True

    def _observer_start_thread(self):
        """Chạy observer schedule + start trong background thread."""
        try:
            handler = _EventHandler(
                self._queue,
                self._debounce,
                ignored_roots=self._build_ignored_roots(),
            )
            self._observer = Observer()
            self._observer.schedule(handler, self._watch_directory,
                                   recursive=self._watch_recursive)
            self._observer.start()
        except Exception as e:
            logger.error(f"Observer start error: {e}")
        finally:
            self._observer_ready_event.set()

    def stop(self):
        """Dừng giám sát."""
        if not self._is_running:
            return

        self._stop_event.set()

        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)

        # Drain queue
        try:
            while not self._queue.empty():
                self._queue.get_nowait()
        except Exception:
            pass

        # Gửi sentinel để kết thúc workers
        for _ in self._workers:
            self._queue.put(None)

        for t in self._workers:
            t.join(timeout=2)

        self._workers.clear()

        # Stop Process Monitor (v2.2)
        self._process_monitor.stop()

        self._is_running = False

    def _worker_loop(self):
        """Worker thread: lấy file từ queue và phân tích."""
        engine = get_engine()

        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if item is None:  # Sentinel
                break

            event_type, file_path = item

            # Đợi file ghi xong (write lock release)
            time.sleep(0.3)
            if not os.path.isfile(file_path):
                continue

            result = ScanResult(file_path)
            try:
                result.size = os.path.getsize(file_path)
                features = extract_features(file_path)
                if features is not None:
                    label, proba = engine.predict(features)
                    result.label      = label
                    result.probability = proba
                    result.risk_level = engine.get_risk_level(proba)
                    result.entropy    = float(features[0])

                    # ─── Entropy Burst Detection (v2.4) ───────────────────
                    self._check_entropy_burst(
                        file_path, float(features[0]), result
                    )

                    # Record to Process Monitor (v2.2)
                    self._record_process_event(
                        file_path,
                        event_type,
                        features,
                        result.size,
                        result.probability,
                    )
                else:
                    result.error = "Không thể trích xuất features"
            except Exception as e:
                result.error = str(e)[:100]

            with self._lock:
                self.total_analyzed += 1

            if self.on_analyzed:
                self.on_analyzed(result, event_type)

            # Kích hoạt alert nếu vượt ngưỡng
            if result.probability >= ALERT_THRESHOLD and result.error is None:
                threat = ThreatEvent(result, event_type)
                with self._lock:
                    self.threat_history.append(threat)
                    self.total_threats += 1
                if self.on_threat:
                    self.on_threat(threat)

                # Send Windows notification (v2.2)
                self._notifier.notify(
                    title="Ransomware Detected!",
                    message=f"{result.filename} - Risk: {result.risk_level}",
                    severity=result.risk_level.lower()
                )

    def _record_process_event(
        self,
        file_path: str,
        event_type: str,
        features,
        size: int,
        probability: float,
    ):
        """Ghi nhận event vào Process Monitor."""
        from datetime import datetime

        entropy = float(features[0]) if features is not None else 0.0
        should_lookup_pid = (
            event_type == "created" or
            probability >= ALERT_THRESHOLD or
            entropy >= self._entropy_threshold
        )
        pid = self._get_file_process_pid(file_path) if should_lookup_pid else None

        file_event = FileEvent(
            path=file_path,
            event_type=event_type,
            timestamp=datetime.now(),
            pid=pid,
            process_name="",
            entropy=entropy,
            size=size
        )

        self._process_monitor.record_event(file_event)

    def _build_ignored_roots(self) -> List[str]:
        roots = []
        for dirname in INTERNAL_PROJECT_DIRS:
            candidate = os.path.join(PROJECT_ROOT, dirname)
            if os.path.exists(candidate):
                roots.append(candidate)
        return roots

    def _get_file_process_pid(self, file_path: str) -> Optional[int]:
        """Lấy PID của process đang truy cập file (Windows only)."""
        if platform.system() != "Windows":
            return None

        normalized_path = _normalize_path(file_path)
        now = time.time()

        cached = self._pid_lookup_cache.get(normalized_path)
        if cached and now - cached[0] <= PID_LOOKUP_CACHE_TTL_SECONDS:
            return cached[1]

        if now - self._last_pid_lookup_at < PID_LOOKUP_COOLDOWN_SECONDS:
            return None

        self._last_pid_lookup_at = now

        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    open_files = proc.info.get('open_files')
                    if open_files:
                        for f in open_files:
                            candidate = getattr(f, "path", "")
                            if not candidate:
                                continue
                            if _normalize_path(candidate) == normalized_path:
                                pid = proc.info['pid']
                                self._pid_lookup_cache[normalized_path] = (time.time(), pid)
                                return pid
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        self._pid_lookup_cache[normalized_path] = (time.time(), None)
        return None

    def _handle_behavior_alert(self, alert: BehaviorAlert):
        """Xử lý behavior alert từ Process Monitor."""
        # Send notification
        self._notifier.notify_ransomware_alert(
            alert_type=alert.behavior_type.value,
            process_name=alert.process.name,
            file_count=len(alert.files),
            details=alert.description
        )

        # Callback to GUI
        if self.on_behavior:
            self.on_behavior(alert)

    def get_stats(self) -> Dict[str, Any]:
        """Thống kê của phiên giám sát hiện tại."""
        return {
            "is_running":     self._is_running,
            "total_analyzed": self.total_analyzed,
            "total_threats":  self.total_threats,
            "queue_size":     self._queue.qsize(),
            "process_monitor": self._process_monitor.get_all_stats(),
            "notifications":  self._notifier.get_stats(),
        }

    @property
    def process_monitor(self):
        """Lấy ProcessMonitor instance."""
        return self._process_monitor

    @property
    def notifier(self):
        """Lấy NotificationManager instance."""
        return self._notifier

    def get_current_io_rate(self) -> Dict[str, float]:
        """Lấy current IO rates cho GUI chart."""
        stats = {}
        for pid, samples in self._process_monitor._io_samples.items():
            if samples:
                recent = samples[-1]
                stats[pid] = {
                    "write_mbps": recent["write_mbps"],
                    "read_mbps": recent.get("read_mbps", 0.0),
                    "timestamp": recent["timestamp"],
                }
        return stats

    def get_signal_stats(self) -> Dict[str, Any]:
        """Lấy behavior signal stats."""
        pm_stats = self._process_monitor.get_all_stats()
        sig_stats = self._process_monitor._signal_aggregator.get_signal_stats() if hasattr(self._process_monitor, "_signal_aggregator") else {}
        return {
            "process_monitor": pm_stats,
            "signal_aggregator": sig_stats,
        }

    # ─── Entropy Burst Detection (v2.4) ───────────────────────────────────

    def _compute_shannon_entropy(self, file_path: str) -> float:
        """
        Tính Shannon entropy H = -Σ p_i * log2(p_i) của file.

        Đọc tối đa 64KB để tính entropy nhanh.
        """
        import math
        try:
            byte_counts = [0] * 256
            total = 0
            with open(file_path, "rb") as f:
                chunk = f.read(65536)
                for byte in chunk:
                    byte_counts[byte] += 1
                    total += 1
            if total == 0:
                return 0.0
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    p = count / total
                    entropy -= p * math.log2(p)
            return entropy
        except Exception:
            return 0.0

    def _check_entropy_burst(self, file_path: str, entropy: float, result: ScanResult):
        """
        Kiểm tra xem có entropy burst không.

        Logic:
          - Nếu entropy > threshold → thêm vào history
          - Dọn history cũ hơn window
          - Nếu >= consecutive files trong window → ALERT
        """
        now = time.time()

        with self._entropy_lock:
            # Dọn entries cũ hơn window
            cutoff = now - self._entropy_window_seconds
            self._entropy_history = [
                e for e in self._entropy_history
                if e["timestamp"] > cutoff
            ]

            if entropy > self._entropy_threshold:
                self._entropy_history.append({
                    "file": file_path,
                    "entropy": entropy,
                    "timestamp": now,
                    "filename": os.path.basename(file_path),
                    "risk_level": result.risk_level,
                })

            # Kiểm tra ngưỡng
            if len(self._entropy_history) >= self._entropy_consecutive:
                if not self._entropy_alert_logged:
                    self._fire_entropy_alert()

    def _fire_entropy_alert(self):
        """Kích hoạt entropy alert."""
        self._entropy_alert_logged = True

        alert_info = {
            "timestamp": datetime.now().isoformat(),
            "type": "entropy_burst",
            "consecutive_files": len(self._entropy_history),
            "threshold": self._entropy_threshold,
            "window_seconds": self._entropy_window_seconds,
            "files": [
                {
                    "file": e["file"],
                    "entropy": round(e["entropy"], 3),
                    "risk_level": e.get("risk_level", "UNKNOWN"),
                }
                for e in self._entropy_history[-self._entropy_consecutive:]
            ],
        }

        # Ghi log
        self._log_entropy_alert(alert_info)

        # Reset flag sau 60s để có thể alert lại nếu có đợt mới
        threading.Timer(60.0, self._reset_entropy_alert_flag).start()

        # Callback GUI
        if self.on_entropy_alert:
            try:
                self.on_entropy_alert(alert_info)
            except Exception:
                pass

        # Gửi notification
        self._notifier.notify(
            title="Entropy Burst Detected!",
            message=f"Ransomware encryption suspected: {len(self._entropy_history)} high-entropy files",
            severity="CRITICAL"
        )

        logger.warning(
            f"ENTROPY BURST: {len(self._entropy_history)} high-entropy files detected "
            f"in {self._entropy_window_seconds}s window"
        )

    def _reset_entropy_alert_flag(self):
        """Reset entropy alert flag sau cooldown."""
        with self._entropy_lock:
            self._entropy_alert_logged = False

    def _log_entropy_alert(self, alert_info: Dict[str, Any]):
        """Ghi entropy alert ra log file."""
        log_file = self._resolve_path(self._entropy_alert_log_path)

        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)

            with open(log_file, "a", encoding="utf-8") as f:
                timestamp = alert_info["timestamp"]
                f.write(f"\n{'='*60}\n")
                f.write(f"[ENTROPY BURST ALERT] {timestamp}\n")
                f.write(f"Consecutive files: {alert_info['consecutive_files']}\n")
                f.write(f"Threshold: {alert_info['threshold']}\n")
                f.write(f"Window: {alert_info['window_seconds']}s\n")
                f.write("\nFiles detected:\n")
                for entry in alert_info["files"]:
                    f.write(
                        f"  - {entry['file']} | "
                        f"Entropy: {entry['entropy']} | "
                        f"Risk: {entry['risk_level']}\n"
                    )
                f.write(f"{'='*60}\n\n")
        except Exception as e:
            logger.error(f"Failed to write entropy alert log: {e}")

    def _resolve_path(self, path: str) -> str:
        """Resolve relative path tu project root."""
        if os.path.isabs(path):
            return path
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, path)

    def get_entropy_stats(self) -> Dict[str, Any]:
        """Tra ve entropy monitoring stats."""
        with self._entropy_lock:
            now = time.time()
            cutoff = now - self._entropy_window_seconds
            recent = [e for e in self._entropy_history if e["timestamp"] > cutoff]
            return {
                "enabled": True,
                "threshold": self._entropy_threshold,
                "consecutive_files": self._entropy_consecutive,
                "window_seconds": self._entropy_window_seconds,
                "recent_entries": len(recent),
                "consecutive_count": len(recent),
                "is_above_threshold": len(recent) >= self._entropy_consecutive,
                "alert_triggered": self._entropy_alert_logged,
            }

    def reset_entropy_state(self):
        """Reset entropy history (sau khi alert đã được xử lý)."""
        with self._entropy_lock:
            self._entropy_history.clear()
            self._entropy_consecutive = 0
            self._entropy_alert_logged = False
