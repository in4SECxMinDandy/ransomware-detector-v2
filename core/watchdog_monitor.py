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
"""

import os
import time
import queue
import threading
import platform
from typing import Callable, Optional, List, Dict, Any
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileSystemEvent
)
from core.feature_extractor import extract_features
from core.ml_engine import get_engine
from core.scanner import SKIP_EXTENSIONS, MIN_FILE_SIZE, MAX_FILE_SIZE, ScanResult
from core.process_monitor import (
    get_process_monitor, ProcessInfo, FileEvent, BehaviorAlert, BehaviorType
)
from core.notifications import get_notifier

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

    def __init__(self, file_queue: queue.Queue, debounce_cache: Dict[str, float]):
        super().__init__()
        self._queue         = file_queue
        self._debounce      = debounce_cache
        self._debounce_lock = threading.Lock()

    def _should_process(self, path: str) -> bool:
        """Kiểm tra debounce và filter."""
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

        # Khởi động watchdog observer
        handler = _EventHandler(self._queue, self._debounce)
        self._observer = Observer()
        self._observer.schedule(handler, watch_directory, recursive=recursive)
        self._observer.start()

        self._is_running = True
        return True

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

                    # Record to Process Monitor (v2.2)
                    self._record_process_event(file_path, event_type, features, result.size)
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

    def _record_process_event(self, file_path: str, event_type: str, features, size: int):
        """Ghi nhận event vào Process Monitor."""
        from datetime import datetime

        # Get PID of process accessing the file (if available)
        pid = self._get_file_process_pid(file_path)

        file_event = FileEvent(
            path=file_path,
            event_type=event_type,
            timestamp=datetime.now(),
            pid=pid,
            process_name="",
            entropy=float(features[0]) if features is not None else 0.0,
            size=size
        )

        self._process_monitor.record_event(file_event)

    def _get_file_process_pid(self, file_path: str) -> Optional[int]:
        """Lấy PID của process đang truy cập file (Windows only)."""
        if platform.system() != "Windows":
            return None

        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    open_files = proc.info.get('open_files')
                    if open_files:
                        for f in open_files:
                            if f.path == file_path or file_path in f.path:
                                return proc.info['pid']
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

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
