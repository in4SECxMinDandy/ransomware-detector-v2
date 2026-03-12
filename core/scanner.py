"""
scanner.py — v2.0 (Anti-FP Edition)
======================================
Static Scanner Module với tích hợp FP Reducer.

Nâng cấp v2:
  - Tích hợp fp_reducer.py: per-extension threshold + magic bytes discount
  - Adaptive threshold: mỗi file dùng threshold phù hợp với extension của nó
  - Whitelist check trước khi gọi ML model → tiết kiệm tài nguyên
  - ScanResult thêm trường: fp_adjusted (bool), effective_threshold, fp_reason

Hai chế độ:
  - FULL_SCAN:  đệ quy toàn bộ thư mục
  - QUICK_SCAN: chỉ quét lớp ngoài cùng

Xử lý đa luồng:
  - ThreadPoolExecutor để quét song song
  - Callback progress không block UI
  - Hỗ trợ cancel scan giữa chừng
"""

import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Dict, Optional, Any

from core.feature_extractor import extract_features
from core.ml_engine import get_engine
from core.yara_engine import get_yara_engine
from core.fp_reducer import (
    check_path_whitelist,
    apply_fp_reduction,
    ALWAYS_SAFE_EXTENSIONS,
)

# Extensions luôn bỏ qua (hệ thống, không cần phân tích)
SKIP_EXTENSIONS = {
    ".lnk", ".ini", ".log", ".tmp", ".cache", ".db", ".sqlite",
    ".sys",
    ".ico", ".cur", ".ani", ".ttf", ".otf", ".woff", ".woff2",
}

MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB
MIN_FILE_SIZE = 64                        # 64 bytes
MAX_THREADS   = 8


class ScanResult:
    """Kết quả quét một file — v2 thêm FP metadata."""
    __slots__ = [
        "path", "filename", "size", "extension",
        "label", "probability", "risk_level",
        "entropy", "scan_time_ms", "error",
        # v2: FP reduction metadata
        "raw_probability",       # probability gốc từ model (trước FP adjustment)
        "fp_adjusted",           # True nếu probability đã được điều chỉnh
        "effective_threshold",   # threshold thực tế áp dụng cho file này
        "fp_reason",             # lý do FP adjustment (debug)
        # v2.1: YARA  ← thêm vào __slots__ để tránh AttributeError
        "yara_matches",          # list of YaraMatch objects
        "yara_boosted",          # True nếu probability được boost bởi YARA
    ]

    def __init__(self, path: str):
        self.path                = path
        self.filename            = os.path.basename(path)
        self.size                = 0
        self.extension           = os.path.splitext(path)[1].lower()
        self.label               = 0
        self.probability         = 0.0
        self.risk_level          = "SAFE"
        self.entropy             = 0.0
        self.scan_time_ms        = 0.0
        self.error               = None
        # v2
        self.raw_probability     = 0.0
        self.fp_adjusted         = False
        self.effective_threshold = 0.65
        self.fp_reason           = ""
        # v2.1: YARA
        self.yara_matches: list  = []
        self.yara_boosted: bool  = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path":               self.path,
            "filename":           self.filename,
            "size":               self.size,
            "extension":          self.extension,
            "label":              self.label,
            "probability":        self.probability,
            "risk_level":         self.risk_level,
            "entropy":            self.entropy,
            "scan_time_ms":       self.scan_time_ms,
            "error":              self.error,
            "raw_probability":    self.raw_probability,
            "fp_adjusted":        self.fp_adjusted,
            "effective_threshold": self.effective_threshold,
            "fp_reason":          self.fp_reason,
        }


class Scanner:
    """Multi-threaded file scanner với ML-based detection và FP reduction."""

    def __init__(self):
        self._cancel_flag = threading.Event()
        self._lock        = threading.Lock()
        self._results: List[ScanResult] = []
        self._progress    = 0
        self._total       = 0
        self._is_scanning = False

    @property
    def is_scanning(self) -> bool:
        return self._is_scanning

    @property
    def results(self) -> List[ScanResult]:
        return self._results.copy()

    def cancel(self):
        """Hủy scan đang chạy."""
        self._cancel_flag.set()

    def _collect_files(self, directory: str, recursive: bool) -> List[str]:
        """Thu thập danh sách files cần quét."""
        files = []
        try:
            if recursive:
                for root, dirs, filenames in os.walk(directory):
                    dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                                {"System Volume Information", "$Recycle.Bin", "Windows",
                                 "__pycache__", "node_modules", ".git"}]
                    for fn in filenames:
                        fp  = os.path.join(root, fn)
                        ext = os.path.splitext(fn)[1].lower()
                        if ext in SKIP_EXTENSIONS:
                            continue
                        try:
                            size = os.path.getsize(fp)
                            if MIN_FILE_SIZE <= size <= MAX_FILE_SIZE:
                                files.append(fp)
                        except (OSError, PermissionError):
                            pass
            else:
                for fn in os.listdir(directory):
                    fp = os.path.join(directory, fn)
                    if not os.path.isfile(fp):
                        continue
                    ext = os.path.splitext(fn)[1].lower()
                    if ext in SKIP_EXTENSIONS:
                        continue
                    try:
                        size = os.path.getsize(fp)
                        if MIN_FILE_SIZE <= size <= MAX_FILE_SIZE:
                            files.append(fp)
                    except (OSError, PermissionError):
                        pass
        except PermissionError:
            pass
        return files

    def _scan_single_file(self, file_path: str) -> ScanResult:
        """
        Quét một file đơn lẻ với FP reduction pipeline.

        Quy trình:
          1. Whitelist check → skip nếu an toàn
          2. Extract 16 features
          3. ML predict → raw probability
          4. FP reduction: per-extension threshold + magic bytes discount
          5. Áp dụng effective_threshold → final label
        """
        result  = ScanResult(file_path)
        t_start = time.perf_counter()

        try:
            result.size = os.path.getsize(file_path)

            # ── Bước 1: Whitelist ──
            if check_path_whitelist(file_path):
                result.label        = 0
                result.probability  = 0.0
                result.risk_level   = "SAFE"
                result.fp_reason    = "whitelist"
                result.scan_time_ms = (time.perf_counter() - t_start) * 1000
                return result

            # ── Bước 2: Feature Extraction ──
            features = extract_features(file_path)
            if features is None:
                result.error      = "Không thể trích xuất features"
                result.risk_level = "UNKNOWN"
                result.scan_time_ms = (time.perf_counter() - t_start) * 1000
                return result

            # ── Bước 3: ML Predict ──
            engine = get_engine()
            base_threshold = engine.get_threshold()
            _, raw_proba   = engine.predict(features)  # label từ engine chưa dùng

            result.raw_probability = raw_proba
            result.entropy         = float(features[0])

            # ── Bước 4: FP Reduction ──
            adjusted_proba, eff_threshold, fp_reason = apply_fp_reduction(
                file_path, raw_proba, base_threshold
            )

            result.probability        = adjusted_proba
            result.effective_threshold = eff_threshold
            result.fp_reason          = fp_reason
            result.fp_adjusted        = (adjusted_proba != raw_proba or eff_threshold != base_threshold)

            # ── Bước 5: YARA Signature Scan (v2.1) ──
            yara_eng = get_yara_engine()
            yara_matches = yara_eng.scan_file(file_path)
            if yara_matches:
                adjusted_proba, yara_reason = yara_eng.apply_yara_boost(
                    adjusted_proba, yara_matches
                )
                result.yara_matches  = yara_matches
                result.yara_boosted  = True
                result.fp_reason    += f" | {yara_reason}"
                result.probability   = adjusted_proba

            # ── Bước 6: Final Classification ──
            result.label      = 1 if adjusted_proba >= eff_threshold else 0
            result.risk_level = engine.get_risk_level(adjusted_proba)

            # Override: nếu adjusted prob thấp hơn base threshold → SAFE
            if adjusted_proba < base_threshold * 0.8 and not result.yara_boosted:
                result.risk_level = "SAFE"

        except PermissionError:
            result.error = "Không có quyền đọc file"
        except Exception as e:
            result.error = str(e)[:100]

        result.scan_time_ms = (time.perf_counter() - t_start) * 1000
        return result

    def scan(
        self,
        directory: str,
        recursive: bool = True,
        on_progress: Optional[Callable[[int, int, "ScanResult"], None]] = None,
        on_complete: Optional[Callable[[List["ScanResult"]], None]] = None,
        on_error:    Optional[Callable[[str], None]] = None,
        max_threads: int = MAX_THREADS
    ) -> None:
        """
        Bắt đầu quét directory trong background thread.

        Parameters
        ----------
        directory   : thư mục cần quét
        recursive   : True = Full Scan (đệ quy), False = Quick Scan
        on_progress : callback(scanned_count, total_count, latest_result)
        on_complete : callback(all_results) khi hoàn thành
        on_error    : callback(error_message)
        max_threads : số thread song song
        """
        def _run():
            self._cancel_flag.clear()
            self._results.clear()
            self._is_scanning = True
            self._progress    = 0

            try:
                files       = self._collect_files(directory, recursive)
                self._total = len(files)

                if self._total == 0:
                    if on_complete:
                        on_complete([])
                    return

                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    future_to_path = {
                        executor.submit(self._scan_single_file, fp): fp
                        for fp in files
                    }

                    for future in as_completed(future_to_path):
                        if self._cancel_flag.is_set():
                            executor.shutdown(wait=False, cancel_futures=True)
                            break

                        result = future.result()
                        with self._lock:
                            self._results.append(result)
                            self._progress += 1
                            current_progress = self._progress

                        if on_progress:
                            on_progress(current_progress, self._total, result)

                if on_complete:
                    on_complete(self._results.copy())

            except Exception as e:
                if on_error:
                    on_error(str(e))
            finally:
                self._is_scanning = False

        t = threading.Thread(target=_run, daemon=True)
        t.start()

    def get_summary(self) -> Dict[str, Any]:
        """Tóm tắt kết quả quét — v2 thêm FP stats."""
        results = self._results
        total   = len(results)
        if total == 0:
            return {
                "total": 0, "safe": 0, "encrypted": 0,
                "critical": 0, "high": 0, "fp_adjusted_count": 0,
            }

        encrypted       = sum(1 for r in results if r.label == 1)
        critical        = sum(1 for r in results if r.risk_level == "CRITICAL")
        high            = sum(1 for r in results if r.risk_level == "HIGH")
        medium          = sum(1 for r in results if r.risk_level == "MEDIUM")
        safe            = sum(1 for r in results if r.risk_level in {"SAFE", "LOW"})
        errors          = sum(1 for r in results if r.error is not None)
        fp_adjusted     = sum(1 for r in results if getattr(r, "fp_adjusted", False))
        avg_entropy     = sum(r.entropy for r in results) / total

        return {
            "total":            total,
            "safe":             safe,
            "encrypted":        encrypted,
            "critical":         critical,
            "high":             high,
            "medium":           medium,
            "errors":           errors,
            "avg_entropy":      round(avg_entropy, 4),
            "fp_adjusted_count": fp_adjusted,  # v2: số file được điều chỉnh FP
        }