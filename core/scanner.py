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
import hashlib
import threading
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Dict, Optional, Any

from core.feature_extractor import extract_features  # type: ignore[import]
from core.ml_engine import get_engine  # type: ignore[import]
from core.yara_engine import get_yara_engine  # type: ignore[import]
from core.fp_reducer import (  # type: ignore[import]
    check_path_whitelist,
    apply_fp_reduction,
)
from core.pe_analyzer import analyze_pe  # type: ignore[import]
from core.logger_setup import get_logger

logger = get_logger("scanner")

# ─── Incremental Scan Cache ─────────────────────────────────────────────────

_INCREMENTAL_CACHE_FILE = "data/scan_cache.json"
_INCREMENTAL_CACHE: dict[str, float] = {}


def _load_incremental_cache() -> dict[str, float]:
    """Load file modification-time cache from disk."""
    global _INCREMENTAL_CACHE
    if not _INCREMENTAL_CACHE:
        cache_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            _INCREMENTAL_CACHE_FILE,
        )
        if os.path.isfile(cache_path):
            try:
                import json
                with open(cache_path, "r", encoding="utf-8") as f:
                    _INCREMENTAL_CACHE = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load cache file: {e}")
                _INCREMENTAL_CACHE = {}
    return _INCREMENTAL_CACHE


def _save_incremental_cache():
    """Persist file modification-time cache to disk."""
    cache_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        _INCREMENTAL_CACHE_FILE,
    )
    try:
        import json
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(_INCREMENTAL_CACHE, f, indent=2)
    except (IOError, OSError) as e:
        logger.warning(f"Failed to save cache file: {e}")


def is_modified_since_last_scan(file_path: str) -> bool:
    """Returns True if file is new or modified since last scan."""
    try:
        mtime = os.path.getmtime(file_path)
    except OSError:
        return False
    cache = _load_incremental_cache()
    return mtime > cache.get(file_path, 0)


def mark_scanned(file_path: str):
    """Record file's current modification time."""
    try:
        _INCREMENTAL_CACHE[file_path] = os.path.getmtime(file_path)
        _save_incremental_cache()
    except OSError:
        pass

# Extensions luôn bỏ qua (hệ thống, không cần phân tích)
SKIP_EXTENSIONS = {
    ".lnk", ".ini", ".log", ".tmp", ".cache", ".db", ".sqlite",
    ".sys",
    ".ico", ".cur", ".ani", ".ttf", ".otf", ".woff", ".woff2",
}

# Extensions thường dùng bởi ransomware
SUSPICIOUS_EXTENSIONS = {
    ".locked", ".locky", ".crypt", ".crypted", ".enc", ".encrypted",
    ".crypto", ".zepto", ".cerber", ".ryuk", ".conti", ".revil",
    ".lockbit", ".blackcat", ".alphv", ".wncry",
}

# PE / nhị phân: luôn hỏi VT (khi bật check_binaries) để không chỉ dựa Entropy+ML
VT_BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".msi", ".scr", ".com", ".pif",
}

# Heuristic thresholds (tăng nhạy nhưng tránh FP)
HEURISTIC_ENTROPY_HIGH = 7.35
HEURISTIC_ENTROPY_EXT_Z = 2.0
HEURISTIC_LOW_COMPRESS  = 0.15
HEURISTIC_LOW_STRUCT    = 0.35

SENSITIVITY_PROFILES = {
    "balanced": {
        "threshold_delta": 0.00,
        "heuristic_boost": 0.08,
        "entropy_high": 7.35,
        "entropy_z": 2.0,
        "low_compress": 0.15,
        "low_struct": 0.35,
    },
    "high_sensitivity": {
        "threshold_delta": -0.05,
        "heuristic_boost": 0.12,
        "entropy_high": 7.25,
        "entropy_z": 1.7,
        "low_compress": 0.18,
        "low_struct": 0.40,
    },
    "paranoid": {
        "threshold_delta": -0.10,
        "heuristic_boost": 0.18,
        "entropy_high": 7.15,
        "entropy_z": 1.4,
        "low_compress": 0.22,
        "low_struct": 0.45,
    },
}

DEFAULT_SENSITIVITY_PROFILE = "balanced"

MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB
MIN_FILE_SIZE = 64                        # 64 bytes
MAX_THREADS   = 8


def apply_vt_risk_fusion(
    risk_level: str,
    *,
    vt_malicious: int,
    vt_suspicious: int,
    vt_total_engines: int,
    vt_error: str,
    fusion_min_engines: int,
    fusion_max_suspicious: int,
    fusion_downgrade: bool,
    yara_boosted: bool,
    injection_found: bool,
) -> tuple[str, str]:
    """
    Khi VirusTotal có đủ engine và 0 malicious (đồng thuận sạch), hạ mức HIGH/CRITICAL
    do ML/heuristic để tránh FP kiểu installer hợp lệ bị CRITICAL.

    Không hạ nếu có YARA boost hoặc PE injection — tín hiệu cục bộ mạnh hơn VT crowd.
    """
    if not fusion_downgrade:
        return risk_level, ""
    if risk_level not in ("HIGH", "CRITICAL"):
        return risk_level, ""
    if vt_error:
        return risk_level, ""
    if vt_total_engines < fusion_min_engines:
        return risk_level, ""
    if vt_malicious > 0:
        return risk_level, ""
    if vt_suspicious > fusion_max_suspicious:
        return risk_level, ""
    if yara_boosted or injection_found:
        return risk_level, ""
    return "MEDIUM", " | VT_consensus_clean(downgrade)"


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
        # v2.5: PE analysis
        "pe_info",               # {"rwx_sections": [...], "suspicious_sections": [...], "is_packed": bool}
        # v3.0: VirusTotal (must be in __slots__ or AttributeError on assign/access)
        "sha256",
        "vt_available",
        "vt_malicious_count",
        "vt_suspicious_count",
        "vt_total_engines",
        "vt_detection_ratio",
        "vt_permalink",
        "vt_from_cache",
        "vt_error",
        "vt_pending",
        # v3.5: Threat Intelligence Correlation
        "ti_available",
        "ti_mb_available",
        "ti_mb_family",
        "ti_mb_signature",
        "ti_mb_first_seen",
        "ti_mb_tags",
        "ti_mb_delivery_method",
        "ti_tf_available",
        "ti_tf_threat_type",
        "ti_tf_malware_family",
        "ti_tf_confidence",
        "ti_tf_tags",
        "ti_otx_available",
        "ti_otx_pulse_count",
        "ti_otx_pulse_names",
        "ti_otx_analysis_metadata",
        "ti_error",
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
        self.error: Optional[str] = None
        # v2
        self.raw_probability     = 0.0
        self.fp_adjusted         = False
        self.effective_threshold = 0.65
        self.fp_reason           = ""
        # v2.1: YARA
        self.yara_matches: list  = []
        self.yara_boosted: bool  = False
        # v2.5: PE analysis results
        self.pe_info: dict = {}  # {"rwx_sections": [...], "suspicious_sections": [...], "is_packed": bool}
        # v3.0: VirusTotal integration
        self.sha256: str = ""
        self.vt_available: bool = False        # VT was checked (cache hit or API call)
        self.vt_malicious_count: int = 0
        self.vt_suspicious_count: int = 0
        self.vt_total_engines: int = 0
        self.vt_detection_ratio: str = "0/0"
        self.vt_permalink: str = ""
        self.vt_from_cache: bool = False
        self.vt_error: str = ""
        self.vt_pending: bool = False          # True if VT query is in progress
        # v3.5: Threat Intelligence Correlation
        self.ti_available: bool = False
        self.ti_mb_available: bool = False
        self.ti_mb_family: str = ""
        self.ti_mb_signature: str = ""
        self.ti_mb_first_seen: str = ""
        self.ti_mb_tags: list = []
        self.ti_mb_delivery_method: str = ""
        self.ti_tf_available: bool = False
        self.ti_tf_threat_type: str = ""
        self.ti_tf_malware_family: str = ""
        self.ti_tf_confidence: int = 0
        self.ti_tf_tags: list = []
        self.ti_otx_available: bool = False
        self.ti_otx_pulse_count: int = 0
        self.ti_otx_pulse_names: list = []
        self.ti_otx_analysis_metadata: dict = {}
        self.ti_error: str = ""

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
            "sha256":             self.sha256,
            "vt_available":       self.vt_available,
            "vt_malicious_count": self.vt_malicious_count,
            "vt_suspicious_count": self.vt_suspicious_count,
            "vt_total_engines":   self.vt_total_engines,
            "vt_detection_ratio": self.vt_detection_ratio,
            "vt_permalink":       self.vt_permalink,
            "vt_from_cache":      self.vt_from_cache,
            "vt_error":           self.vt_error,
            "vt_pending":         self.vt_pending,
            # v3.5: Threat Intelligence
            "ti_available":              self.ti_available,
            "ti_mb_available":           self.ti_mb_available,
            "ti_mb_family":              self.ti_mb_family,
            "ti_mb_signature":           self.ti_mb_signature,
            "ti_mb_first_seen":          self.ti_mb_first_seen,
            "ti_mb_tags":                self.ti_mb_tags,
            "ti_mb_delivery_method":     self.ti_mb_delivery_method,
            "ti_tf_available":           self.ti_tf_available,
            "ti_tf_threat_type":         self.ti_tf_threat_type,
            "ti_tf_malware_family":      self.ti_tf_malware_family,
            "ti_tf_confidence":          self.ti_tf_confidence,
            "ti_tf_tags":                self.ti_tf_tags,
            "ti_otx_available":          self.ti_otx_available,
            "ti_otx_pulse_count":        self.ti_otx_pulse_count,
            "ti_otx_pulse_names":        self.ti_otx_pulse_names,
            "ti_otx_analysis_metadata":  self.ti_otx_analysis_metadata,
            "ti_error":                  self.ti_error,
        }


class Scanner:
    """Multi-threaded file scanner với ML-based detection và FP reduction."""

    def __init__(
        self,
        sensitivity_profile: str = DEFAULT_SENSITIVITY_PROFILE,
        vt_enabled: bool = False,
        vt_auto_check: bool = False,
        vt_malicious_threshold: int = 5,
        vt_suspicious_threshold: int = 3,
    ):
        self._cancel_flag = threading.Event()
        self._lock        = threading.Lock()
        self._results: List[ScanResult] = []
        self._progress    = 0
        self._total       = 0
        self._is_scanning = False
        self._sensitivity_profile = sensitivity_profile
        # VirusTotal settings
        self._vt_enabled  = vt_enabled
        self._vt_auto_check = vt_auto_check          # query VT for ALL files
        self._vt_malicious_threshold = vt_malicious_threshold  # min engines to boost to malicious
        self._vt_suspicious_threshold = vt_suspicious_threshold
        self._vt_client = None
        self._vt_check_binaries = True
        self._vt_fusion_min_engines = 40
        self._vt_fusion_max_suspicious = 2
        self._vt_fusion_downgrade = True

    @property
    def is_scanning(self) -> bool:
        return self._is_scanning

    @property
    def results(self) -> List[ScanResult]:
        return self._results.copy()

    @property
    def sensitivity_profile(self) -> str:
        return self._sensitivity_profile

    def set_sensitivity(self, profile: str):
        """Set sensitivity profile at runtime."""
        if profile in SENSITIVITY_PROFILES:
            self._sensitivity_profile = profile

    def _init_vt_client(self):
        """Lazily initialize VirusTotal client from config."""
        if self._vt_client is not None:
            return
        if not self._vt_enabled:
            return
        try:
            from core.virustotal_client import get_vt_client
            from core.config_manager import config
            api_key = config.get("virustotal.api_key", "")
            self._vt_client = get_vt_client(api_key) if api_key else None
        except Exception:
            self._vt_client = None

    def _query_virustotal(self, sha256: str) -> tuple:
        """
        Query VirusTotal for a file by SHA256.

        Returns (malicious_count, suspicious_count, total_engines, ratio_str,
                 permalink, from_cache, error_str).
        Falls back gracefully if VT is disabled, not configured, or rate-limited.
        """
        self._init_vt_client()
        if self._vt_client is None or not self._vt_client.is_configured():
            return (0, 0, 0, "0/0", "", False, "VT not configured")

        report = self._vt_client.get_file_report(sha256)
        if report is None:
            return (0, 0, 0, "0/0", "", False, "Not found in VT")

        from_cache = bool(report.cached_at)
        return (
            report.malicious_count,
            report.suspicious_count,
            report.total_engines,
            report.detection_ratio,
            report.permalink,
            from_cache,
            "",
        )

    def _init_ti_client(self):
        """Lazily initialize Threat Intelligence client from config."""
        if getattr(self, "_ti_client", None) is not None:
            return
        try:
            from core.threat_intel_client import get_ti_client
            self._ti_client = get_ti_client()
        except Exception:
            self._ti_client = None

    def _query_threat_intel(self, result: ScanResult):
        """
        Tra cuu Threat Intelligence cho mot file da co SHA256.

        Chi goi khi co SHA256 va co nguon TI nao duoc bat trong config.
        Enriches result voi TI data tu MalwareBazaar, ThreatFox, AlienVault OTX.
        """
        if not result.sha256:
            return

        self._init_ti_client()
        ti_client = getattr(self, "_ti_client", None)
        if ti_client is None or not ti_client.is_configured():
            return

        try:
            ti_result = ti_client.lookup_sha256(result.sha256)

            # MalwareBazaar
            result.ti_mb_available        = ti_result.mb_available
            result.ti_mb_family          = ti_result.mb_family
            result.ti_mb_signature       = ti_result.mb_signature
            result.ti_mb_first_seen      = ti_result.mb_first_seen
            result.ti_mb_tags            = ti_result.mb_tags
            result.ti_mb_delivery_method = ti_result.mb_delivery_method

            # ThreatFox
            result.ti_tf_available        = ti_result.tf_available
            result.ti_tf_threat_type     = ti_result.tf_threat_type
            result.ti_tf_malware_family   = ti_result.tf_malware_family
            result.ti_tf_confidence       = ti_result.tf_confidence
            result.ti_tf_tags             = ti_result.tf_tags

            # AlienVault OTX
            result.ti_otx_available          = ti_result.otx_available
            result.ti_otx_pulse_count        = ti_result.otx_pulse_count
            result.ti_otx_pulse_names         = ti_result.otx_pulse_names
            result.ti_otx_analysis_metadata   = ti_result.otx_analysis_metadata

            # Merge errors
            errors = []
            if ti_result.mb_error:
                errors.append(f"MB:{ti_result.mb_error}")
            if ti_result.tf_error:
                errors.append(f"TF:{ti_result.tf_error}")
            if ti_result.otx_error:
                errors.append(f"OTX:{ti_result.otx_error}")
            result.ti_error = "; ".join(errors)

            result.ti_available = ti_result.has_any_ti()

        except Exception as e:
            result.ti_error = str(e)[:100]

    def _compute_sha256(self, file_path: str) -> str:
        """Compute SHA256 of a file."""
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""

    def cancel(self):
        """Hủy scan đang chạy."""
        self._cancel_flag.set()

    def _collect_files(self, directory: str, recursive: bool) -> List[str]:
        """Thu thập danh sách files cần quét."""
        if os.path.isfile(directory):
            try:
                size = os.path.getsize(directory)
                if MIN_FILE_SIZE <= size <= MAX_FILE_SIZE:
                    return [directory]
            except OSError:
                pass
            return []

        files = []
        try:
            if recursive:
                for root, dirs, filenames in os.walk(directory):
                    # Filter out unwanted directories
                    skip_dirs = {
                        "System Volume Information",
                        "$Recycle.Bin",
                        "Windows",
                        "__pycache__",
                        "node_modules",
                        ".git",
                    }
                    dirs[:] = [  # type: ignore[assignment]
                        d for d in dirs
                        if not d.startswith(".") and d not in skip_dirs
                    ]
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

        # Compute SHA256 for VirusTotal lookup
        try:
            with open(file_path, "rb") as f:
                result.sha256 = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            result.sha256 = ""

        # Sensitivity profile (per-instance)
        profile = SENSITIVITY_PROFILES.get(
            self._sensitivity_profile,
            SENSITIVITY_PROFILES["balanced"],
        )

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

            # ── Heuristic signal (fast) ──
            ext = os.path.splitext(file_path)[1].lower()
            entropy_z = float(features[10]) if len(features) > 10 else 0.0
            compression_est = float(features[12]) if len(features) > 12 else 0.0
            structural_consistency = float(features[13]) if len(features) > 13 else 0.0
            suspicious_ext = ext in SUSPICIOUS_EXTENSIONS
            
            # ── PE structural analysis (v2.1) ──
            injection_found = False
            if ext in {".exe", ".dll", ".sys"}:
                pe_res = analyze_pe(file_path)
                result.pe_info = pe_res.to_dict()
                if pe_res.is_suspicious():
                    injection_found = True
                    result.fp_reason += f" | PE_INJECTION({','.join(pe_res.rwx_sections + pe_res.suspicious_sections)})"

            heuristic_hit = (
                entropy_z >= profile["entropy_z"] and
                features[0] >= profile["entropy_high"] and
                compression_est <= profile["low_compress"] and
                structural_consistency <= profile["low_struct"]
            ) or suspicious_ext or injection_found

            # ── Bước 4: FP Reduction ──
            adjusted_proba, eff_threshold, reduction_reason = apply_fp_reduction(
                file_path, raw_proba, base_threshold
            )
            # Sensitivity profile: hạ threshold hiệu dụng (không thấp hơn 0.35)
            eff_threshold = max(0.35, eff_threshold + profile["threshold_delta"])

            # Heuristic boost (không vượt quá 0.95, không ghi đè FP reducer)
            if heuristic_hit:
                boost_val = profile["heuristic_boost"]
                if injection_found:
                    boost_val += 0.20  # Boost mạnh hơn nếu có dấu hiệu injection
                adjusted_proba = min(max(adjusted_proba, raw_proba + boost_val), 0.95)
                if not injection_found:
                    reduction_reason += " | heuristic_boost"

            result.probability         = adjusted_proba
            result.effective_threshold = eff_threshold
            # Gộp các lý do điều chỉnh
            result.fp_reason          += f" | {reduction_reason}"
            result.fp_adjusted         = (adjusted_proba != raw_proba or eff_threshold != base_threshold)

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

            # #region agent debug
            try:
                _debug_log_path = os.path.normpath(
                    os.path.join(os.path.dirname(__file__), "..", "debug-4602d0.log")
                )
                _debug_payload = {
                    "sessionId": "4602d0",
                    "timestamp": int(time.time() * 1000),
                    "location": "scanner.py:_scan_one",
                    "message": "pipeline_trace",
                    "data": {
                        "filename": result.filename,
                        "risk_level": result.risk_level,
                        "raw_proba": raw_proba,
                        "adjusted_proba": adjusted_proba,
                        "eff_threshold": eff_threshold,
                        "heuristic_hit": heuristic_hit,
                        "injection_found": injection_found,
                        "fp_reason": result.fp_reason,
                        "yara_boosted": result.yara_boosted,
                        "yara_match_count": len(yara_matches),
                        "yara_severities": [m.severity for m in yara_matches] if yara_matches else [],
                        "entropy": features[0],
                        "entropy_z": entropy_z,
                        "compression": compression_est,
                        "struct_consistency": structural_consistency,
                        "suspicious_ext": suspicious_ext,
                        "base_threshold": base_threshold,
                    },
                    "hypothesisId": "UNIKEY",
                }
                with open(_debug_log_path, "a", encoding="utf-8") as _f:
                    _f.write(json.dumps(_debug_payload, ensure_ascii=False) + "\n")
            except Exception:
                pass
            # #endregion

            # ── Bước 7: VirusTotal Lookup (v3.0) ──
            # Query VT khi: toàn bộ file (auto_check), HIGH/CRITICAL, hoặc nhị phân (.exe…)
            binary_vt = ext in VT_BINARY_EXTENSIONS and self._vt_check_binaries
            should_vt = (
                self._vt_auto_check
                or result.risk_level in ("HIGH", "CRITICAL")
                or binary_vt
            )
            if self._vt_enabled and should_vt and result.sha256:
                result.vt_pending = True
                vt_mal, vt_susp, vt_total, vt_ratio, vt_perma, vt_cache, vt_err = \
                    self._query_virustotal(result.sha256)
                result.vt_pending = False
                result.vt_malicious_count    = vt_mal
                result.vt_suspicious_count   = vt_susp
                result.vt_total_engines      = vt_total
                result.vt_detection_ratio    = vt_ratio
                result.vt_permalink          = vt_perma
                result.vt_from_cache         = vt_cache
                result.vt_error              = vt_err
                # Chỉ coi là có báo cáo VT hợp lệ khi có engine count (không phải 404)
                result.vt_available = bool(vt_total > 0 and not vt_err)

                # Override risk level nếu VT rõ ràng là malicious
                if vt_mal >= self._vt_malicious_threshold:
                    result.risk_level = "CRITICAL"
                    result.label      = 1
                    result.fp_reason += f" | VT({vt_mal}/{vt_total})"
                elif vt_mal >= 1 and vt_mal < self._vt_malicious_threshold:
                    # VT có phát hiện nhưng chưa đủ threshold → nâng lên HIGH
                    if result.risk_level not in ("CRITICAL",):
                        result.risk_level = "HIGH"
                        result.label      = 1
                        result.fp_reason += f" | VT_suspicious({vt_mal}/{vt_total})"

                # Gộp VT + ML: đồng thuận sạch → hạ CRITICAL/HIGH (tránh FP installer)
                new_risk, fusion_note = apply_vt_risk_fusion(
                    result.risk_level,
                    vt_malicious=vt_mal,
                    vt_suspicious=vt_susp,
                    vt_total_engines=vt_total,
                    vt_error=vt_err,
                    fusion_min_engines=self._vt_fusion_min_engines,
                    fusion_max_suspicious=self._vt_fusion_max_suspicious,
                    fusion_downgrade=self._vt_fusion_downgrade,
                    yara_boosted=result.yara_boosted,
                    injection_found=injection_found,
                )
                if fusion_note:
                    result.risk_level = new_risk
                    if new_risk == "MEDIUM":
                        result.label = 1 if result.probability >= result.effective_threshold else 0
                    result.fp_reason += fusion_note

            # ── Bước 8: Threat Intelligence Correlation (v3.5) ──
            self._query_threat_intel(result)

        except PermissionError:
            result.error = "Không có quyền đọc file"
        except Exception as e:
            error_str = str(e)
            result.error = error_str[:100] if len(error_str) > 100 else error_str  # type: ignore[index]

        result.scan_time_ms = (time.perf_counter() - t_start) * 1000
        return result

    def scan(
        self,
        directory: str,
        recursive: bool = True,
        on_progress: Optional[Callable[[int, int, "ScanResult"], None]] = None,
        on_complete: Optional[Callable[[List["ScanResult"],], None]] = None,
        on_error:    Optional[Callable[[str], None]] = None,
        max_threads: int = MAX_THREADS,
        scan_mode: str = "full",
        vt_enabled: bool = False,
        vt_auto_check: bool = False,
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
        scan_mode   : "full" | "quick" | "incremental"
                      - "full":       quét tất cả files
                      - "quick":      non-recursive
                      - "incremental": chỉ quét files mới hoặc đã sửa đổi
        vt_enabled  : bật tích hợp VirusTotal
        vt_auto_check: query VT cho TẤT CẢ files (tốn rate limit, dùng khi cần)
        """
        if scan_mode == "full" and not recursive:
            scan_mode = "quick"

        def _run():
            self._cancel_flag.clear()
            self._results.clear()
            self._is_scanning = True
            self._progress    = 0
            self._vt_enabled    = vt_enabled
            self._vt_auto_check = vt_auto_check
            try:
                from core.config_manager import config
                self._vt_check_binaries = bool(
                    config.get("virustotal.check_binaries", True)
                )
                self._vt_fusion_min_engines = int(
                    config.get("virustotal.fusion_min_engines", 40)
                )
                self._vt_fusion_max_suspicious = int(
                    config.get("virustotal.fusion_max_suspicious", 2)
                )
                self._vt_fusion_downgrade = bool(
                    config.get("virustotal.fusion_downgrade", True)
                )
            except Exception:
                self._vt_check_binaries = True
                self._vt_fusion_min_engines = 40
                self._vt_fusion_max_suspicious = 2
                self._vt_fusion_downgrade = True

            try:
                files = self._collect_files(directory, recursive)

                # ── Incremental: skip already-scanned unmodified files ──
                if scan_mode == "incremental":
                    original_count = len(files)
                    files = [f for f in files if is_modified_since_last_scan(f)]
                    skipped = original_count - len(files)
                    if skipped > 0:
                        logger.info("Incremental: skipped %d unchanged files", skipped)

                self._total = len(files)

                if self._total == 0:
                    if on_complete:
                        on_complete([])
                    return

                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    def scan_file_wrapper(fp: str) -> ScanResult:
                        result = self._scan_single_file(fp)
                        if scan_mode == "incremental":
                            mark_scanned(fp)
                        return result
                    future_to_path = {
                        executor.submit(scan_file_wrapper, fp): fp  # type: ignore[arg-type]
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
                logger.error("Scan error: %s", e)
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
            "avg_entropy":      round(avg_entropy * 10000) / 10000,
            "fp_adjusted_count": fp_adjusted,  # v2: số file được điều chỉnh FP
        }