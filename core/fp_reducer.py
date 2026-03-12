"""
fp_reducer.py — v2.0 (MỚI)
============================
Module chống False Positive (FP) độc lập.

Chiến lược giảm FP theo 3 tầng:
  Tầng 1: Whitelist — file system objects không bao giờ là ransomware
  Tầng 2: Per-extension Threshold — PNG/ZIP dùng threshold cao hơn
  Tầng 3: Magic Bytes Validator — file có magic bytes hợp lệ → giảm score

Root Cause FP (PNG screenshots bị flagged CRITICAL):
  ❌ PNG entropy tự nhiên: 7.6–7.9 bits/byte (do zlib compression)
  ❌ Model v1 không có training samples cho compressed PNG
  ❌ Threshold cứng 0.5 → tất cả high-entropy files bị flagged
  ✅ Giải pháp: per-extension threshold + magic bytes verification + whitelist
"""

import os
import struct
from typing import Optional, Dict, Tuple, Set
import numpy as np

# ─────────────────────────────────────────────────────────────
# TẦNG 1: Whitelist — Extensions không bao giờ bị scan
# ─────────────────────────────────────────────────────────────

# Extensions hệ thống/font/metadata → skip hoàn toàn
ALWAYS_SAFE_EXTENSIONS: Set[str] = {
    # Font
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    # Icon/cursor
    ".ico", ".cur", ".ani",
    # Hệ thống Windows
    ".lnk", ".url", ".desktop",
    # Log/config
    ".log", ".ini", ".cfg", ".conf",
    # Cache/temp
    ".tmp", ".temp", ".cache", ".bak",
    # Database index
    ".idx", ".db-wal", ".db-shm",
    # Thumbnail
    ".thm",
}

# Paths chứa từ khóa này → skip
ALWAYS_SAFE_PATH_KEYWORDS: Set[str] = {
    "windows\\system32",
    "windows\\syswow64",
    "program files\\windows defender",
    "/proc/",
    "/sys/",
    "/dev/",
    "/__pycache__/",
    "/site-packages/",
    "/.git/",
    "/node_modules/",
}

# ─────────────────────────────────────────────────────────────
# TẦNG 2: Per-extension Threshold
# Các extension có entropy cao tự nhiên cần threshold CAO HƠN
# để tránh FP
# ─────────────────────────────────────────────────────────────

# Format: ext → ngưỡng xác suất để bị coi là ENCRYPTED
# Giá trị cao hơn = khó bị flagged hơn (giảm FP)
EXTENSION_THRESHOLDS: Dict[str, float] = {
    # Ảnh nén (entropy tự nhiên cao: 7.5–7.9)
    ".png":   0.80,   # PNG: zlib compression → entropy rất cao, cần threshold 0.80
    ".jpg":   0.80,
    ".jpeg":  0.80,
    ".gif":   0.80,
    ".webp":  0.80,
    ".heic":  0.80,
    ".avif":  0.80,

    # Video/Audio nén (entropy tự nhiên cao: 7.0–8.0)
    ".mp4":   0.82,
    ".mkv":   0.82,
    ".avi":   0.82,
    ".mov":   0.82,
    ".mp3":   0.80,
    ".aac":   0.80,
    ".flac":  0.78,
    ".opus":  0.80,

    # Archives (entropy cao do nén)
    ".zip":   0.82,
    ".gz":    0.82,
    ".bz2":   0.82,
    ".xz":    0.82,
    ".7z":    0.82,
    ".rar":   0.82,
    ".tar":   0.75,

    # Office (ZIP-based, entropy trung bình)
    ".docx":  0.75,
    ".xlsx":  0.75,
    ".pptx":  0.75,
    ".odt":   0.75,
    ".ods":   0.75,

    # Executables (PE headers + code sections = entropy hỗn hợp)
    ".exe":   0.85,   # exe thường bị pack → entropy cao, cần threshold cao
    ".dll":   0.85,
    ".so":    0.82,
    ".dylib": 0.82,

    # Python/scripts (entropy thấp)
    ".py":    0.60,
    ".js":    0.60,
    ".ts":    0.60,
    ".php":   0.60,

    # Documents thuần text
    ".pdf":   0.70,
    ".txt":   0.55,
    ".csv":   0.55,
    ".json":  0.55,
    ".xml":   0.55,
    ".html":  0.55,
    ".md":    0.55,
}

# Threshold mặc định cho extensions không có trong danh sách
DEFAULT_EXTENSION_THRESHOLD = 0.65

# ─────────────────────────────────────────────────────────────
# TẦNG 3: Magic Bytes Validator
# File có magic bytes hợp lệ → giảm probability score
# ─────────────────────────────────────────────────────────────

# Magic bytes signature DB (mở rộng)
MAGIC_SIGNATURES: Dict[str, bytes] = {
    ".png":  b"\x89PNG\r\n\x1a\n",
    ".jpg":  b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".gif":  b"GIF8",
    ".zip":  b"PK\x03\x04",
    ".docx": b"PK\x03\x04",
    ".xlsx": b"PK\x03\x04",
    ".pptx": b"PK\x03\x04",
    ".pdf":  b"%PDF",
    ".exe":  b"MZ",
    ".dll":  b"MZ",
    ".elf":  b"\x7fELF",
    ".mp4":  None,  # Check offset 4: 'ftyp'
    ".mov":  None,  # Check offset 4: 'ftyp' hoặc 'moov'
    ".mp3":  b"ID3",
    ".flac": b"fLaC",
    ".webp": None,  # Check bytes 0-3: 'RIFF', bytes 8-11: 'WEBP'
    ".7z":   b"7z\xbc\xaf'\x1c",
    ".gz":   b"\x1f\x8b",
    ".bz2":  b"BZh",
    ".rar":  b"Rar!\x1a\x07",
    ".xz":   b"\xfd7zXZ\x00",
}

# Discount: nếu magic bytes hợp lệ → nhân probability với factor này
# 0.7 = giảm 30% probability (giảm FP đáng kể)
MAGIC_BYTES_DISCOUNT_FACTOR = 0.70


def check_path_whitelist(file_path: str) -> bool:
    """
    Tầng 1: Kiểm tra xem file có nằm trong whitelist không.

    Returns: True nếu file AN TOÀN (bỏ qua scan)
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext in ALWAYS_SAFE_EXTENSIONS:
        return True

    path_lower = file_path.lower().replace("\\", "/")
    for keyword in ALWAYS_SAFE_PATH_KEYWORDS:
        if keyword in path_lower:
            return True

    return False


def get_extension_threshold(file_path: str, base_threshold: float) -> float:
    """
    Tầng 2: Lấy threshold theo extension.

    Nếu extension có entry trong EXTENSION_THRESHOLDS → dùng giá trị đó.
    Ngược lại → dùng base_threshold (từ model/GUI).
    Luôn trả về giá trị ≥ base_threshold (không bao giờ LÀM KHÓ HƠN để phát hiện).
    """
    ext = os.path.splitext(file_path)[1].lower()
    ext_threshold = EXTENSION_THRESHOLDS.get(ext, DEFAULT_EXTENSION_THRESHOLD)
    # Lấy max để đảm bảo không giảm threshold dưới mức base
    return max(ext_threshold, base_threshold)


def check_magic_bytes(file_path: str) -> Tuple[bool, bool]:
    """
    Tầng 3: Kiểm tra magic bytes của file.

    Returns: (has_signature_entry, magic_bytes_valid)
      has_signature_entry = extension có trong DB
      magic_bytes_valid   = magic bytes thực tế khớp với kỳ vọng
    """
    ext = os.path.splitext(file_path)[1].lower()

    if ext not in MAGIC_SIGNATURES:
        return False, True  # Không có entry → không kết luận

    expected = MAGIC_SIGNATURES[ext]
    if expected is None:
        # Special cases
        return _check_special_magic(file_path, ext)

    try:
        with open(file_path, "rb") as f:
            header = f.read(max(len(expected), 12))
        valid = header[:len(expected)] == expected
        return True, valid
    except Exception:
        return True, False


def _check_special_magic(file_path: str, ext: str) -> Tuple[bool, bool]:
    """Kiểm tra magic bytes cho các format đặc biệt."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(12)

        if ext == ".mp4" or ext == ".mov":
            # Bytes 4–7 phải là 'ftyp', 'moov', hoặc 'mdat'
            box_type = header[4:8]
            valid = box_type in {b"ftyp", b"moov", b"mdat", b"free", b"jP  "}
            return True, valid

        if ext == ".webp":
            # Bytes 0–3: 'RIFF', bytes 8–11: 'WEBP'
            valid = header[:4] == b"RIFF" and header[8:12] == b"WEBP"
            return True, valid

    except Exception:
        pass
    return True, False


def apply_fp_reduction(
    file_path: str,
    probability: float,
    base_threshold: float,
) -> Tuple[float, float, str]:
    """
    Áp dụng toàn bộ pipeline FP reduction cho một file.

    Parameters
    ----------
    file_path      : đường dẫn file cần kiểm tra
    probability    : xác suất ENCRYPTED từ ML model (0.0–1.0)
    base_threshold : threshold từ model/GUI

    Returns
    -------
    (adjusted_probability, effective_threshold, reduction_reason)
      adjusted_probability : xác suất sau khi điều chỉnh
      effective_threshold  : threshold hiệu dụng cho file này
      reduction_reason     : lý do giảm (để debug/log)
    """
    reasons = []
    adjusted_prob = probability

    # Tầng 2: Per-extension threshold
    effective_threshold = get_extension_threshold(file_path, base_threshold)
    if effective_threshold > base_threshold:
        reasons.append(f"ext_threshold={effective_threshold:.2f}")

    # Tầng 3: Magic bytes discount
    has_sig, magic_valid = check_magic_bytes(file_path)
    if has_sig and magic_valid:
        # Magic bytes hợp lệ → giảm probability (file có cấu trúc đúng)
        adjusted_prob = probability * MAGIC_BYTES_DISCOUNT_FACTOR
        reasons.append(f"magic_ok→prob×{MAGIC_BYTES_DISCOUNT_FACTOR}")
    elif has_sig and not magic_valid:
        # Magic bytes SAI → tăng nhẹ probability (suspicious)
        adjusted_prob = min(probability * 1.15, 0.99)
        reasons.append("magic_mismatch→prob×1.15")

    reason_str = "; ".join(reasons) if reasons else "no_adjustment"
    return adjusted_prob, effective_threshold, reason_str


def get_fp_stats(results: list) -> Dict:
    """
    Tính FP statistics từ danh sách ScanResult để hiển thị trong GUI.

    Parameters
    ----------
    results : list of ScanResult objects (phải có .label, .probability, .extension)

    Returns
    -------
    dict với các thông số FP
    """
    if not results:
        return {}

    total      = len(results)
    flagged    = sum(1 for r in results if getattr(r, "label", 0) == 1)
    fp_rate    = flagged / total if total > 0 else 0.0

    # Thống kê theo extension
    ext_stats: Dict[str, Dict] = {}
    for r in results:
        ext = getattr(r, "extension", "unknown")
        if ext not in ext_stats:
            ext_stats[ext] = {"total": 0, "flagged": 0}
        ext_stats[ext]["total"] += 1
        if getattr(r, "label", 0) == 1:
            ext_stats[ext]["flagged"] += 1

    # Extensions có FP rate cao nhất
    high_fp_exts = {
        ext: stats
        for ext, stats in ext_stats.items()
        if stats["total"] > 0 and stats["flagged"] / stats["total"] > 0.3
    }

    return {
        "total":         total,
        "flagged":       flagged,
        "fp_rate":       round(fp_rate, 4),
        "ext_stats":     ext_stats,
        "high_fp_exts":  high_fp_exts,
    }
