"""
dataset_generator.py — v2.0 (Anti-FP Edition)
===============================================
Dataset mở rộng với các benign samples giống file thực tế nhất có thể
để mô hình học cách phân biệt:
  - PNG/JPEG/ZIP thật  vs  file bị mã hóa giả vờ có extension .png
  - PE executables     vs  file được packed/mã hóa hoàn toàn
  - Python scripts     vs  shellcode/payload

SAFE samples (7 loại, tăng từ 3):
  1. text_ascii        - Text/code thông thường (entropy thấp)
  2. binary_structured - Binary có cấu trúc (MZ header)
  3. compressed_png    - Giả lập PNG với magic bytes hợp lệ + entropy cao tự nhiên
  4. compressed_zip    - Giả lập ZIP với magic bytes hợp lệ
  5. compressed_media  - Giả lập MP4/MP3 với entropy cao
  6. pe_valid          - PE executable hợp lệ (có import table, sections)
  7. office_doc        - Office document (ZIP-based, structured)

ENCRYPTED samples (5 loại, tăng từ 3):
  1. full_aes          - Mã hóa hoàn toàn (AES/ChaCha20)
  2. intermittent      - Intermittent encryption (LockBit 3.0)
  3. header_only       - Chỉ mã hóa header (HeadOnly mode)
  4. disguised_png     - File mã hóa giả vờ là PNG (extension mismatch)
  5. disguised_zip     - File mã hóa giả vờ là ZIP
"""

import os
import struct
import numpy as np
import pandas as pd
from typing import Tuple
from core.feature_extractor import extract_features, FEATURE_NAMES, N_FEATURES

RNG = np.random.default_rng(seed=42)

# ─── SAFE sample generators ───────────────────────────────────

def _make_safe_text(size: int) -> bytes:
    """Text ASCII bình thường (entropy ~3.5-5.0)."""
    chars = list("abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ\n\t.,;:!?0123456789")
    weights = [7.8,2.0,4.0,4.2,13.0,2.2,2.0,6.1,7.0,0.15,0.77,4.0,2.4,
               6.7,7.5,1.9,0.1,6.0,6.3,9.0,2.8,0.98,2.4,0.15,2.0,0.07,
               5.0,2.5,2.8,1.5,3.5,1.2,2.5,1.0,2.0,0.5,0.2,0.2,0.1,0.5,
               0.2,0.3,0.2,2.0,1.5,1.0,0.8,0.5,0.3,0.2,0.2,1.5,2.0,0.8,
               0.8,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,
               0.5,0.5,0.5,0.5,0.5,0.5,0.5]
    while len(weights) < len(chars):
        weights.append(0.5)
    weights = np.array(weights[:len(chars)])
    weights /= weights.sum()
    chosen = RNG.choice(len(chars), size=size, p=weights)
    return "".join(chars[i] for i in chosen).encode("ascii", errors="replace")


def _make_safe_binary(size: int) -> bytes:
    """Binary có cấu trúc (entropy ~2.0-4.5)."""
    header = b"\x4D\x5A" + bytes(RNG.integers(0, 100, 62, dtype=np.uint8))
    body_size = max(1, size - 64)
    body_arr = np.zeros(body_size, dtype=np.uint8)
    n_random = int(body_size * 0.15)
    if n_random > 0:
        rnd_pos = RNG.choice(body_size, n_random, replace=False)
        body_arr[rnd_pos] = RNG.integers(1, 256, n_random, dtype=np.uint8)
    return header + bytes(body_arr)


def _make_safe_png(size: int) -> bytes:
    """
    Giả lập PNG với magic bytes hợp lệ + entropy cao tự nhiên.
    KEY: magic bytes = \x89PNG → is_known_benign_format = 1
         extension_entropy_z sẽ gần 0 (entropy ~7.6 là bình thường cho PNG)
    """
    # PNG signature
    png_sig = b"\x89PNG\r\n\x1a\n"
    # IHDR chunk giả
    ihdr_data = struct.pack(">IIBBBBB", 
                            int(RNG.integers(100, 2000)),   # width
                            int(RNG.integers(100, 2000)),   # height
                            8,   # bit depth
                            2,   # color type (RGB)
                            0, 0, 0)
    ihdr_crc = bytes(RNG.integers(0, 256, 4, dtype=np.uint8))
    ihdr_chunk = b"\x00\x00\x00\x0DIHDR" + ihdr_data + ihdr_crc
    
    # IDAT chunk: dữ liệu nén giả (entropy cao ~7.5-7.8)
    idat_size = max(0, size - len(png_sig) - len(ihdr_chunk) - 12)
    if idat_size > 0:
        # PNG data: entropy cao nhưng có pattern (không hoàn toàn random)
        idat_body = bytes(RNG.integers(0, 256, idat_size, dtype=np.uint8))
        # Giảm 10% entropy bằng cách lặp một số byte
        idat_arr = bytearray(idat_body)
        for i in range(0, idat_size, 100):
            idat_arr[i] = idat_arr[i] % 128  # slightly non-uniform
        idat_body = bytes(idat_arr)
    else:
        idat_body = b""
    
    idat_chunk = struct.pack(">I", len(idat_body)) + b"IDAT" + idat_body + \
                 bytes(RNG.integers(0, 256, 4, dtype=np.uint8))
    iend_chunk = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    
    result = png_sig + ihdr_chunk + idat_chunk + iend_chunk
    return result[:size] if len(result) > size else result + b"\x00" * (size - len(result))


def _make_safe_zip(size: int) -> bytes:
    """
    Giả lập ZIP với magic bytes PK\x03\x04 + entropy cao.
    Phân biệt với file mã hóa: structural_consistency cao, magic bytes khớp.
    """
    pk_header = b"PK\x03\x04"
    # ZIP local file header
    zip_header = pk_header + bytes([
        0x14, 0x00,   # version needed
        0x00, 0x00,   # general purpose bit flag
        0x08, 0x00,   # compression method (deflated)
        0x00, 0x00,   # last mod file time
        0x00, 0x00,   # last mod file date
    ]) + bytes(RNG.integers(0, 256, 4, dtype=np.uint8))  # CRC-32
    
    # Compressed data: entropy cao tương tự PNG
    body_size = max(0, size - len(zip_header) - 8)
    body = bytes(RNG.integers(0, 256, body_size, dtype=np.uint8))
    # Thêm chút structure
    body_arr = bytearray(body)
    for i in range(0, len(body_arr), 50):
        body_arr[i] = body_arr[i] % 200  # slight bias
    
    # End of central directory record
    eocd = b"PK\x05\x06" + b"\x00" * 18
    
    result = zip_header + bytes(body_arr) + eocd
    return result[:size] if len(result) > size else result + b"\x00" * (size - len(result))


def _make_safe_media(size: int) -> bytes:
    """
    Giả lập file MP4/media với entropy cao tự nhiên.
    Magic bytes: ftyp box
    """
    # MP4 ftyp box
    ftyp_box = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2avc1mp41"
    
    body_size = max(0, size - len(ftyp_box))
    # Media data: entropy cao nhưng có motion vectors pattern
    body = bytes(RNG.integers(0, 256, body_size, dtype=np.uint8))
    body_arr = bytearray(body)
    # Thêm NAL unit headers (0x00 0x00 0x00 0x01) định kỳ
    for i in range(0, len(body_arr) - 4, 200):
        body_arr[i:i+4] = [0, 0, 0, 1]
    
    result = ftyp_box + bytes(body_arr)
    return result[:size] if len(result) > size else result + b"\x00" * (size - len(result))


def _make_safe_pe_valid(size: int) -> bytes:
    """
    PE executable hợp lệ với MZ header, PE signature, Import section.
    entropy trung bình ~5.0-6.5 (không hoàn toàn random).
    """
    # DOS header
    dos_header = b"MZ" + bytes(RNG.integers(0, 256, 58, dtype=np.uint8))
    # PE offset at 0x3C
    pe_offset = 0x80
    dos_header = dos_header[:0x3C] + struct.pack("<I", pe_offset) + dos_header[0x40:]
    dos_stub = bytes(RNG.integers(0, 100, pe_offset - len(dos_header), dtype=np.uint8))
    
    # PE signature + COFF header
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIH H", 
                       0x014c,     # Machine: x86
                       3,          # NumberOfSections
                       0,          # TimeDateStamp
                       0, 0,       # PointerToSymbolTable, NumberOfSymbols
                       0xE0,       # SizeOfOptionalHeader
                       0x0102)     # Characteristics
    
    # Optional header
    opt_header = struct.pack("<HBB", 0x010B, 14, 0)  # Magic, MajorLinkerVersion, Minor
    opt_header += bytes(RNG.integers(0, 256, 0xE0 - 4, dtype=np.uint8))
    
    # Sections: .text (code), .data, .rdata
    sections = b""
    for name in [b".text\x00\x00\x00", b".data\x00\x00\x00", b".rdata\x00\x00"]:
        section_size = max(0, (size - pe_offset - 24 - 0xE0 - 120) // 3)
        sections += name + struct.pack("<IIIIIIHHI",
            section_size, 0x1000, section_size, pe_offset + 200,
            0, 0, 0, 0, 0x60000020)
    
    # Code section: entropy thấp hơn random (instructions có pattern)
    code_size = max(0, size - pe_offset - 24 - 0xE0 - len(sections) - len(dos_stub) - len(dos_header))
    code = bytes(RNG.integers(0, 180, code_size, dtype=np.uint8))  # max 180 để tránh entropy quá cao
    
    result = dos_header + dos_stub + pe_sig + coff + opt_header + sections + code
    return (result + b"\x00" * (size - len(result)))[:size]


def _make_safe_office(size: int) -> bytes:
    """
    Office document (docx/xlsx) = ZIP format bên trong.
    Tương tự ZIP nhưng có [Content_Types].xml ở đầu.
    """
    # docx = ZIP với magic bytes PK
    return _make_safe_zip(size)


# ─── ENCRYPTED sample generators ──────────────────────────────

def _make_full_encrypted(size: int) -> bytes:
    """Mã hóa hoàn toàn AES/ChaCha20: entropy ~7.95-8.0."""
    return bytes(RNG.integers(0, 256, size, dtype=np.uint8))


def _make_partial_encrypted(size: int, ratio: float = None) -> bytes:
    """Intermittent encryption (LockBit 3.0 style)."""
    if ratio is None:
        ratio = float(RNG.uniform(0.3, 0.8))
    data = bytearray(_make_safe_text(size))
    encrypted_len = int(size * ratio)
    encrypted_part = bytes(RNG.integers(0, 256, encrypted_len, dtype=np.uint8))
    start = int(RNG.integers(0, max(1, size - encrypted_len)))
    data[start:start + encrypted_len] = encrypted_part
    return bytes(data)


def _make_header_encrypted(size: int) -> bytes:
    """HeadOnly mode: chỉ 20-40% đầu bị mã hóa."""
    enc_size = int(size * float(RNG.uniform(0.20, 0.40)))
    encrypted = bytes(RNG.integers(0, 256, enc_size, dtype=np.uint8))
    plain = _make_safe_binary(max(1, size - enc_size))
    return encrypted + plain


def _make_disguised_png(size: int) -> bytes:
    """
    File mã hóa giả vờ là PNG — magic bytes KHÔNG khớp.
    
    KEY: đây là cách ransomware đổi tên sau khi mã hóa.
    is_known_benign_format = 0 (vì magic bytes sai)
    magic_bytes_mismatch = 1
    """
    # Hoàn toàn random, KHÔNG có PNG magic bytes
    return bytes(RNG.integers(0, 256, size, dtype=np.uint8))


def _make_disguised_zip(size: int) -> bytes:
    """File mã hóa giả vờ là ZIP — magic bytes không khớp."""
    return bytes(RNG.integers(0, 256, size, dtype=np.uint8))


# ─── Main generator ───────────────────────────────────────────

def generate_synthetic_dataset(
    n_safe: int = 1000,
    n_encrypted: int = 1000,
    output_dir: str = None,
    save_files: bool = False,
    verbose: bool = True
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Tạo dataset tổng hợp v2 với các benign samples đa dạng.
    
    Phân phối SAFE (7 loại):
      25% text/code, 20% binary_pe, 15% png, 15% zip, 
      10% media, 10% office, 5% binary_misc
    
    Phân phối ENCRYPTED (5 loại):
      35% full_aes, 25% intermittent, 15% header_only, 
      15% disguised_png, 10% disguised_zip
    """
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    samples_dir = os.path.join(output_dir, "samples")
    os.makedirs(samples_dir, exist_ok=True)

    all_features, all_labels = [], []

    # ── SAFE samples ──
    generators_safe = [
        ("text_ascii",      _make_safe_text,       int(n_safe * 0.25), ".txt"),
        ("pe_valid",        _make_safe_pe_valid,   int(n_safe * 0.20), ".exe"),
        ("compressed_png",  _make_safe_png,        int(n_safe * 0.15), ".png"),
        ("compressed_zip",  _make_safe_zip,        int(n_safe * 0.15), ".zip"),
        ("media_mp4",       _make_safe_media,      int(n_safe * 0.10), ".mp4"),
        ("office_doc",      _make_safe_office,     int(n_safe * 0.10), ".docx"),
        ("binary_struct",   _make_safe_binary,     int(n_safe * 0.05), ".bin"),
    ]

    if verbose:
        print(f"[DatasetGen v2] SAFE: {n_safe} mẫu | ENCRYPTED: {n_encrypted} mẫu")

    for gen_name, gen_fn, count, ext in generators_safe:
        for i in range(count):
            size = int(RNG.integers(4096, 524288))
            tmp_path = os.path.join(samples_dir, f"safe_{gen_name}_{i:04d}{ext}")
            try:
                data = gen_fn(size)
                with open(tmp_path, "wb") as f:
                    f.write(data)
                feats = extract_features(tmp_path)
                if feats is not None and len(feats) == N_FEATURES:
                    all_features.append(feats)
                    all_labels.append(0)
            except Exception:
                pass
            finally:
                if not save_files and os.path.exists(tmp_path):
                    os.remove(tmp_path)
        if verbose:
            print(f"  ✓ SAFE [{gen_name:18s}] {count:4d} mẫu  ext={ext}")

    # ── ENCRYPTED samples ──
    generators_enc = [
        ("full_aes",        _make_full_encrypted,    int(n_encrypted * 0.35), ".enc"),
        ("intermittent",    _make_partial_encrypted, int(n_encrypted * 0.25), ".enc"),
        ("header_only",     _make_header_encrypted,  int(n_encrypted * 0.15), ".enc"),
        ("disguised_png",   _make_disguised_png,     int(n_encrypted * 0.15), ".png"),
        ("disguised_zip",   _make_disguised_zip,     int(n_encrypted * 0.10), ".zip"),
    ]

    for gen_name, gen_fn, count, ext in generators_enc:
        for i in range(count):
            size = int(RNG.integers(4096, 524288))
            tmp_path = os.path.join(samples_dir, f"enc_{gen_name}_{i:04d}{ext}")
            try:
                data = gen_fn(size)
                with open(tmp_path, "wb") as f:
                    f.write(data)
                feats = extract_features(tmp_path)
                if feats is not None and len(feats) == N_FEATURES:
                    all_features.append(feats)
                    all_labels.append(1)
            except Exception:
                pass
            finally:
                if not save_files and os.path.exists(tmp_path):
                    os.remove(tmp_path)
        if verbose:
            print(f"  ✓ ENCRYPTED [{gen_name:15s}] {count:4d} mẫu  ext={ext}")

    X = np.array(all_features, dtype=np.float32)
    y = np.array(all_labels, dtype=np.int32)

    if len(X) == 0:
        raise ValueError("Dataset rỗng — không có sample nào được tạo thành công.")

    # Lưu CSV
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df["label"] = y
    df["label_name"] = df["label"].map({0: "SAFE", 1: "ENCRYPTED"})
    csv_path = os.path.join(output_dir, "synthetic_dataset_v2.csv")
    df.to_csv(csv_path, index=False)

    if verbose:
        print(f"\n[DatasetGen v2] Saved: {csv_path}")
        print(f"  Total: {len(y)} | SAFE: {(y==0).sum()} | ENCRYPTED: {(y==1).sum()}")

    return X, y
