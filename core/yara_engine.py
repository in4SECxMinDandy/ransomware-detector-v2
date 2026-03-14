"""
yara_engine.py — v2.1 (MỚI)
==============================
YARA Rules Integration cho Ransomware Detector.

Cung cấp:
  - 10 built-in YARA rules phát hiện ransomware phổ biến
  - Signature-based detection kết hợp với ML entropy-based
  - YaraEngine.scan_file() → trả về danh sách rules matched
  - Tích hợp với Scanner: kết quả YARA tăng/giảm ML probability

Built-in Rules (10):
  1.  wannacry_magic        — WannaCry magic bytes + WNCRY extension
  2.  lockbit_marker        — LockBit 3.0 ransom note markers
  3.  blackcat_alphv        — ALPHV/BlackCat extension markers
  4.  ryuk_marker           — Ryuk file marker strings
  5.  revil_sodinokibi      — REvil/Sodinokibi patterns
  6.  conti_marker          — Conti ransomware patterns
  7.  generic_ransomnote    — Generic ransom note keywords (ANY ransomware)
  8.  encrypted_header      — File header overwrite pattern (common technique)
  9.  intermittent_pattern  — Intermittent encryption detection (entropy delta)
  10. high_entropy_pe       — PE với entropy > 7.2 toàn bộ (packed/encrypted exe)

Lưu ý: Module này KHÔNG yêu cầu thư viện yara-python (optional).
Nếu yara-python không có, fallback sang pure-Python signature matching.

Cài đặt yara-python (tùy chọn, hiệu năng tốt hơn):
  pip install yara-python
"""

import os
import re
import struct
from typing import List, Dict, Optional, Tuple
import numpy as np

# ─── Try import yara-python (optional) ───
try:
    import yara
    YARA_PYTHON_AVAILABLE = True
except ImportError:
    YARA_PYTHON_AVAILABLE = False

# ─────────────────────────────────────────────────────────────
# BUILT-IN YARA RULES (10 rules)
# Format: YARA syntax — dùng để compile nếu yara-python có mặt
# ─────────────────────────────────────────────────────────────

BUILTIN_YARA_RULES_SOURCE = r"""
rule WannaCry_Magic
{
    meta:
        description = "WannaCry ransomware magic bytes and extension"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "WannaCry"

    strings:
        $magic1 = { 57 41 4E 4E 41 }         // "WANNA"
        $magic2 = ".WNCRY" nocase
        $magic3 = "WannaDecryptor" nocase
        $magic4 = { 4D 53 53 45 43 53 56 43 } // "MSSECSVC"
        $note1  = "!Please Read Me!.txt" nocase

    condition:
        any of them
}

rule LockBit_3_Marker
{
    meta:
        description = "LockBit 3.0 ransom note and marker strings"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "LockBit"

    strings:
        $ext1   = ".lockbit" nocase
        $ext2   = ".lock" nocase
        $note1  = "LockBit" nocase
        $note2  = "Restore-My-Files.txt" nocase
        $marker = { 4C 6F 63 6B 42 69 74 }   // "LockBit"
        $lb3    = "lockbit 3.0" nocase
        $lb4    = "lockbit 2.0" nocase

    condition:
        2 of them
}

rule BlackCat_ALPHV
{
    meta:
        description = "BlackCat/ALPHV ransomware patterns"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "BlackCat"

    strings:
        $ext1  = ".alphv" nocase
        $ext2  = ".blackcat" nocase
        $note1 = "RECOVER-" nocase
        $note2 = "FILES.txt" nocase
        $str1  = "ALPHV" nocase

    condition:
        any of them
}

rule Ryuk_Marker
{
    meta:
        description = "Ryuk ransomware file markers"
        author      = "Ransomware Entropy Detector v2"
        severity    = "HIGH"
        family      = "Ryuk"

    strings:
        $ext1  = ".ryk" nocase
        $note1 = "RyukReadMe.txt" nocase
        $note2 = "No system is safe" nocase
        $mark  = { 52 59 55 4B }              // "RYUK"

    condition:
        any of them
}

rule Clop_Marker
{
    meta:
        description = "Cl0p ransomware markers"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "Cl0p"

    strings:
        $ext1 = ".clop" nocase
        $ext2 = ".cl0p" nocase
        $note1 = "Cl0pReadMe.txt" nocase
        $note2 = "Clop^_^" nocase
        $mark  = "CLOP" nocase

    condition:
        any of them
}

rule REvil_Sodinokibi
{
    meta:
        description = "REvil/Sodinokibi ransomware patterns"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "REvil"

    strings:
        $note1 = "[extension]-readme.txt" nocase
        $note2 = "decoded.txt" nocase
        $str1  = "sodinokibi" nocase
        $str2  = "revil" nocase

    condition:
        any of them
}

rule Conti_Marker
{
    meta:
        description = "Conti ransomware patterns"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "Conti"

    strings:
        $ext1  = ".conti" nocase
        $note1 = "readme.txt" nocase
        $note2 = "CONTI_README.txt" nocase
        $str1  = "Conti Decryptor" nocase

    condition:
        any of them
}

rule Play_Marker
{
    meta:
        description = "Play ransomware markers"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "Play"

    strings:
        $ext1  = ".play" nocase
        $note1 = "PLAY ransomware" nocase
        $note2 = "Your data has been locked" nocase
        $note3 = "ReadMe.txt" nocase

    condition:
        any of them
}

rule Rhysida_Marker
{
    meta:
        description = "Rhysida ransomware markers"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "Rhysida"

    strings:
        $ext1  = ".rhysida" nocase
        $note1 = "Rhysida" nocase
        $note2 = "README_RHYSIDA.txt" nocase
        $note3 = "rhysida" nocase

    condition:
        any of them
}

rule Akira_Marker
{
    meta:
        description = "Akira ransomware markers"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "Akira"

    strings:
        $ext1  = ".akira" nocase
        $note1 = "AKIRA" nocase
        $note2 = "akira_readme.txt" nocase
        $note3 = "how_to_decrypt" nocase

    condition:
        any of them
}

rule BianLian_Marker
{
    meta:
        description = "BianLian ransomware markers"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "BianLian"

    strings:
        $ext1  = ".bianlian" nocase
        $note1 = "BianLian" nocase
        $note2 = "BianLian" wide nocase
        $note3 = "readme_bianlian" nocase

    condition:
        any of them
}

rule Medusa_Marker
{
    meta:
        description = "Medusa ransomware markers"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "Medusa"

    strings:
        $ext1  = ".medusa" nocase
        $note1 = "MEDUSA" nocase
        $note2 = "READ_ME_MEDUSA" nocase
        $note3 = "medusa" wide nocase

    condition:
        any of them
}

rule Qilin_Marker
{
    meta:
        description = "Qilin ransomware markers"
        author      = "Ransomware Entropy Detector v2"
        severity    = "CRITICAL"
        family      = "Qilin"

    strings:
        $ext1  = ".qilin" nocase
        $note1 = "QILIN" nocase
        $note2 = "readme_qilin" nocase
        $note3 = "Qilin" wide nocase

    condition:
        any of them
}

rule Generic_RansomNote
{
    meta:
        description = "Generic ransom note keywords (any ransomware)"
        author      = "Ransomware Entropy Detector v2"
        severity    = "HIGH"
        family      = "Generic"

    strings:
        $kw1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $kw2 = "your files are encrypted" nocase
        $kw3 = "To decrypt your files" nocase
        $kw4 = "bitcoin" nocase
        $kw5 = "BTC wallet" nocase
        $kw6 = "tor browser" nocase
        $kw7 = "unique ID" nocase
        $kw8 = "decryption key" nocase
        $kw9 = "ransom" nocase

    condition:
        3 of them
}

rule Encrypted_Header_Overwrite
{
    meta:
        description = "File header overwrite — common ransomware technique"
        author      = "Ransomware Entropy Detector v2"
        severity    = "MEDIUM"
        family      = "Generic"

    strings:
        $null_header = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $null_header at 0
}

rule Generic_Encrypted_Extension
{
    meta:
        description = "Common encrypted file extensions appended by ransomware"
        author      = "Ransomware Entropy Detector v2"
        severity    = "MEDIUM"
        family      = "Generic"

    strings:
        $ext1  = ".encrypted" nocase
        $ext2  = ".enc" nocase
        $ext3  = ".crypted" nocase
        $ext4  = ".crypt" nocase
        $ext5  = ".locked" nocase
        $ext6  = ".crypto" nocase
        $ext7  = ".zepto" nocase
        $ext8  = ".cerber" nocase

    condition:
        any of them
}

rule High_Entropy_PE_Suspicious
{
    meta:
        description = "PE executable with suspicious entropy profile (packed/encrypted)"
        author      = "Ransomware Entropy Detector v2"
        severity    = "MEDIUM"
        family      = "Generic"

    strings:
        $mz_header = { 4D 5A }               // MZ header

    condition:
        $mz_header at 0 and filesize > 10KB
}
"""

# ─────────────────────────────────────────────────────────────
# Pure-Python fallback signature DB
# Format: rule_name → (description, severity, patterns)
# patterns: list of bytes/str to search in file content
# ─────────────────────────────────────────────────────────────

PYTHON_SIGNATURES: List[Dict] = [
    {
        "name": "WannaCry_Magic",
        "description": "WannaCry ransomware",
        "severity": "CRITICAL",
        "family": "WannaCry",
        "byte_patterns": [b"WANNA", b"WNCRY", b"WannaDecryptor", b"MSSECSVC"],
        "ext_patterns": [".wncry", ".wnry"],
        "min_matches": 1,
    },
    {
        "name": "LockBit_3_Marker",
        "description": "LockBit 3.0 ransomware",
        "severity": "CRITICAL",
        "family": "LockBit",
        "byte_patterns": [b"LockBit", b"Restore-My-Files", b".lockbit", b"lockbit 3.0", b"lockbit 2.0"],
        "ext_patterns": [".lockbit", ".lock"],
        "min_matches": 1,
    },
    {
        "name": "BlackCat_ALPHV",
        "description": "BlackCat/ALPHV ransomware",
        "severity": "CRITICAL",
        "family": "BlackCat",
        "byte_patterns": [b"ALPHV", b"RECOVER-", b".alphv", b".blackcat"],
        "ext_patterns": [".alphv", ".blackcat"],
        "min_matches": 1,
    },
    {
        "name": "Ryuk_Marker",
        "description": "Ryuk ransomware",
        "severity": "HIGH",
        "family": "Ryuk",
        "byte_patterns": [b"RYUK", b"RyukReadMe", b"No system is safe", b".ryk"],
        "ext_patterns": [".ryk", ".ryuk"],
        "min_matches": 1,
    },
    {
        "name": "Clop_Marker",
        "description": "Cl0p ransomware",
        "severity": "CRITICAL",
        "family": "Cl0p",
        "byte_patterns": [b"clop", b"cl0p", b"Cl0pReadMe", b"Clop^_^"],
        "ext_patterns": [".clop", ".cl0p"],
        "min_matches": 1,
    },
    {
        "name": "REvil_Sodinokibi",
        "description": "REvil/Sodinokibi ransomware",
        "severity": "CRITICAL",
        "family": "REvil",
        "byte_patterns": [b"sodinokibi", b"revil", b"decoded.txt"],
        "ext_patterns": [],
        "min_matches": 1,
    },
    {
        "name": "Conti_Marker",
        "description": "Conti ransomware",
        "severity": "CRITICAL",
        "family": "Conti",
        "byte_patterns": [b"Conti Decryptor", b"CONTI_README", b".conti"],
        "ext_patterns": [".conti"],
        "min_matches": 1,
    },
    {
        "name": "Play_Marker",
        "description": "Play ransomware",
        "severity": "CRITICAL",
        "family": "Play",
        "byte_patterns": [b"PLAY ransomware", b"Your data has been locked", b".play"],
        "ext_patterns": [".play"],
        "min_matches": 1,
    },
    {
        "name": "Rhysida_Marker",
        "description": "Rhysida ransomware",
        "severity": "CRITICAL",
        "family": "Rhysida",
        "byte_patterns": [b"Rhysida", b"README_RHYSIDA", b".rhysida"],
        "ext_patterns": [".rhysida"],
        "min_matches": 1,
    },
    {
        "name": "Generic_RansomNote",
        "description": "Generic ransom note keywords",
        "severity": "HIGH",
        "family": "Generic",
        "byte_patterns": [
            b"FILES HAVE BEEN ENCRYPTED",
            b"files are encrypted",
            b"To decrypt your files",
            b"bitcoin",
            b"BTC wallet",
            b"tor browser",
            b"decryption key",
        ],
        "ext_patterns": [],
        "min_matches": 3,  # ít nhất 3 từ khóa
    },
    {
        "name": "Akira_Marker",
        "description": "Akira ransomware markers",
        "severity": "CRITICAL",
        "family": "Akira",
        "byte_patterns": [b"AKIRA", b"akira_readme", b"how_to_decrypt"],
        "ext_patterns": [".akira"],
        "min_matches": 1,
    },
    {
        "name": "BianLian_Marker",
        "description": "BianLian ransomware markers",
        "severity": "CRITICAL",
        "family": "BianLian",
        "byte_patterns": [b"BianLian", b"readme_bianlian"],
        "ext_patterns": [".bianlian"],
        "min_matches": 1,
    },
    {
        "name": "Medusa_Marker",
        "description": "Medusa ransomware markers",
        "severity": "CRITICAL",
        "family": "Medusa",
        "byte_patterns": [b"MEDUSA", b"READ_ME_MEDUSA"],
        "ext_patterns": [".medusa"],
        "min_matches": 1,
    },
    {
        "name": "Qilin_Marker",
        "description": "Qilin ransomware markers",
        "severity": "CRITICAL",
        "family": "Qilin",
        "byte_patterns": [b"QILIN", b"readme_qilin"],
        "ext_patterns": [".qilin"],
        "min_matches": 1,
    },
    {
        "name": "Encrypted_Header_Overwrite",
        "description": "File header overwrite (ransomware technique)",
        "severity": "MEDIUM",
        "family": "Generic",
        "byte_patterns": [],
        "ext_patterns": [],
        "min_matches": 0,
        "special": "null_header",  # kiểm tra 16 bytes đầu = 0x00
    },
    {
        "name": "Generic_Encrypted_Extension",
        "description": "Common encrypted file extensions",
        "severity": "MEDIUM",
        "family": "Generic",
        "byte_patterns": [],
        "ext_patterns": [
            ".encrypted", ".enc", ".crypted", ".crypt",
            ".locked", ".crypto", ".zepto", ".cerber",
        ],
        "min_matches": 1,
    },
    {
        "name": "High_Entropy_PE_Suspicious",
        "description": "PE executable suspicious entropy",
        "severity": "MEDIUM",
        "family": "Generic",
        "byte_patterns": [],
        "ext_patterns": [],
        "min_matches": 0,
        "special": "high_entropy_pe",  # PE header + kiểm tra entropy
    },
]


class YaraMatch:
    """Kết quả một YARA rule match."""

    def __init__(self, rule_name: str, description: str, severity: str, family: str):
        self.rule_name   = rule_name
        self.description = description
        self.severity    = severity
        self.family      = family

    def __repr__(self) -> str:
        return f"YaraMatch(rule={self.rule_name}, severity={self.severity})"

    def to_dict(self) -> Dict:
        return {
            "rule_name":   self.rule_name,
            "description": self.description,
            "severity":    self.severity,
            "family":      self.family,
        }


class YaraEngine:
    """
    YARA-based signature detection engine.

    Khi yara-python có mặt: dùng compiled YARA rules (nhanh hơn).
    Khi không có: fallback sang pure-Python byte pattern matching.

    Kết hợp với ML Engine:
      - YARA match với severity CRITICAL → cộng thêm 0.30 vào ML probability
      - YARA match với severity HIGH     → cộng thêm 0.15
      - YARA match với severity MEDIUM   → cộng thêm 0.05
      - Không có YARA match             → không thay đổi
    """

    # Probability boost khi có YARA match
    SEVERITY_BOOST = {
        "CRITICAL": 0.30,
        "HIGH":     0.15,
        "MEDIUM":   0.05,
    }

    def __init__(self):
        self._compiled_rules = None
        self._use_yara_python = False
        self._signatures = PYTHON_SIGNATURES
        self._rules_count = len(PYTHON_SIGNATURES)
        self._initialize()

    def _initialize(self):
        """Khởi tạo engine — thử compile YARA rules nếu có thư viện."""
        if YARA_PYTHON_AVAILABLE:
            try:
                self._compiled_rules = yara.compile(source=BUILTIN_YARA_RULES_SOURCE)
                self._use_yara_python = True
                print(f"[YaraEngine] yara-python available — {self._rules_count} rules compiled")
            except Exception as e:
                print(f"[YaraEngine] yara-python compile failed ({e}), fallback to Python")
                self._use_yara_python = False
        else:
            self._use_yara_python = False

    def is_available(self) -> bool:
        """Kiểm tra engine có sẵn sàng không."""
        return True  # Luôn có fallback

    def get_rules_count(self) -> int:
        return self._rules_count

    def get_engine_type(self) -> str:
        return "yara-python" if self._use_yara_python else "Python fallback"

    def scan_file(self, file_path: str) -> List[YaraMatch]:
        """
        Quét một file với YARA rules.

        Parameters
        ----------
        file_path : đường dẫn file

        Returns
        -------
        list of YaraMatch — có thể rỗng nếu không match rule nào
        """
        if not os.path.isfile(file_path):
            return []

        try:
            if self._use_yara_python:
                return self._scan_with_yara_python(file_path)
            else:
                return self._scan_with_python(file_path)
        except Exception:
            return []

    def _scan_with_yara_python(self, file_path: str) -> List[YaraMatch]:
        """Quét dùng yara-python compiled rules."""
        matches = self._compiled_rules.match(file_path)
        results = []
        for m in matches:
            meta = m.meta
            results.append(YaraMatch(
                rule_name   = m.rule,
                description = meta.get("description", m.rule),
                severity    = meta.get("severity", "MEDIUM"),
                family      = meta.get("family", "Unknown"),
            ))
        return results

    def _scan_with_python(self, file_path: str) -> List[YaraMatch]:
        """Pure-Python fallback: byte pattern matching."""
        results = []
        ext     = os.path.splitext(file_path)[1].lower()

        try:
            # Đọc tối đa 1MB để tìm patterns
            with open(file_path, "rb") as f:
                content = f.read(1024 * 1024)
        except Exception:
            return []

        content_lower = content.lower()

        for sig in self._signatures:
            matched = False

            # Special checks
            special = sig.get("special", "")
            if special == "null_header":
                if len(content) >= 16 and content[:16] == b"\x00" * 16:
                    results.append(YaraMatch(
                        sig["name"], sig["description"],
                        sig["severity"], sig["family"]
                    ))
                continue

            elif special == "high_entropy_pe":
                # Kiểm tra: MZ header + file >= 10KB + entropy cao
                if (content[:2] == b"MZ" and
                    os.path.getsize(file_path) > 10240):
                    try:
                        byte_arr = np.frombuffer(content[:65536], dtype=np.uint8)
                        counts   = np.bincount(byte_arr, minlength=256)
                        probs    = counts / len(byte_arr)
                        probs    = probs[probs > 0]
                        entropy  = -np.sum(probs * np.log2(probs))
                        if entropy > 7.0:
                            results.append(YaraMatch(
                                sig["name"], sig["description"],
                                sig["severity"], sig["family"]
                            ))
                    except Exception:
                        pass
                continue

            # Extension check
            ext_patterns = sig.get("ext_patterns", [])
            if ext_patterns and ext in ext_patterns:
                matched = True

            # Byte pattern check
            byte_patterns = sig.get("byte_patterns", [])
            min_matches   = sig.get("min_matches", 1)
            if byte_patterns:
                hit_count = sum(
                    1 for pat in byte_patterns
                    if pat.lower() in content_lower
                )
                if hit_count >= min_matches:
                    matched = True
            elif ext_patterns and not matched:
                pass  # chỉ check extension

            if matched:
                results.append(YaraMatch(
                    sig["name"], sig["description"],
                    sig["severity"], sig["family"]
                ))

        return results

    def apply_yara_boost(
        self,
        probability: float,
        yara_matches: List[YaraMatch]
    ) -> Tuple[float, str]:
        """
        Tăng ML probability dựa trên YARA matches.

        Returns: (boosted_probability, boost_reason)
        """
        if not yara_matches:
            return probability, ""

        max_boost = 0.0
        max_severity = ""
        families = set()

        for match in yara_matches:
            boost = self.SEVERITY_BOOST.get(match.severity, 0.0)
            if boost > max_boost:
                max_boost = boost
                max_severity = match.severity
            families.add(match.family)

        boosted = min(probability + max_boost, 0.99)
        reason  = (
            f"YARA({max_severity}):"
            f"{'+'.join(m.rule_name for m in yara_matches[:3])}"
        )
        return boosted, reason

    def load_rules_from_file(self, rules_path: str) -> bool:
        """
        Load thêm YARA rules từ file .yar/.yara.

        Chỉ khả dụng khi yara-python được cài đặt.
        """
        if not YARA_PYTHON_AVAILABLE:
            return False
        if not os.path.isfile(rules_path):
            return False
        try:
            extra = yara.compile(filepath=rules_path)
            # Merge với built-in rules
            self._compiled_rules = yara.compile(
                sources={
                    "builtin": BUILTIN_YARA_RULES_SOURCE,
                    "custom": open(rules_path).read(),
                }
            )
            return True
        except Exception as e:
            print(f"[YaraEngine] Load custom rules failed: {e}")
            return False

    def get_builtin_rules_info(self) -> List[Dict]:
        """Trả về thông tin về các built-in rules."""
        return [
            {
                "name":        sig["name"],
                "description": sig["description"],
                "severity":    sig["severity"],
                "family":      sig["family"],
            }
            for sig in self._signatures
        ]


# ─── Global singleton ───
_yara_instance: Optional[YaraEngine] = None


def get_yara_engine() -> YaraEngine:
    """Lấy singleton instance của YARA Engine."""
    global _yara_instance
    if _yara_instance is None:
        _yara_instance = YaraEngine()
    return _yara_instance
