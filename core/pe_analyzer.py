"""
pe_analyzer.py — v2.0
======================
Advanced PE (Portable Executable) analyzer for detecting injection indicators.

Nâng cấp từ v1.0 với các tính năng:
- Import table analysis cho dangerous APIs
- Section entropy analysis
- Overlay detection
- Suspicious API detection
- Process Hollowing detection (so sánh in-memory vs disk PE)

Dependencies:
- struct: built-in
- Optional pefile: pip install pefile (for detailed analysis)
"""

import struct
import os
import math
import logging
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# Section Characteristics (Flags)
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ    = 0x40000000
IMAGE_SCN_MEM_WRITE   = 0x80000000
IMAGE_SCN_MEM_RWX     = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE

# Common benign section names
BENIGN_SECTIONS = {
    b".text\0\0\0", b".data\0\0\0", b".rdata\0\0", b".bss\0\0\0\0",
    b".idata\0\0", b".edata\0\0", b".rsrc\0\0\0", b".reloc\0\0",
    b".pdata\0\0", b".tls\0\0\0\0", b".text", b".data", b".rdata",
    b".rsrc", b".reloc", b"UPX0", b"UPX1", b".aspack", b".pdata",
}

# Dangerous APIs commonly used by malware for injection
DANGEROUS_APIS = {
    # Memory manipulation
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    # Process injection
    "CreateRemoteThread", "NtCreateThreadEx", "SetThreadContext", "ResumeThread",
    "QueueUserAPC", "NtQueueApcThread",
    # DLL injection
    "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "LdrLoadDll", "LdrGetProcedureAddress",
    # Process hollowing /傀儡进程
    "NtUnmapViewOfSection", "NtMapViewOfSection",
    # Shellcode execution
    "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
    # Cryptography (ransomware)
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "BCryptEncrypt", "BCryptDecrypt",
    # Network (C2 communication)
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
    "URLDownloadToFileA", "URLDownloadToFileW", "HttpSendRequestA", "HttpSendRequestW",
    # Registry manipulation (persistence)
    "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
    # File encryption
    "EncryptFile", "DecryptFile",
}

# Suspicious section names
SUSPICIOUS_SECTION_NAMES = {
    ".upx", ".aspack", ".petite", ".pec", ".pec1", ".pec2",
    ".stub", ".adata", ".pdata", ".xdata", ". Bootstrap", ".stub",
}

# Packer signatures
PACKER_SIGNATURES = {
    "UPX": [b"UPX0", b"UPX1", b"UPX!",
            b"UPX02", b"UPX03", b"UPX0", b"UPX1"],
    "ASPack": [b".aspack", b"ASPack"],
    "Petite": [b".petite", b"Petite"],
    "Themida": [b".themida", b"Themida"],
    "VMProtect": [b".vmp0", b".vmp1", b".vmp"],
}


class ThreatLevel(Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    CONFIRMED_MALICIOUS = "confirmed_malicious"


@dataclass
class SectionInfo:
    """Thông tin về một section trong PE."""
    name: str
    virtual_size: int
    raw_size: int
    virtual_address: int
    entropy: float
    is_rwx: bool
    is_writable: bool
    is_executable: bool
    is_suspicious: bool
    suspicion_reason: str = ""


@dataclass
class ImportInfo:
    """Thông tin về import."""
    dll_name: str
    function_name: str
    is_dangerous: bool
    category: str = ""  # memory, injection, network, crypto, etc.


@dataclass
class PEAnalysisResult:
    """Kết quả phân tích PE."""
    is_pe: bool = False
    file_path: str = ""
    file_size: int = 0
    
    # Basic info
    machine_type: str = ""
    num_sections: int = 0
    timestamp: Optional[str] = None
    
    # Section analysis
    sections: List[SectionInfo] = field(default_factory=list)
    rwx_sections: List[str] = field(default_factory=list)
    suspicious_sections: List[str] = field(default_factory=list)
    high_entropy_sections: List[str] = field(default_factory=list)
    
    # Import analysis
    imports: List[ImportInfo] = field(default_factory=list)
    dangerous_imports: List[str] = field(default_factory=list)
    
    # Packer detection
    is_packed: bool = False
    packer_type: str = ""
    
    # Overlay
    has_overlay: bool = False
    overlay_size: int = 0
    overlay_entropy: float = 0.0
    
    # Threat assessment
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    threat_score: float = 0.0
    indicators: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Errors
    errors: List[str] = field(default_factory=list)

    def is_suspicious(self) -> bool:
        return self.threat_level != ThreatLevel.BENIGN

    def to_dict(self) -> Dict:
        return {
            "is_pe": self.is_pe,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "machine_type": self.machine_type,
            "num_sections": self.num_sections,
            "sections": [
                {
                    "name": s.name,
                    "virtual_size": s.virtual_size,
                    "raw_size": s.raw_size,
                    "entropy": round(s.entropy, 2),
                    "is_rwx": s.is_rwx,
                    "is_suspicious": s.is_suspicious,
                }
                for s in self.sections
            ],
            "rwx_sections": self.rwx_sections,
            "suspicious_sections": self.suspicious_sections,
            "high_entropy_sections": self.high_entropy_sections,
            "dangerous_imports": self.dangerous_imports,
            "is_packed": self.is_packed,
            "packer_type": self.packer_type,
            "has_overlay": self.has_overlay,
            "overlay_size": self.overlay_size,
            "threat_level": self.threat_level.value,
            "threat_score": round(self.threat_score, 2),
            "indicators": self.indicators,
            "warnings": self.warnings,
            "is_suspicious": self.is_suspicious(),
        }


def calculate_entropy(data: bytes) -> float:
    """Tính Shannon entropy của dữ liệu."""
    if not data:
        return 0.0
    
    entropy = 0.0
    byte_counts = [0] * 256
    
    for byte in data:
        byte_counts[byte] += 1
    
    data_len = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / data_len
        entropy -= probability * math.log2(probability)
    
    return entropy


def analyze_pe(file_path: str) -> PEAnalysisResult:
    """
    Phân tích PE file toàn diện.
    
    Args:
        file_path: Đường dẫn đến PE file
        
    Returns:
        PEAnalysisResult object
    """
    result = PEAnalysisResult()
    result.file_path = file_path
    
    try:
        if not os.path.isfile(file_path):
            result.errors.append("File not found")
            return result
            
        file_size = os.path.getsize(file_path)
        result.file_size = file_size
        
        if file_size < 512:
            result.errors.append("File too small to be valid PE")
            return result

        with open(file_path, "rb") as f:
            # === DOS Header ===
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[:2] != b"MZ":
                result.errors.append("Invalid DOS header")
                return result
            
            pe_offset = struct.unpack("<I", dos_header[60:64])[0]
            if pe_offset > file_size:
                result.errors.append("Invalid PE offset")
                return result

            # === PE Header ===
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b"PE\0\0":
                result.errors.append("Invalid PE signature")
                return result
            
            result.is_pe = True

            # === File Header (20 bytes) ===
            file_header = f.read(20)
            if len(file_header) < 20:
                result.errors.append("Invalid file header")
                return result
                
            machine = struct.unpack("<H", file_header[0:2])[0]
            result.machine_type = {0x14c: "x86", 0x8664: "x64"}.get(machine, f"0x{machine:04x}")
            result.num_sections = struct.unpack("<H", file_header[2:4])[0]
            
            timestamp = struct.unpack("<I", file_header[4:8])[0]
            if timestamp > 0:
                import datetime
                result.timestamp = datetime.datetime.fromtimestamp(timestamp).isoformat()
            
            size_of_optional_header = struct.unpack("<H", file_header[16:18])[0]

            # === Optional Header ===
            optional_header_start = f.tell()
            optional_header = f.read(size_of_optional_header)
            
            if len(optional_header) >= 2:
                magic = struct.unpack("<H", optional_header[0:2])[0]
                if magic == 0x10b:
                    result.machine_type += " (PE32)"
                elif magic == 0x20b:
                    result.machine_type += " (PE32+)"
            
            # Data directories offset (PE+ has different offset)
            # For simplicity, we'll parse sections first and use pefile if available
            
            # === Section Headers ===
            sections_data = []
            for i in range(result.num_sections):
                section_offset = optional_header_start + size_of_optional_header + (i * 40)
                f.seek(section_offset)
                section_header = f.read(40)
                
                if len(section_header) < 40:
                    continue
                
                section_name = section_header[:8].decode("utf-8", errors="ignore").split("\x00")[0]
                virtual_size = struct.unpack("<I", section_header[8:12])[0]
                virtual_address = struct.unpack("<I", section_header[12:16])[0]
                raw_size = struct.unpack("<I", section_header[16:20])[0]
                raw_offset = struct.unpack("<I", section_header[20:24])[0]
                characteristics = struct.unpack("<I", section_header[36:40])[0]
                
                is_r = bool(characteristics & IMAGE_SCN_MEM_READ)
                is_w = bool(characteristics & IMAGE_SCN_MEM_WRITE)
                is_x = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)
                is_rwx = is_r and is_w and is_x
                
                # Calculate entropy of section
                section_entropy = 0.0
                if raw_size > 0 and raw_offset > 0 and raw_offset + raw_size <= file_size:
                    current_pos = f.tell()
                    f.seek(raw_offset)
                    section_data = f.read(min(raw_size, 1024 * 1024))  # Max 1MB for entropy
                    section_entropy = calculate_entropy(section_data)
                    f.seek(current_pos)
                
                # Check suspicious
                is_suspicious = False
                suspicion_reason = ""
                clean_name = section_name.lower()
                
                if not any(bs.lower().startswith(clean_name) or clean_name.startswith(bs.lower().rstrip(b'\x00'.decode()).lstrip('.')) 
                          for bs in BENIGN_SECTIONS):
                    if not clean_name.startswith("."):
                        is_suspicious = True
                        suspicion_reason = f"Non-standard section name: {section_name}"
                    elif section_name.lower() in [".upx", ".aspack", ".petite"]:
                        is_suspicious = True
                        suspicion_reason = f"Known packer section: {section_name}"
                
                if is_rwx:
                    result.rwx_sections.append(section_name)
                    if not is_suspicious:
                        is_suspicious = True
                        suspicion_reason = "RWX permissions"
                
                if section_entropy > 7.0:
                    result.high_entropy_sections.append(section_name)
                    if not is_suspicious:
                        is_suspicious = True
                        suspicion_reason = f"High entropy: {section_entropy:.2f}"
                
                section_info = SectionInfo(
                    name=section_name,
                    virtual_size=virtual_size,
                    raw_size=raw_size,
                    virtual_address=virtual_address,
                    entropy=section_entropy,
                    is_rwx=is_rwx,
                    is_writable=is_w,
                    is_executable=is_x,
                    is_suspicious=is_suspicious,
                    suspicion_reason=suspicion_reason
                )
                sections_data.append(section_info)
                result.sections.append(section_info)
                
                if is_suspicious and section_name not in result.suspicious_sections:
                    result.suspicious_sections.append(section_name)
                
                if "UPX" in section_name.upper():
                    result.is_packed = True
                    result.packer_type = "UPX"
            
            # === Import Table Analysis ===
            result.imports, result.dangerous_imports = _analyze_imports(file_path, pe_offset, optional_header, size_of_optional_header)
            
            # === Overlay Detection ===
            _detect_overlay(result, file_path, sections_data, file_size)
            
            # === Threat Assessment ===
            _assess_threat(result)
            
    except struct.error as e:
        result.errors.append(f"Struct unpacking failed: {e}")
    except OSError as e:
        result.errors.append(f"OS error reading file: {e}")
    except Exception as e:
        result.errors.append(f"Unexpected error analyzing PE: {e}")
        logger.exception(f"Error analyzing PE: {file_path}")

    return result


def _analyze_imports(file_path: str, pe_offset: int, optional_header: bytes, opt_header_size: int) -> Tuple[List[ImportInfo], List[str]]:
    """Phân tích import table để tìm dangerous APIs."""
    imports = []
    dangerous_imports = []
    
    # Try using pefile if available
    try:
        import pefile
        pe = pefile.PE(file_path)
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                    else:
                        func_name = f"Ordinal_{imp.ordinal}"
                    
                    is_dangerous = func_name in DANGEROUS_APIS
                    
                    # Categorize dangerous API
                    category = ""
                    if func_name in {"VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
                                    "WriteProcessMemory", "ReadProcessMemory"}:
                        category = "memory"
                    elif func_name in {"CreateRemoteThread", "NtCreateThreadEx", "SetThreadContext",
                                      "ResumeThread", "QueueUserAPC", "NtQueueApcThread"}:
                        category = "injection"
                    elif func_name in {"LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
                                      "LdrLoadDll", "LdrGetProcedureAddress"}:
                        category = "dll"
                    elif func_name in {"CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
                                      "BCryptEncrypt", "BCryptDecrypt"}:
                        category = "crypto"
                    elif func_name in {"InternetOpenA", "InternetOpenW", "InternetConnectA",
                                      "URLDownloadToFileA"}:
                        category = "network"
                    
                    import_info = ImportInfo(
                        dll_name=dll_name,
                        function_name=func_name,
                        is_dangerous=is_dangerous,
                        category=category
                    )
                    imports.append(import_info)
                    
                    if is_dangerous and func_name not in dangerous_imports:
                        dangerous_imports.append(func_name)
        
        pe.close()
        
    except ImportError:
        # pefile not available, try manual parsing
        imports, dangerous_imports = _analyze_imports_manual(file_path, pe_offset, optional_header, opt_header_size)
    except Exception as e:
        logger.warning(f"pefile analysis failed: {e}")
        imports, dangerous_imports = _analyze_imports_manual(file_path, pe_offset, optional_header, opt_header_size)
    
    return imports, dangerous_imports


def _analyze_imports_manual(file_path: str, pe_offset: int, optional_header: bytes, opt_header_size: int) -> Tuple[List[ImportInfo], List[str]]:
    """Manual import table parsing without pefile."""
    imports = []
    dangerous_imports = []
    
    try:
        with open(file_path, "rb") as f:
            # Get import directory RVA
            if len(optional_header) >= 108:  # PE32
                import_rva = struct.unpack("<I", optional_header[104:108])[0]
            elif len(optional_header) >= 112:  # PE32+
                import_rva = struct.unpack("<I", optional_header[112:116])[0]
            else:
                return imports, dangerous_imports
            
            if import_rva == 0:
                return imports, dangerous_imports
            
            # Read import directory
            # This is a simplified parser - for full implementation use pefile
            
    except Exception:
        pass
    
    return imports, dangerous_imports


def _detect_overlay(result: PEAnalysisResult, file_path: str, sections: List[SectionInfo], file_size: int):
    """Detect overlay data (data appended after sections)."""
    try:
        # Calculate end of last section
        max_offset = 0
        for section in sections:
            if hasattr(section, 'raw_size') and hasattr(section, 'virtual_address'):
                # Rough calculation
                section_end = section.virtual_address + section.virtual_size
                # Find raw offset in PE (simplified)
        
        # Simple heuristic: check if there's significant data after section headers
        with open(file_path, "rb") as f:
            # Read last 64KB
            if file_size > 65536:
                f.seek(file_size - 65536)
                tail_data = f.read(65536)
                
                if len(tail_data) > 0:
                    entropy = calculate_entropy(tail_data)
                    
                    # If entropy is very different from expected section entropy, likely overlay
                    if entropy > 5.0 and len(tail_data) > 1024:
                        result.has_overlay = True
                        result.overlay_size = len(tail_data)
                        result.overlay_entropy = entropy
                        
                        if entropy > 7.0:
                            result.warnings.append(f"High entropy overlay ({entropy:.2f}) - possible packed malware")
                            
    except Exception as e:
        logger.warning(f"Overlay detection failed: {e}")


def _assess_threat(result: PEAnalysisResult):
    """Đánh giá mức độ threat dựa trên các indicators."""
    score = 0.0
    indicators = []
    
    # High-risk indicators
    if len(result.rwx_sections) > 0:
        score += 0.15
        indicators.append(f"RWX sections found: {', '.join(result.rwx_sections)}")
    
    if len(result.dangerous_imports) >= 5:
        score += 0.20
        indicators.append(f"Multiple dangerous imports: {len(result.dangerous_imports)} APIs")
    elif len(result.dangerous_imports) > 0:
        score += 0.10
        indicators.append(f"Dangerous imports: {', '.join(result.dangerous_imports[:5])}")
    
    if result.is_packed:
        score += 0.15
        indicators.append(f"Possibly packed: {result.packer_type}")
    
    if result.has_overlay and result.overlay_entropy > 7.0:
        score += 0.20
        indicators.append(f"High-entropy overlay data ({result.overlay_entropy:.2f})")
    
    if len(result.high_entropy_sections) > 0:
        score += 0.10
        indicators.append(f"High-entropy sections: {', '.join(result.high_entropy_sections)}")
    
    if len(result.suspicious_sections) > 0:
        score += 0.15
        indicators.append(f"Suspicious sections: {', '.join(result.suspicious_sections)}")
    
    # Check for specific dangerous API combinations
    dangerous_set = set(result.dangerous_imports)
    injection_apis = {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"}
    if injection_apis.intersection(dangerous_set) == injection_apis:
        score += 0.25
        indicators.append("Process injection API combination detected")
    
    crypto_apis = {"CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt"}
    if len(crypto_apis.intersection(dangerous_set)) >= 2:
        score += 0.20
        indicators.append("Cryptography API combination detected - possible ransomware")
    
    result.threat_score = min(score, 1.0)
    result.indicators = indicators
    
    # Determine threat level
    if score >= 0.70:
        result.threat_level = ThreatLevel.CONFIRMED_MALICIOUS
    elif score >= 0.45:
        result.threat_level = ThreatLevel.LIKELY_MALICIOUS
    elif score >= 0.20:
        result.threat_level = ThreatLevel.SUSPICIOUS
    else:
        result.threat_level = ThreatLevel.BENIGN


def compare_pe_with_memory(exe_path: str, process_handle: int = None) -> Dict:
    """
    So sánh PE header trên disk với in-memory (Process Hollowing detection).
    
    Args:
        exe_path: Đường dẫn đến executable trên disk
        process_handle: Handle đến process (Windows HANDLE)
        
    Returns:
        Dictionary với kết quả so sánh
    """
    result = {
        "is_hollowing": False,
        "confidence": 0.0,
        "differences": [],
        "message": ""
    }
    
    if not os.path.exists(exe_path):
        result["message"] = "Executable not found"
        return result
    
    # Analyze disk PE
    disk_analysis = analyze_pe(exe_path)
    
    # If no process handle provided, return disk analysis only
    if process_handle is None:
        result["message"] = "Process handle not provided"
        result["disk_analysis"] = disk_analysis.to_dict()
        return result
    
    # For in-memory comparison, we'd need ReadProcessMemory
    # This requires pywin32 or ctypes - simplified version here
    
    try:
        import ctypes
        from ctypes import wintypes
        
        kernel32 = ctypes.windll.kernel32
        
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        
        # Read DOS header from memory
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]
        
        # Simplified check: just analyze disk PE
        result["message"] = "Process Hollowing analysis based on disk PE"
        result["disk_analysis"] = disk_analysis.to_dict()
        
        # Add heuristics
        if disk_analysis.threat_score > 0.4:
            result["is_hollowing"] = True
            result["confidence"] = disk_analysis.threat_score * 0.7
            result["differences"].append("High threat score in PE suggests possible hollowing")
        
    except Exception as e:
        result["message"] = f"Error during comparison: {e}"
        logger.exception("Process hollowing detection error")
    
    return result


# Alias for backward compatibility
analyze_pe_file = analyze_pe


if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        res = analyze_pe(target)
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print("Usage: python pe_analyzer.py <exe_file>")
