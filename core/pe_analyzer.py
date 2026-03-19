"""
pe_analyzer.py — v1.0
======================
Lightweight PE (Portable Executable) analyzer for detecting injection indicators.
Does NOT require external dependencies (uses built-in struct).

Indicators:
- RWX (Read-Write-Execute) sections.
- Unusual section names.
- Suspicious characteristics.
"""

import struct
import os
from typing import List, Dict, Optional, Tuple

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

class PEAnalysisResult:
    def __init__(self):
        self.is_pe = False
        self.rwx_sections: List[str] = []
        self.suspicious_sections: List[str] = []
        self.is_packed = False
        self.has_overlay = False
        self.errors: List[str] = []

    def is_suspicious(self) -> bool:
        return len(self.rwx_sections) > 0 or len(self.suspicious_sections) > 0

    def to_dict(self):
        return {
            "is_pe": self.is_pe,
            "rwx_sections": self.rwx_sections,
            "suspicious_sections": self.suspicious_sections,
            "is_packed": self.is_packed,
            "is_suspicious": self.is_suspicious(),
        }

def analyze_pe(file_path: str) -> PEAnalysisResult:
    """Analyze a PE file for suspicious structural traits."""
    result = PEAnalysisResult()
    
    try:
        if not os.path.isfile(file_path):
            return result
            
        file_size = os.path.getsize(file_path)
        if file_size < 512:
            return result

        with open(file_path, "rb") as f:
            # 1. DOS Header
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[:2] != b"MZ":
                return result
            
            # e_lfanew is at offset 0x3C
            pe_offset = struct.unpack("<I", dos_header[60:64])[0]
            if pe_offset > file_size:
                return result

            # 2. PE Header
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b"PE\0\0":
                return result
            
            result.is_pe = True

            # 3. File Header (20 bytes)
            # Offset: Machine (2), NumberOfSections (2), TimeDateStamp (4), ...
            file_header = f.read(20)
            num_sections = struct.unpack("<H", file_header[2:4])[0]
            size_of_optional_header = struct.unpack("<H", file_header[16:18])[0]

            # 4. Optional Header
            # We need to skip this to reach Section Table
            optional_header_start = f.tell()
            f.seek(optional_header_start + size_of_optional_header)

            # 5. Section Table
            # Each entry is 40 bytes
            for _ in range(num_sections):
                section_data = f.read(40)
                if len(section_data) < 40:
                    break

                try:
                    section_name_bytes = section_data[:8]
                    name = section_name_bytes.decode("utf-8", errors="ignore").split("\x00")[0]
                except Exception:
                    name = "unknown"

                # Characteristics (at offset 36, 4 bytes)
                characteristics = struct.unpack("<I", section_data[36:40])[0]

                # Check for RWX
                is_r = bool(characteristics & IMAGE_SCN_MEM_READ)
                is_w = bool(characteristics & IMAGE_SCN_MEM_WRITE)
                is_x = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)

                if is_x and is_w:
                    result.rwx_sections.append(name)

                # Check suspicious names
                clean_name = name.lower()
                is_standard = any(
                    sn.lower().startswith(clean_name) if isinstance(sn, bytes) else sn.lower().startswith(clean_name)
                    for sn in BENIGN_SECTIONS
                )

                if not is_standard and not clean_name.startswith("."):
                    if name.strip():
                        result.suspicious_sections.append(name)

                if "UPX" in name.upper():
                    result.is_packed = True

    except struct.error:
        result.errors.append(f"Struct unpacking failed: {file_path}")
    except OSError as e:
        result.errors.append(f"OS error reading file: {e}")
    except Exception as e:
        result.errors.append(f"Unexpected error analyzing PE: {e}")

    return result

if __name__ == "__main__":
    # Test script for pe_analyzer
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        res = analyze_pe(target)
        import json
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print("Usage: python pe_analyzer.py <exe_file>")
