import os
import struct
from core.pe_analyzer import analyze_pe
from core.scanner import Scanner

def create_mock_pe(filename, rwx=True, injection_strings=False):
    """Create a minimal mock PE file for testing."""
    # DOS Header
    data = bytearray(b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40))
    # PE Header at 0x40
    data += b"PE\0\0"
    # File Header: Mach (2), NumSect (2), Time (4), SymP (4), SymC (4), OptH (2), Char (2)
    data += struct.pack("<HHIIHHH", 0x14C, 1, 0, 0, 0, 0, 0)
    
    # Section Table entry (40 bytes)
    # Name (8), VSize (4), VAddr (4), RSize (4), RAddr (4), ... Char (4)
    char = 0
    if rwx:
        char = 0x20000000 | 0x40000000 | 0x80000000
    
    data += b".text\0\0\0" # Name
    data += b"\0" * 28      # Various sizes/addrs
    data += struct.pack("<I", char) # Characteristics
    
    # Pad to some size
    data += b"\0" * 1024
    
    if injection_strings:
        data += b"VirtualAllocEx\0"
        data += b"WriteProcessMemory\0"
        data += b"CreateRemoteThread\0"

    with open(filename, "wb") as f:
        f.write(data)

def test_detection():
    test_file = "injection_test.exe"
    print(f"--- Testing {test_file} ---")
    create_mock_pe(test_file, rwx=True, injection_strings=True)
    
    # 1. Test PE Analyzer
    res = analyze_pe(test_file)
    print(f"PE Analyzer Suspicious: {res.is_suspicious()}")
    print(f"RWX Sections: {res.rwx_sections}")
    
    # 2. Test Scanner (integration)
    scanner = Scanner()
    result = scanner._scan_single_file(test_file)
    print(f"Scan Probability: {result.probability:.4f}")
    print(f"Risk Level: {result.risk_level}")
    print(f"FP Reason: {result.fp_reason}")
    
    os.remove(test_file)

if __name__ == "__main__":
    test_detection()
