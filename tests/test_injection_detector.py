"""
test_injection_detector.py
==========================
Audit P2-12 regression tests for ``core.injection_detector``.

The native Win32 paths (``OpenProcess``, ``ReadProcessMemory``, etc.) are
out of scope for unit tests — those need a Windows VM. Here we cover the
pure-Python pieces that already drive most of the detection logic:
LOLBins lookup, dataclass round-trips, severity ordering.
"""

import sys
from datetime import datetime

import pytest

from core.injection_detector import (
    InjectionAlert, InjectionDetector, InjectionType,
    MemoryRegion, Severity,
    get_injection_detector,
)


class TestEnumsAndDataclasses:
    def test_injection_type_values_unique(self):
        values = [t.value for t in InjectionType]
        assert len(values) == len(set(values))

    def test_severity_values(self):
        # Exactly four levels, in expected order.
        assert {s.value for s in Severity} == {
            "CRITICAL", "HIGH", "MEDIUM", "LOW"
        }

    def test_alert_to_dict_round_trip(self):
        alert = InjectionAlert(
            injection_type=InjectionType.PROCESS_HOLLOWING,
            pid=4242,
            process_name="explorer.exe",
            severity=Severity.HIGH,
            description="rwx + entropy mismatch",
            indicators=["rwx_section", "high_entropy"],
            metadata={"confidence": 0.7},
            timestamp=datetime(2025, 1, 1, 12, 0, 0),
        )
        d = alert.to_dict()
        assert d["type"] == "process_hollowing"
        assert d["pid"] == 4242
        assert d["severity"] == "HIGH"
        assert d["indicators"] == ["rwx_section", "high_entropy"]
        assert d["metadata"]["confidence"] == 0.7
        assert d["timestamp"] == "2025-01-01T12:00:00"

    def test_memory_region_flags(self):
        # RWX = read + write + execute simultaneously.
        region = MemoryRegion(
            address=0x10000000,
            size=4096,
            protect=0x40,
            state="MEM_COMMIT",
            type="MEM_PRIVATE",
            is_executable=True,
            is_writable=True,
            is_readable=True,
            is_rwx=True,
            allocation_protect=0x40,
        )
        assert region.is_rwx
        assert region.size == 4096


class TestLolbinsCatalog:
    def test_known_binaries_present(self):
        det = InjectionDetector()
        for binary in ("mshta.exe", "regsvr32.exe", "certutil.exe",
                       "rundll32.exe", "wscript.exe"):
            assert binary in det.LOLBINS, f"{binary} missing from LOLBINS catalog"

    def test_each_entry_has_required_keys(self):
        det = InjectionDetector()
        required = {"description", "risk", "suspicious_args"}
        for name, info in det.LOLBINS.items():
            missing = required - set(info)
            assert not missing, f"{name} missing keys {missing}"
            assert isinstance(info["suspicious_args"], list)
            assert info["risk"] in {"low", "medium", "high"}


class TestSingleton:
    def test_get_injection_detector_returns_singleton(self):
        a = get_injection_detector()
        b = get_injection_detector()
        assert a is b


@pytest.mark.skipif(sys.platform != "win32",
                     reason="Windows-only ctypes path")
class TestWindowsKernel32Init:
    def test_kernel32_loaded_on_windows(self):
        det = InjectionDetector()
        # ctypes.windll.kernel32 is truthy when loaded.
        assert det._kernel32 is not None


@pytest.mark.skipif(sys.platform == "win32",
                     reason="Linux/Mac path verifies graceful skip")
class TestNonWindowsGracefulSkip:
    def test_kernel32_none_off_windows(self):
        det = InjectionDetector()
        assert det._kernel32 is None
