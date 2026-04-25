import importlib

import pytest

from core.pe_analyzer import (
    ImportInfo,
    PEAnalysisResult,
    ThreatLevel,
    _analyze_imports,
    _assess_threat,
)


def test_analyze_imports_falls_back_to_manual_parser_when_pefile_is_unavailable(monkeypatch, temp_dir):
    sample_path = temp_dir / "sample.exe"
    sample_path.write_bytes(b"MZ" + (b"\x00" * 510))

    calls = {"manual": 0}

    def fake_import_module(name: str):
        if name == "pefile":
            raise ModuleNotFoundError(name)
        return importlib.import_module(name)

    def fake_manual(file_path: str, pe_offset: int, optional_header: bytes, opt_header_size: int):
        calls["manual"] += 1
        assert file_path == str(sample_path)
        assert pe_offset == 128
        assert optional_header == b"\x00" * 120
        assert opt_header_size == 120
        return [], ["VirtualAllocEx"]

    monkeypatch.setattr("core.pe_analyzer.importlib.import_module", fake_import_module)
    monkeypatch.setattr("core.pe_analyzer._analyze_imports_manual", fake_manual)

    imports, dangerous_imports = _analyze_imports(
        str(sample_path),
        128,
        b"\x00" * 120,
        120,
    )

    assert calls["manual"] == 1
    assert imports == []
    assert dangerous_imports == ["VirtualAllocEx"]


def test_assess_threat_uses_import_metadata_for_suspicious_dll_detection():
    result = PEAnalysisResult(
        imports=[
            ImportInfo("evil.dll", "VirtualAllocEx", True, "memory"),
            ImportInfo("evil.dll", "WriteProcessMemory", True, "memory"),
            ImportInfo("evil.dll", "CreateRemoteThread", True, "injection"),
        ],
        dangerous_imports=[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ],
    )

    _assess_threat(result)

    assert result.threat_level == ThreatLevel.LIKELY_MALICIOUS
    assert result.threat_score == pytest.approx(0.45)
    assert any("Suspicious DLLs with dangerous APIs" in indicator for indicator in result.indicators)
    assert any("Process injection API combo" in indicator for indicator in result.indicators)
