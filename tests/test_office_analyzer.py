"""
test_office_analyzer.py
=========================
Unit tests for Office Document Analyzer module.
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock oletools/PyMuPDF if not available
import unittest.mock
import builtins

_original_import = builtins.__import__


def mock_import(name, *args, **kwargs):
    if name in ("fitz", "PyMuPDF"):
        mock_module = unittest.mock.MagicMock()
        mock_module.open.return_value.__enter__ = unittest.mock.MagicMock()
        mock_module.open.return_value.__exit__ = unittest.mock.MagicMock()
        return mock_module
    if name == "oletools.olevba":
        mock_vba = unittest.mock.MagicMock()
        mock_vba.VBA_Parser = unittest.mock.MagicMock()
        return unittest.mock.MagicMock(VBA_Parser=mock_vba.VBA_Parser)
    if name in ("oletools.mraptor", "oletools.rtfobj"):
        return unittest.mock.MagicMock()
    return _original_import(name, *args, **kwargs)


builtins.__import__ = mock_import


def test_supported_extensions():
    """Test that supported extensions are correctly defined."""
    from core.office_doc_analyzer import SUPPORTED_EXTENSIONS

    expected = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
                ".ppt", ".pptx", ".pdf", ".rtf"}
    assert SUPPORTED_EXTENSIONS == expected


def test_auto_exec_triggers_defined():
    """Test that auto-execution VBA triggers are defined."""
    from core.office_doc_analyzer import AUTO_EXEC_TRIGGERS

    expected_triggers = {"AutoOpen", "Auto_Open", "Document_Open",
                        "Workbook_Open", "AutoExec", "AutoClose"}
    assert expected_triggers.issubset(AUTO_EXEC_TRIGGERS)


def test_pdf_dangerous_actions():
    """Test that PDF dangerous action patterns are defined."""
    from core.office_doc_analyzer import PDF_DANGEROUS_ACTIONS

    assert "/OpenAction" in PDF_DANGEROUS_ACTIONS
    assert "/Launch" in PDF_DANGEROUS_ACTIONS
    assert "/AA" in PDF_DANGEROUS_ACTIONS
    assert "/JavaScript" in PDF_DANGEROUS_ACTIONS


def test_office_analyzer_is_supported():
    """Test is_supported() method."""
    from core.office_doc_analyzer import OfficeDocAnalyzer

    analyzer = OfficeDocAnalyzer()

    assert analyzer.is_supported("test.doc") == True
    assert analyzer.is_supported("test.docx") == True
    assert analyzer.is_supported("test.pdf") == True
    assert analyzer.is_supported("test.xlsx") == True
    assert analyzer.is_supported("test.pptx") == True
    assert analyzer.is_supported("test.rtf") == True
    assert analyzer.is_supported("test.exe") == False
    assert analyzer.is_supported("test.txt") == False


def test_office_scan_result_dataclass(temp_dir):
    """Test OfficeScanResult dataclass."""
    from core.office_doc_analyzer import OfficeScanResult, THREAT_CLEAN

    result = OfficeScanResult(
        file_path="test.doc",
        filename="test.doc",
        extension=".doc",
        file_size=1024,
        sha256="abc123",
        threat_level=THREAT_CLEAN,
    )

    assert result.threat_level == "CLEAN"
    assert result.filename == "test.doc"
    assert result.triggers_found == []
    assert result.macro_count == 0

    d = result.to_dict()
    assert d["threat_level"] == "CLEAN"
    assert d["sha256"] == "abc123"


def test_office_scan_result_summary(temp_dir):
    """Test to_summary() method."""
    from core.office_doc_analyzer import OfficeScanResult, THREAT_CLEAN, THREAT_SUSPICIOUS, THREAT_MALICIOUS

    clean = OfficeScanResult("path/file.doc", "file.doc", ".doc", 100, "hash")
    clean.threat_level = THREAT_CLEAN
    assert "CLEAN" in clean.to_summary()

    susp = OfficeScanResult("path/file.doc", "file.doc", ".doc", 100, "hash")
    susp.threat_level = THREAT_SUSPICIOUS
    susp.triggers_found = ["AutoOpen"]
    assert "SUSPICIOUS" in susp.to_summary()

    mal = OfficeScanResult("path/file.doc", "file.doc", ".doc", 100, "hash")
    mal.threat_level = THREAT_MALICIOUS
    mal.triggers_found = ["AutoOpen", "Shell"]
    assert "MALICIOUS" in mal.to_summary()


def test_detect_suspicious_vba():
    """Test suspicious VBA keyword detection."""
    from core.office_doc_analyzer import _detect_suspicious_vba

    # Clean VBA code
    has_susp, keywords, risk = _detect_suspicious_vba("Sub Hello(): MsgBox 'Hello' : End Sub")
    assert has_susp == False
    assert keywords == []
    assert risk == 0.0

    # Suspicious VBA code with Shell()
    suspicious_code = "Shell(\"cmd.exe /c calc\")"
    has_susp, keywords, risk = _detect_suspicious_vba(suspicious_code)
    assert has_susp == True
    assert len(keywords) > 0
    assert risk > 0

    # Very suspicious with multiple keywords
    very_suspicious = """
    Shell "powershell.exe -enc BASE64PAYLOAD"
    WScript.Shell.CreateObject
    URLDownloadToFile
    """
    has_susp, keywords, risk = _detect_suspicious_vba(very_suspicious)
    assert has_susp == True
    assert risk >= 0.3  # Multiple keywords


def test_analyzer_init():
    """Test analyzer initialization and stats."""
    from core.office_doc_analyzer import OfficeDocAnalyzer

    analyzer = OfficeDocAnalyzer()
    stats = analyzer.stats

    assert stats["total_scanned"] == 0
    assert stats["clean"] == 0
    assert stats["suspicious"] == 0
    assert stats["malicious"] == 0


def test_compute_sha256(temp_dir):
    """Test SHA256 computation."""
    from core.office_doc_analyzer import OfficeDocAnalyzer

    # Create a test file
    test_file = temp_dir / "test.txt"
    test_file.write_bytes(b"Hello World")

    analyzer = OfficeDocAnalyzer()
    sha = analyzer._compute_sha256(str(test_file))

    assert len(sha) == 64  # SHA256 is 64 hex chars
    assert sha.isalnum()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
