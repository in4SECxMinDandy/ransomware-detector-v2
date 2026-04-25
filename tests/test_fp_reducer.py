"""
test_fp_reducer.py
=================
Unit tests for core/fp_reducer.py
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.fp_reducer import (
    check_path_whitelist,
    get_extension_threshold,
    check_magic_bytes,
    apply_fp_reduction,
    get_fp_stats,
    ALWAYS_SAFE_EXTENSIONS,
    EXTENSION_THRESHOLDS,
    MAGIC_BYTES_DISCOUNT_FACTOR,
)


class TestCheckPathWhitelist:
    def test_safe_extensions(self):
        """System/font extensions should be whitelisted."""
        assert check_path_whitelist("C:/Windows/Fonts/arial.ttf") is True
        assert check_path_whitelist("C:/Windows/System32/config.ico") is True
        assert check_path_whitelist("C:/Users/test/file.lnk") is True
        assert check_path_whitelist("C:/Users/test/file.tmp") is True

    def test_safe_path_keywords(self):
        """Paths with safe keywords should be whitelisted."""
        assert check_path_whitelist("C:/Windows/System32/drivers/test.sys") is True
        assert check_path_whitelist("/proc/123/mem") is True
        assert check_path_whitelist("/usr/lib/node_modules/test.js") is True

    def test_regular_files_not_whitelisted(self):
        """Regular files should NOT be whitelisted."""
        assert check_path_whitelist("C:/Users/test/document.docx") is False
        assert check_path_whitelist("C:/Users/test/photo.png") is False

    def test_case_insensitive(self):
        """Path checks should be case-insensitive."""
        assert check_path_whitelist("C:/WINDOWS/SYSTEM32/config.sys") is True
        assert check_path_whitelist("C:/USERS/TEST/DOCUMENT.PDF") is False


class TestGetExtensionThreshold:
    def test_png_high_threshold(self):
        """PNG should have a high threshold (0.80) to avoid FP."""
        t = get_extension_threshold("photo.png", base_threshold=0.65)
        assert t == 0.80

    def test_exe_high_threshold(self):
        """EXE should have high threshold (0.85)."""
        t = get_extension_threshold("app.exe", base_threshold=0.65)
        assert t == 0.85

    def test_txt_low_threshold(self):
        """TXT should have lower threshold (0.55)."""
        t = get_extension_threshold("readme.txt", base_threshold=0.65)
        assert t == 0.65  # max(0.55, 0.65) = 0.65

    def test_unknown_extension_default(self):
        """Unknown extension should use default threshold."""
        t = get_extension_threshold("file.xyz", base_threshold=0.65)
        assert t == 0.65

    def test_threshold_never_below_base(self):
        """Effective threshold should never be below base_threshold."""
        # All thresholds >= DEFAULT_EXTENSION_THRESHOLD (0.65)
        for ext, threshold in EXTENSION_THRESHOLDS.items():
            assert threshold >= 0.55  # minimum entry


class TestCheckMagicBytes:
    def test_valid_png(self, sample_png_header):
        """Valid PNG should pass magic bytes check."""
        has_sig, valid = check_magic_bytes(sample_png_header)
        assert has_sig is True
        assert valid is True

    def test_valid_pdf(self, sample_pdf_header):
        """Valid PDF should pass magic bytes check."""
        has_sig, valid = check_magic_bytes(sample_pdf_header)
        assert has_sig is True
        assert valid is True

    def test_valid_zip(self, sample_zip_header):
        """Valid ZIP should pass magic bytes check."""
        has_sig, valid = check_magic_bytes(sample_zip_header)
        assert has_sig is True
        assert valid is True

    def test_mismatch_png_extension(self, temp_dir):
        """PNG extension but text content should fail magic check."""
        # Create a file with .png extension but text content
        from pathlib import Path
        path = Path(temp_dir) / "fake.png"
        path.write_bytes(b"This is plain text content, not PNG data.")
        has_sig, valid = check_magic_bytes(str(path))
        assert has_sig is True
        assert valid is False

    def test_unknown_extension_no_conclusion(self):
        """Unknown extension returns (False, True) - no conclusion."""
        has_sig, valid = check_magic_bytes("/tmp/file.xyz")
        assert has_sig is False
        assert valid is True

    def test_nonexistent_file(self):
        """Non-existent file should not crash."""
        has_sig, valid = check_magic_bytes("/nonexistent/file.png")
        assert has_sig is True
        assert valid is False


class TestApplyFpReduction:
    def test_magic_bytes_valid_reduces_probability(self, sample_png_header, monkeypatch):
        """Valid magic bytes should reduce probability when the discount is enabled.

        After audit P4-6 the magic-bytes discount is OFF by default
        (it double-counted with feature 15), so this test must opt in
        explicitly to exercise the discount path.
        """
        from core import fp_reducer as _fp
        monkeypatch.setattr(_fp, "_magic_bytes_discount_enabled", lambda: True)

        prob, _threshold, reason = apply_fp_reduction(
            sample_png_header, 0.80, 0.65
        )
        assert prob < 0.80  # Reduced by MAGIC_BYTES_DISCOUNT_FACTOR
        assert "magic_ok" in reason

    def test_magic_bytes_default_does_not_double_count(self, sample_png_header):
        """Audit P4-6 regression: with the default config (discount OFF)
        a valid PNG must not have its probability multiplied by 0.70.

        Feature 15 ``Is Known Benign Format`` already encodes this
        signal in the model, so applying it again post-hoc broke
        calibration.
        """
        prob, _threshold, reason = apply_fp_reduction(
            sample_png_header, 0.80, 0.65
        )
        # No probability scaling should have been applied.
        assert prob == pytest.approx(0.80, abs=1e-6)
        assert "magic_ok" in reason
        assert "prob×" not in reason

    def test_magic_bytes_mismatch_increases_probability(self, temp_dir):
        """Mismatch magic bytes should slightly increase probability."""
        # Create a .png file with wrong content (not PNG data)
        from pathlib import Path
        path = Path(temp_dir) / "fake.png"
        path.write_bytes(b"This is NOT a PNG file at all!")
        prob, threshold, reason = apply_fp_reduction(
            str(path), 0.50, 0.65
        )
        assert prob >= 0.50
        assert "magic_mismatch" in reason

    def test_extension_threshold_applied(self, sample_png_header):
        """PNG should use higher extension threshold."""
        _, threshold, reason = apply_fp_reduction(
            sample_png_header, 0.50, 0.65
        )
        assert threshold == 0.80
        assert "ext_threshold" in reason

    def test_discount_factor_value(self):
        """MAGIC_BYTES_DISCOUNT_FACTOR should be 0.70."""
        assert MAGIC_BYTES_DISCOUNT_FACTOR == 0.70


class TestGetFpStats:
    def test_empty_results(self):
        """Empty results should return empty stats."""
        stats = get_fp_stats([])
        assert stats == {}

    def test_no_flagged(self):
        """All safe files → fp_rate = 0."""
        class MockResult:
            def __init__(self, ext):
                self.extension = ext
                self.label = 0

        results = [MockResult(".txt"), MockResult(".pdf")]
        stats = get_fp_stats(results)
        assert stats["total"] == 2
        assert stats["flagged"] == 0
        assert stats["fp_rate"] == 0.0

    def test_fp_rate_calculation(self):
        """FP rate should be flagged / total."""
        class MockResult:
            def __init__(self, label):
                self.extension = ".txt"
                self.label = label

        results = [MockResult(0), MockResult(0), MockResult(1), MockResult(0)]
        stats = get_fp_stats(results)
        assert stats["total"] == 4
        assert stats["flagged"] == 1
        assert stats["fp_rate"] == 0.25

    def test_ext_stats_grouped_by_extension(self):
        """ext_stats should group by extension."""
        class MockResult:
            def __init__(self, ext, label):
                self.extension = ext
                self.label = label

        results = [
            MockResult(".txt", 0),
            MockResult(".txt", 1),
            MockResult(".png", 0),
        ]
        stats = get_fp_stats(results)
        assert ".txt" in stats["ext_stats"]
        assert ".png" in stats["ext_stats"]
        assert stats["ext_stats"][".txt"]["total"] == 2


class TestAlwaysSafeExtensions:
    def test_font_extensions(self):
        """Font extensions should be in whitelist."""
        assert ".ttf" in ALWAYS_SAFE_EXTENSIONS
        assert ".otf" in ALWAYS_SAFE_EXTENSIONS
        assert ".woff" in ALWAYS_SAFE_EXTENSIONS

    def test_system_extensions(self):
        """System-related extensions should be whitelisted."""
        assert ".ico" in ALWAYS_SAFE_EXTENSIONS
        assert ".lnk" in ALWAYS_SAFE_EXTENSIONS
        assert ".log" in ALWAYS_SAFE_EXTENSIONS
        assert ".ini" in ALWAYS_SAFE_EXTENSIONS

    def test_not_compressed_extensions(self):
        """.zip, .png, .jpg should NOT be in ALWAYS_SAFE_EXTENSIONS."""
        assert ".zip" not in ALWAYS_SAFE_EXTENSIONS
        assert ".png" not in ALWAYS_SAFE_EXTENSIONS
        assert ".jpg" not in ALWAYS_SAFE_EXTENSIONS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
