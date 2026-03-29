"""
test_feature_extractor.py
========================
Unit tests for core/feature_extractor.py
"""

import sys
import os
import pytest
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.feature_extractor import (
    _shannon_entropy,
    _chi_square,
    _serial_correlation,
    _check_magic_bytes,
    _is_known_benign_format,
    _extension_entropy_delta,
    _structural_consistency,
    _byte_distribution_mode,
    _compression_ratio_estimate,
    extract_features,
    FEATURE_NAMES,
    N_FEATURES,
)


class TestShannonEntropy:
    def test_random_bytes_high_entropy(self):
        """Random bytes should produce high entropy (~7.95)."""
        data = bytes(range(256)) * 4  # uniform distribution
        h = _shannon_entropy(data)
        assert 7.5 < h <= 8.0

    def test_low_entropy_repeated_bytes(self):
        """Repeated bytes should produce low entropy."""
        data = b"\x00" * 1000
        h = _shannon_entropy(data)
        assert h == 0.0

    def test_empty_data(self):
        """Empty data should return 0.0."""
        assert _shannon_entropy(b"") == 0.0

    def test_short_data(self):
        """Short data should still compute entropy."""
        data = b"Hello World!"
        h = _shannon_entropy(data)
        assert 3.0 < h < 6.0


class TestChiSquare:
    def test_random_bytes_high_chi2(self):
        """Random bytes should have high chi-square (no pattern)."""
        rng = np.random.default_rng(42)
        data = rng.integers(0, 256, size=10000, dtype=np.uint8).tobytes()
        chi2 = _chi_square(data)
        assert chi2 > 200  # Should deviate significantly from expected

    def test_empty_data(self):
        """Empty data should return 0.0."""
        assert _chi_square(b"") == 0.0

    def test_small_data(self):
        """Data < 256 bytes should return 0.0."""
        assert _chi_square(b"hello") == 0.0


class TestSerialCorrelation:
    def test_random_data_low_correlation(self):
        """Random bytes should have near-zero serial correlation."""
        rng = np.random.default_rng(123)
        data = rng.integers(0, 256, size=1000, dtype=np.uint8).tobytes()
        corr = _serial_correlation(data)
        assert -0.1 < corr < 0.1

    def test_increasing_pattern_high_correlation(self):
        """Monotonically increasing bytes should have high correlation."""
        data = bytes(range(256)) * 4
        corr = _serial_correlation(data)
        assert corr > 0.9

    def test_empty_data(self):
        """Empty data should return 0.0."""
        assert _serial_correlation(b"") == 0.0

    def test_single_byte(self):
        """Single byte should return 0.0."""
        assert _serial_correlation(b"x") == 0.0


class TestMagicBytes:
    def test_png_header_valid(self):
        """Valid PNG header should pass."""
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
        assert _check_magic_bytes(data, ".png") == 0

    def test_png_header_mismatch(self):
        """PNG header with wrong extension should fail."""
        data = b"\x00" * 16
        assert _check_magic_bytes(data, ".png") == 1

    def test_pdf_header(self):
        """Valid PDF header should pass."""
        data = b"%PDF-1.4" + b"\x00" * 20
        assert _check_magic_bytes(data, ".pdf") == 0

    def test_zip_header(self):
        """Valid ZIP header should pass."""
        data = b"PK\x03\x04" + b"\x00" * 20
        assert _check_magic_bytes(data, ".zip") == 0

    def test_unknown_extension(self):
        """Unknown extension should return 0 (no conclusion)."""
        data = b"hello world"
        assert _check_magic_bytes(data, ".xyz") == 0


class TestKnownBenignFormat:
    def test_valid_png_returns_one(self):
        """Valid PNG should return 1.0."""
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
        assert _is_known_benign_format(data, ".png") == 1.0

    def test_invalid_png_returns_zero(self):
        """Invalid PNG should return 0.0."""
        data = b"NOT A PNG FILE"
        assert _is_known_benign_format(data, ".png") == 0.0

    def test_unknown_ext_returns_zero(self):
        """Unknown extension should return 0.0."""
        assert _is_known_benign_format(b"hello", ".xyz") == 0.0


class TestExtensionEntropyDelta:
    def test_png_high_entropy_normal(self):
        """PNG with high entropy should have small delta (expected)."""
        # PNG baseline: mean=7.60, std=0.35
        # Entropy 7.6 → z = (7.6-7.6)/0.35 = 0
        delta = _extension_entropy_delta(7.6, ".png")
        assert abs(delta) < 0.1

    def test_txt_high_entropy_suspicious(self):
        """TXT with high entropy should have large positive delta."""
        # TXT baseline: mean=4.0, std=0.8
        # Entropy 7.6 → z = (7.6-4.0)/0.8 = 4.5
        delta = _extension_entropy_delta(7.6, ".txt")
        assert delta > 2.0

    def test_unknown_extension_uses_default(self):
        """Unknown extension should use default baseline."""
        delta = _extension_entropy_delta(5.0, ".xyz")
        # Default baseline: mean=5.5, std=2.0
        # z = (5.0-5.5)/2.0 = -0.25
        assert -1.0 < delta < 0.5


class TestStructuralConsistency:
    def test_uniform_chunks_high_consistency(self):
        """Uniform entropy across chunks → high consistency."""
        # All chunks at entropy 7.8 (compressed file)
        chunks = np.array([7.8, 7.8, 7.8, 7.8])
        score = _structural_consistency(chunks)
        assert score > 0.8

    def test_varying_chunks_low_consistency(self):
        """High variance across chunks → low consistency."""
        chunks = np.array([0.0, 7.8, 0.0, 7.8])
        score = _structural_consistency(chunks)
        assert score < 0.3

    def test_single_chunk(self):
        """Single chunk should return 1.0."""
        chunks = np.array([5.0])
        assert _structural_consistency(chunks) == 1.0

    def test_empty_chunks(self):
        """Empty chunk array should return 1.0."""
        assert _structural_consistency(np.array([])) == 1.0


class TestByteDistributionMode:
    def test_random_data_low_mode(self):
        """Random data has near-uniform distribution → low mode freq."""
        rng = np.random.default_rng(99)
        data = rng.integers(0, 256, size=10000, dtype=np.uint8).tobytes()
        freq = _byte_distribution_mode(data)
        assert freq < 0.02  # No byte appears more than 2%

    def test_repeated_bytes_high_mode(self):
        """Repeated bytes → one byte dominates → high mode freq."""
        data = b"a" * 500 + b"b" * 500
        freq = _byte_distribution_mode(data)
        assert abs(freq - 0.5) < 0.01

    def test_empty_data(self):
        """Empty data should return 0.0."""
        assert _byte_distribution_mode(b"") == 0.0


class TestCompressionRatioEstimate:
    def test_text_easy_to_compress(self):
        """Repeated patterns should be easy to compress."""
        data = b"aaaaaaaaaa" * 100
        ratio = _compression_ratio_estimate(data)
        assert ratio > 0.8  # Low transition rate

    def test_random_data_hard_to_compress(self):
        """Random bytes should be hard to compress."""
        rng = np.random.default_rng(7)
        data = rng.integers(0, 256, size=1000, dtype=np.uint8).tobytes()
        ratio = _compression_ratio_estimate(data)
        assert ratio < 0.3  # High transition rate

    def test_short_data(self):
        """Very short data should return 0.0."""
        assert _compression_ratio_estimate(b"a") == 0.0


class TestExtractFeatures:
    def test_returns_16_features(self, sample_safe_file):
        """extract_features should return a 16-element vector."""
        feats = extract_features(sample_safe_file)
        assert feats is not None
        assert len(feats) == 16

    def test_feature_names_length_matches_n_features(self):
        """FEATURE_NAMES should have N_FEATURES entries."""
        assert len(FEATURE_NAMES) == N_FEATURES == 16

    def test_safe_file_low_entropy(self, sample_safe_file):
        """Safe text file should have low entropy."""
        feats = extract_features(sample_safe_file)
        assert feats is not None
        assert feats[0] < 5.5  # shannon_entropy

    def test_random_file_high_entropy(self, sample_random_file):
        """Random bytes file should have high entropy."""
        feats = extract_features(sample_random_file)
        assert feats is not None
        assert feats[0] > 7.5  # shannon_entropy

    def test_png_valid_magic(self, sample_png_header):
        """PNG with valid magic bytes → magic_mismatch=0."""
        feats = extract_features(sample_png_header)
        assert feats is not None
        assert feats[9] == 0.0  # magic_bytes_mismatch

    def test_pdf_valid_magic(self, sample_pdf_header):
        """PDF with valid magic bytes → known_benign_fmt=1.0."""
        feats = extract_features(sample_pdf_header)
        assert feats is not None
        assert feats[15] == 1.0  # is_known_benign_fmt

    def test_nonexistent_file_returns_none(self):
        """Non-existent file should return None."""
        assert extract_features("/nonexistent/file.txt") is None

    def test_empty_file_returns_none(self, temp_dir):
        """Empty file should return None."""
        path = temp_dir / "empty.txt"
        path.touch()
        assert extract_features(str(path)) is None

    def test_nan_inf_handled(self, sample_safe_file):
        """Features should not contain NaN or Inf."""
        feats = extract_features(sample_safe_file)
        assert feats is not None
        assert not np.any(np.isnan(feats))
        assert not np.any(np.isinf(feats))


class TestNFeaturesConstant:
    def test_n_features_is_16(self):
        """N_FEATURES must be 16."""
        assert N_FEATURES == 16


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
