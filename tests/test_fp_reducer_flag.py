"""
test_fp_reducer_flag.py
=======================
Audit P4-6 regression test for the
``fp_reducer.disable_magic_bytes_discount`` config flag.

Pre-fix the magic-bytes discount (×0.70) was always applied even though
feature 15 ``Is Known Benign Format`` already encodes the same signal,
producing a double-counted FP-reduction. The flag now defaults to
**True** (discount disabled) so the model alone owns that decision;
operators must opt in to restore the legacy behaviour.
"""

import pytest

from core import fp_reducer


@pytest.fixture
def png_file(tmp_path):
    """Tiny valid-PNG file so ``check_magic_bytes`` returns (True, True)."""
    path = tmp_path / "logo.png"
    # PNG signature + minimal header.
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n" +
        b"\x00\x00\x00\x0DIHDR" +  # IHDR length + tag
        b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00" +
        b"\x90\x77\x53\xDE" +  # CRC
        b"\x00" * 32
    )
    return str(path)


class TestMagicBytesDiscountFlag:
    def test_discount_when_explicitly_enabled(self, png_file, monkeypatch):
        """Helper returns True (legacy opt-in) ⇒ probability ×0.70."""
        monkeypatch.setattr(
            fp_reducer, "_magic_bytes_discount_enabled", lambda: True
        )
        adj, _, reason = fp_reducer.apply_fp_reduction(
            png_file, probability=0.80, base_threshold=0.65
        )
        assert adj == pytest.approx(0.80 * 0.70, abs=1e-6)
        assert "magic_ok→prob×" in reason

    def test_default_disables_discount(self, png_file):
        """Audit P4-6: default behaviour (no flag set) ⇒ no probability scaling.

        With feature 15 in the model, applying the 0.70 discount on top
        would double-count and break calibration.
        """
        adj, _, reason = fp_reducer.apply_fp_reduction(
            png_file, probability=0.80, base_threshold=0.65
        )
        assert adj == pytest.approx(0.80, abs=1e-6)
        assert "discount_disabled" in reason
        assert "prob×" not in reason

    def test_flag_disables_discount(self, png_file, monkeypatch):
        """Flag True ⇒ probability passes through unchanged + reason annotated."""
        monkeypatch.setattr(
            fp_reducer, "_magic_bytes_discount_enabled", lambda: False
        )
        adj, _, reason = fp_reducer.apply_fp_reduction(
            png_file, probability=0.80, base_threshold=0.65
        )
        assert adj == pytest.approx(0.80, abs=1e-6)
        assert "discount_disabled" in reason
        assert "prob×" not in reason  # no scaling applied

    def test_helper_reads_config(self, monkeypatch):
        """``_magic_bytes_discount_enabled`` mirrors the config flag.

        New default (post-audit P4-6): when the flag is absent the
        helper returns False (discount disabled), preserving model
        calibration. The flag is honoured exactly when it is present.
        """
        from core import config_manager as cm

        # Stub the singleton config so we never touch user config.json.
        # ``default`` mirrors the production caller's signature so we
        # exercise the new default = True semantics.
        class _StubCfg:
            def __init__(self, value):
                self._v = value
            def get(self, key, default=None):
                if key == "fp_reducer.disable_magic_bytes_discount":
                    return self._v if self._v is not None else default
                return default

        # Flag explicitly True ⇒ discount disabled.
        monkeypatch.setattr(cm, "config", _StubCfg(True))
        assert fp_reducer._magic_bytes_discount_enabled() is False

        # Flag explicitly False ⇒ discount enabled (legacy opt-in).
        monkeypatch.setattr(cm, "config", _StubCfg(False))
        assert fp_reducer._magic_bytes_discount_enabled() is True

        # Flag absent (None) ⇒ helper sees the default=True ⇒ disabled.
        monkeypatch.setattr(cm, "config", _StubCfg(None))
        assert fp_reducer._magic_bytes_discount_enabled() is False


class TestSpecialMagicBoundsCheck:
    """Audit P3-5 regression: short headers must not crash _check_special_magic."""

    def test_truncated_mp4_returns_invalid(self, tmp_path):
        path = tmp_path / "tiny.mp4"
        path.write_bytes(b"abc")  # 3 bytes — below the 12-byte slice
        has_sig, valid = fp_reducer._check_special_magic(str(path), ".mp4")
        assert has_sig is True
        assert valid is False

    def test_truncated_webp_returns_invalid(self, tmp_path):
        path = tmp_path / "tiny.webp"
        path.write_bytes(b"RIFF")  # only 4 bytes
        has_sig, valid = fp_reducer._check_special_magic(str(path), ".webp")
        assert valid is False

    def test_full_mp4_header_recognised(self, tmp_path):
        path = tmp_path / "movie.mp4"
        # 12 bytes: 4 bytes box-size + 'ftyp' + 4 bytes brand
        path.write_bytes(b"\x00\x00\x00\x18ftypisom")
        has_sig, valid = fp_reducer._check_special_magic(str(path), ".mp4")
        assert has_sig is True
        assert valid is True
