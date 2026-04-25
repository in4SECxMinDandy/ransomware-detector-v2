"""
conftest.py — Shared test fixtures
=================================
"""

import sys
import tempfile
import shutil
from pathlib import Path

import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(autouse=True)
def _isolate_jwt_secret(monkeypatch):
    """
    Provide a deterministic JWT secret to every test so api/auth.py never
    falls back to mutating ``data/config.json`` during the suite. Tests that
    need to flip the secret can still override the env var locally.
    """
    monkeypatch.setenv("RANSOMWARE_JWT_SECRET", "tests-only-secret-" + "x" * 40)
    yield


@pytest.fixture
def project_root():
    """Return the project root directory."""
    return PROJECT_ROOT


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def sample_safe_file(temp_dir):
    """Create a benign text file."""
    path = temp_dir / "document.txt"
    path.write_bytes(b"Hello, this is a safe text document.\n" * 100)
    return str(path)


@pytest.fixture
def sample_random_file(temp_dir):
    """Create a file with random-ish bytes (high entropy)."""
    import numpy as np
    path = temp_dir / "random.bin"
    data = np.random.bytes(4096)
    path.write_bytes(data)
    return str(path)


@pytest.fixture
def sample_png_header(temp_dir):
    """Create a file with valid PNG magic bytes."""
    path = temp_dir / "image.png"
    # PNG signature + minimal valid data
    png_sig = b"\x89PNG\r\n\x1a\n"
    # IHDR chunk (13 bytes) + minimal data
    ihdr = b"\x00\x00\x00\x0D"  # length = 13
    ihdr += b"IHDR"
    ihdr += b"\x00\x00\x00\x01"  # width = 1
    ihdr += b"\x00\x00\x00\x01"  # height = 1
    ihdr += b"\x08"              # bit depth = 8
    ihdr += b"\x02"              # color type = RGB
    ihdr += b"\x00"              # compression
    ihdr += b"\x00"              # filter
    ihdr += b"\x00"              # interlace
    crc = b"\x90\x77\x53\xDE"    # CRC (dummy)
    path.write_bytes(png_sig + ihdr + crc + b"\x00" * 20)
    return str(path)


@pytest.fixture
def sample_pdf_header(temp_dir):
    """Create a file with valid PDF magic bytes."""
    path = temp_dir / "document.pdf"
    path.write_bytes(b"%PDF-1.4\n%\xd0\xd4\xc5\xd8" + b"x" * 200)
    return str(path)


@pytest.fixture
def sample_zip_header(temp_dir):
    """Create a file with valid ZIP magic bytes."""
    path = temp_dir / "archive.zip"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return str(path)


@pytest.fixture
def mock_engine():
    """Create a mock ML engine that returns known values."""
    class MockEngine:
        def __init__(self):
            self._threshold = 0.65
            self._loaded = True

        def is_loaded(self):
            return self._loaded

        def get_threshold(self):
            return self._threshold

        def set_threshold(self, t):
            self._threshold = t

        def predict(self, features):
            # Return a medium probability
            return 0, 0.42

        def get_risk_level(self, prob):
            if prob >= 0.80:
                return "CRITICAL"
            elif prob >= 0.65:
                return "HIGH"
            elif prob >= 0.45:
                return "MEDIUM"
            elif prob >= 0.30:
                return "LOW"
            return "SAFE"

    return MockEngine()
