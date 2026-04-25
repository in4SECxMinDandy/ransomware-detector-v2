import csv

import pytest

from core.external_dataset_builder import (
    build_external_dataset,
    compute_sha256,
    is_pe_file,
    is_placeholder_path,
)


def test_is_pe_file():
    assert is_pe_file("sample.exe") is True
    assert is_pe_file("sample.dll") is True
    assert is_pe_file("sample.txt") is False


def test_placeholder_path_detection():
    assert is_placeholder_path(r"C:\path\to\safe") is True
    assert is_placeholder_path(r"C:\duong-dan-that\safe") is True
    assert is_placeholder_path(r"C:\Users\haqua\safe") is False


def test_compute_sha256(temp_dir):
    file_path = temp_dir / "sample.exe"
    file_path.write_bytes(b"MZ" + bytes(range(128)))
    assert len(compute_sha256(str(file_path))) == 64


def test_build_external_dataset_filters_to_pe_and_exports_csv(temp_dir):
    safe_dir = temp_dir / "safe"
    enc_dir = temp_dir / "encrypted"
    safe_dir.mkdir()
    enc_dir.mkdir()

    (safe_dir / "doc1.txt").write_bytes(b"Hello safe world\n" * 200)
    (safe_dir / "app.exe").write_bytes(b"MZ" + bytes(range(256)) * 8)
    (enc_dir / "sample1.enc").write_bytes(bytes(range(256)) * 32)
    (enc_dir / "mal.dll").write_bytes(b"MZ" + bytes(reversed(range(256))) * 8)

    output_csv = temp_dir / "external_dataset.csv"
    result = build_external_dataset(
        safe_dir=str(safe_dir),
        encrypted_dir=str(enc_dir),
        output_csv=str(output_csv),
        recursive=True,
    )

    assert result["safe_count"] == 1
    assert result["encrypted_count"] == 1
    assert result["safe_stats"]["non_pe_skipped"] == 1
    assert result["encrypted_stats"]["non_pe_skipped"] == 1
    assert result["total"] == 2
    assert result["pe_only"] is True
    assert output_csv.exists()

    with open(output_csv, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 2
    assert {row["label_name"] for row in rows} == {"SAFE", "ENCRYPTED"}
    assert all(row["extension"] in {".exe", ".dll"} for row in rows)


def test_build_external_dataset_deduplicates_conflicting_hashes(temp_dir):
    safe_dir = temp_dir / "safe"
    enc_dir = temp_dir / "encrypted"
    safe_dir.mkdir()
    enc_dir.mkdir()

    same_bytes = b"MZ" + bytes(range(256)) * 8
    (safe_dir / "app.exe").write_bytes(same_bytes)
    (enc_dir / "same.exe").write_bytes(same_bytes)

    output_csv = temp_dir / "external_dataset.csv"
    result = build_external_dataset(
        safe_dir=str(safe_dir),
        encrypted_dir=str(enc_dir),
        output_csv=str(output_csv),
        recursive=True,
    )

    assert result["conflicting_hashes"] == 1
    assert result["safe_count"] == 0
    assert result["encrypted_count"] == 0
    assert result["total"] == 0


def test_build_external_dataset_rejects_placeholder_path(temp_dir):
    with pytest.raises(ValueError):
        build_external_dataset(
            safe_dir=r"C:\path\to\safe",
            encrypted_dir=str(temp_dir / "encrypted"),
            output_csv=str(temp_dir / "external_dataset.csv"),
            recursive=True,
        )
