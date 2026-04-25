import csv

from core.pe_corpus_preparer import prepare_pe_samples


def test_prepare_pe_samples_copies_only_pe_files(temp_dir):
    input_dir = temp_dir / "corpus"
    output_dir = temp_dir / "prepared"
    input_dir.mkdir()
    output_dir.mkdir()

    (input_dir / "safe.exe").write_bytes(b"MZ" + bytes(range(64)))
    (input_dir / "note.txt").write_text("not a pe", encoding="utf-8")

    result = prepare_pe_samples(
        input_dir=str(input_dir),
        output_dir=str(output_dir),
        recursive=True,
    )

    assert result["copied"] == 1
    assert result["non_pe_skipped"] == 1
    assert (output_dir / "manifest.csv").exists()

    with open(output_dir / "manifest.csv", "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 1
    assert rows[0]["extension"] == ".exe"


def test_prepare_pe_samples_deduplicates_existing_hashes(temp_dir):
    input_dir = temp_dir / "corpus"
    output_dir = temp_dir / "prepared"
    input_dir.mkdir()
    output_dir.mkdir()

    sample_bytes = b"MZ" + bytes(range(64))
    (input_dir / "a.exe").write_bytes(sample_bytes)
    (input_dir / "b.exe").write_bytes(sample_bytes)

    first = prepare_pe_samples(
        input_dir=str(input_dir),
        output_dir=str(output_dir),
        recursive=True,
    )
    second = prepare_pe_samples(
        input_dir=str(input_dir),
        output_dir=str(output_dir),
        recursive=True,
    )

    assert first["copied"] == 1
    assert second["copied"] == 0
    assert second["duplicate_skipped"] >= 1
