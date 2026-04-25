from core.training_source_registry import render_training_sources, search_training_sources


def test_search_training_sources_safe_query():
    results = search_training_sources(query="benign exe", kind="safe")
    ids = {item["id"] for item in results}
    assert "napierone" in ids or "trusted-vendors" in ids


def test_search_training_sources_encrypted_pe_only():
    results = search_training_sources(kind="encrypted", pe_only=True)
    ids = {item["id"] for item in results}
    assert "sorel20m-github" in ids
    assert "sorel20m-aws" in ids


def test_render_training_sources_no_result():
    output = render_training_sources(query="no-such-source")
    assert "No matching training sources found." in output
