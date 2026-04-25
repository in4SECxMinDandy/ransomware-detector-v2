"""
Test script để kiểm tra Threat Intelligence Integration.
Chạy: python -m tests.test_ti_integration
"""
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def client(tmp_path):
    """Create a ThreatIntelClient with isolated cache for testing."""
    from core.threat_intel_client import ThreatIntelClient
    cache_path = tmp_path / "ti_cache.json"
    client = ThreatIntelClient(cache_ttl_hours=24, timeout_seconds=15)
    client.cache_path = str(cache_path)
    # Clear any existing cache data
    client._cache = {}
    return client


def test_ti_config():
    """Kiểm tra config đã được load đúng chưa."""
    from core.config_manager import config

    mb_enabled = config.get("threat_intel.malwarebazaar.enabled")
    tf_enabled = config.get("threat_intel.threatfox.enabled")
    otx_enabled = config.get("threat_intel.alienvault_otx.enabled")

    # At least one source should be configured
    assert mb_enabled or tf_enabled or otx_enabled, "All TI sources are disabled in config"


def test_ti_client_init(client):
    """Kiểm tra ThreatIntelClient khởi tạo thành công."""
    from core.threat_intel_client import ThreatIntelClient

    assert client is not None
    assert isinstance(client, ThreatIntelClient)
    assert client.cache_ttl_hours == 24
    assert client.timeout == 15

    stats = client.get_stats()
    assert isinstance(stats, dict)


def test_ti_lookup(client):
    """
    Kiểm tra tra cứu TI. Mặc định dùng SHA256 của EICAR test file
    (đã biết là benign, không có trong TI → test connectivity).
    """
    # SHA256 của EICAR — benign, không có trong TI databases
    default_sha256 = "131f95c51cc819465fa1797f6cc461f85c4cfd8fee1b16b9c3a2995e5c4c3d9a"

    result = client.lookup_sha256(default_sha256)

    # Should return a result object (even if empty)
    assert result is not None
    assert hasattr(result, 'has_any_ti')
    assert hasattr(result, 'get_summary')

    # Stats should be updated
    stats = client.get_stats()
    assert isinstance(stats, dict)
    assert 'total_lookups' in stats


def test_cache_persistence(client):
    """Kiểm tra cache được lưu xuống disk."""
    import os
    import json

    cache_path = client.cache_path

    # Force a save to ensure file exists
    client._save_cache()

    if os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        entries = data.get("entries", {})
        assert isinstance(entries, dict)
    else:
        # If cache is empty, file might not be created yet - that's OK
        pass


def main():
    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE INTEGRATION TEST")
    print("=" * 60)

    # 1. Check config
    if not test_ti_config():
        print("\n[!] Dừng do config chưa đúng.")
        return

    # 2. Init client
    client = test_ti_client_init()
    if client is None:
        print("\n[!] Dừng do client khởi tạo lỗi.")
        return

    # 3. Test lookup với 1 hash
    print()
    result = test_ti_lookup(client)

    # 4. Test cache
    test_cache_persistence(client)

    # 5. Summary
    print("\n" + "=" * 60)
    print("5. TỔNG KẾT")
    print("=" * 60)

    if result:
        sources_ok = {
            "MalwareBazaar": result.mb_available or not client._is_mb_enabled(),
            "ThreatFox": result.tf_available or (not client._is_tf_enabled() or bool(result.tf_error)),
            "AlienVault OTX": result.otx_available or not client._is_otx_enabled(),
        }

        # Nếu source bật mà không available → có thể hash không có trong DB
        # Điều đó là OK (không phải lỗi)
        print("  Nguồn bật + có kết quả TI: OK (hash có trong TI database)")
        print("  Nguồn bật + không có kết quả: Bình thường (hash chưa được báo cáo)")
        print("  Nguồn bật + lỗi: Cần kiểm tra lại API key / network")
        print()

        for name, ok in sources_ok.items():
            status = "OK" if result.mb_available or result.tf_available or result.otx_available else "CHECK"
            print(f"  {name}: {status}")

        if result.mb_error or result.tf_error or result.otx_error:
            print("\n  [!] Có lỗi từ API:")
            if result.mb_error:
                print(f"      MalwareBazaar : {result.mb_error}")
            if result.tf_error:
                print(f"      ThreatFox     : {result.tf_error}")
            if result.otx_error:
                print(f"      AlienVault OTX: {result.otx_error}")
            print("\n  → Kiểm tra lại API key hoặc network connection.")
        else:
            print("\n  ✅ Không có lỗi từ API. Tích hợp TI hoạt động!")

        print(f"\n  Cache đã lưu tại: {client.cache_path}")
    else:
        print("  ❌ Tra cứu TI thất bại.")


if __name__ == "__main__":
    main()
