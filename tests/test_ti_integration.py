"""
Test script để kiểm tra Threat Intelligence Integration.
Chạy: python -m tests.test_ti_integration
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_ti_config():
    """Kiểm tra config đã được load đúng chưa."""
    from core.config_manager import config

    print("=" * 60)
    print("1. KIỂM TRA CONFIG")
    print("=" * 60)

    mb_enabled = config.get("threat_intel.malwarebazaar.enabled")
    mb_key = config.get("threat_intel.malwarebazaar.api_key")
    tf_enabled = config.get("threat_intel.threatfox.enabled")
    tf_key = config.get("threat_intel.threatfox.api_key")
    otx_enabled = config.get("threat_intel.alienvault_otx.enabled")
    otx_key = config.get("threat_intel.alienvault_otx.api_key")

    print(f"  MalwareBazaar : {'ON ' if mb_enabled else 'OFF'} | key={'OK' if not mb_key else 'N/A (no key needed)'}")
    print(f"  ThreatFox     : {'ON ' if tf_enabled else 'OFF'} | key={'OK (len=%d)' % len(tf_key) if tf_key else 'MISSING'}")
    print(f"  AlienVault OTX: {'ON ' if otx_enabled else 'OFF'} | key={'OK (len=%d)' % len(otx_key) if otx_key else 'MISSING'}")

    if not mb_enabled and not tf_enabled and not otx_enabled:
        print("\n  [!] Tất cả nguồn TI đều bị tắt trong config!")
        return False

    return True


def test_ti_client_init():
    """Kiểm tra ThreatIntelClient khởi tạo thành công."""
    print("\n" + "=" * 60)
    print("2. KIỂM TRA THREAT INTEL CLIENT")
    print("=" * 60)

    try:
        from core.threat_intel_client import get_ti_client, ThreatIntelClient

        client = ThreatIntelClient(cache_ttl_hours=24, timeout_seconds=15)
        print(f"  Client khởi tạo: OK")
        print(f"  Cache path     : {client.cache_path}")
        print(f"  Cache TTL      : {client.cache_ttl_hours}h")
        print(f"  Timeout        : {client.timeout}s")

        stats = client.get_stats()
        print(f"  Initial stats  : {stats}")

        return client
    except Exception as e:
        print(f"  [!] Lỗi khởi tạo: {e}")
        return None


def test_ti_lookup(client, sha256: str = None):
    """
    Kiểm tra tra cứu TI. Mặc định dùng SHA256 của EICAR test file
    (đã biết là benign, không có trong TI → test connectivity).
    """
    print("\n" + "=" * 60)
    print("3. KIỂM TRA TRA CỨU TI")
    print("=" * 60)

    # SHA256 của EICAR — benign, không có trong TI databases
    default_sha256 = "131f95c51cc819465fa1797f6cc461f85c4cfd8fee1b16b9c3a2995e5c4c3d9a"
    test_hash = sha256 or default_sha256
    print(f"  Test SHA256: {test_hash}")

    try:
        result = client.lookup_sha256(test_hash)
        print(f"\n  === KẾT QUẢ TI ===")
        print(f"  has_any_ti  : {result.has_any_ti()}")
        print(f"  Summary     : {result.get_summary()}")

        print(f"\n  [MalwareBazaar]")
        print(f"    available       : {result.mb_available}")
        print(f"    family          : {result.mb_family or 'N/A'}")
        print(f"    signature       : {result.mb_signature or 'N/A'}")
        print(f"    first_seen      : {result.mb_first_seen or 'N/A'}")
        print(f"    delivery_method : {result.mb_delivery_method or 'N/A'}")
        print(f"    tags            : {result.mb_tags or 'N/A'}")
        print(f"    error           : {result.mb_error or 'None'}")

        print(f"\n  [ThreatFox]")
        print(f"    available      : {result.tf_available}")
        print(f"    threat_type    : {result.tf_threat_type or 'N/A'}")
        print(f"    malware_family : {result.tf_malware_family or 'N/A'}")
        print(f"    confidence     : {result.tf_confidence}")
        print(f"    tags           : {result.tf_tags or 'N/A'}")
        print(f"    error          : {result.tf_error or 'None'}")

        print(f"\n  [AlienVault OTX]")
        print(f"    available        : {result.otx_available}")
        print(f"    pulse_count      : {result.otx_pulse_count}")
        print(f"    pulse_names      : {result.otx_pulse_names or 'N/A'}")
        print(f"    analysis_metadata: {result.otx_analysis_metadata or 'N/A'}")
        print(f"    error            : {result.otx_error or 'None'}")

        # Kiểm tra stats
        stats = client.get_stats()
        print(f"\n  [Stats]")
        for k, v in stats.items():
            print(f"    {k}: {v}")

        return result

    except Exception as e:
        import traceback
        print(f"  [!] Lỗi tra cứu: {e}")
        traceback.print_exc()
        return None


def test_cache_persistence(client):
    """Kiểm tra cache được lưu xuống disk."""
    print("\n" + "=" * 60)
    print("4. KIỂM TRA CACHE PERSISTENCE")
    print("=" * 60)

    import os, json

    cache_path = client.cache_path
    print(f"  Cache file: {cache_path}")
    print(f"  File exists: {os.path.exists(cache_path)}")

    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            entries = data.get("entries", {})
            print(f"  Cached entries: {len(entries)}")
            print(f"  Last updated : {data.get('last_updated', 'N/A')}")
        except Exception as e:
            print(f"  [!] Lỗi đọc cache: {e}")
    else:
        print("  Cache file chưa được tạo (lần đầu chạy)")


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

        all_healthy = True
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
