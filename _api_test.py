import httpx

tests = [
    {
        "name": "MalwareBazaar",
        "method": "POST",
        "url": "https://bazaar.abuse.ch/api/",
        "json": {"query": "get_info", "hash": "131f95c51cc819465fa1797f6cc461f85c4cfd8fee1b16b9c3a2995e5c4c3d9a"},
        "headers": None,
    },
    {
        "name": "ThreatFox",
        "method": "POST",
        "url": "https://threatfox.abuse.ch/api/",
        "json": {"query": "search_ioc", "hash": "131f95c51cc819465fa1797f6cc461f85c4cfd8fee1b16b9c3a2995e5c4c3d9a"},
        "headers": {"API-KEY": "f2a488ca94a8faf695ee9398352e10747c5ffd7eb774df83"},
    },
    {
        "name": "AlienVault OTX",
        "method": "GET",
        "url": "https://otx.alienvault.com/api/v1/indicators/file/sha256/131f95c51cc819465fa1797f6cc461f85c4cfd8fee1b16b9c3a2995e5c4c3d9a",
        "json": None,
        "headers": {"X-OTX-API-KEY": "fb1afdc5636105f1dcb6fdb39fe225867cf78d766ea126d586c5e9641d006f4a"},
    },
]

for t in tests:
    print(f"\n=== {t['name']} ===")
    try:
        if t["method"] == "POST":
            r = httpx.post(t["url"], json=t["json"], headers=t["headers"], timeout=15)
        else:
            r = httpx.get(t["url"], headers=t["headers"], timeout=15)
        ct = r.headers.get("content-type", "")
        print(f"Status: {r.status_code} | Content-Type: {ct}")
        print(f"Response (first 600): {r.text[:600]}")
    except Exception as e:
        print(f"Connection Error: {type(e).__name__}: {e}")
