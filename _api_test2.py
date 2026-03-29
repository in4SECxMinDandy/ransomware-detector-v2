import httpx

# Test connectivity & headers
tests = [
    {
        "name": "MalwareBazaar",
        "method": "POST",
        "url": "https://bazaar.abuse.ch/api/",
        "json": {"query": "get_info", "hash": "131f95c51cc819465fa1797f6cc461f85c4cfd8fee1b16b9c3a2995e5c4c3d9a"},
        "headers": {"Content-Type": "application/json", "User-Agent": "RansomwareDetector/2.5"},
    },
    {
        "name": "ThreatFox",
        "method": "POST",
        "url": "https://threatfox.abuse.ch/api/",
        "json": {"query": "search_ioc", "hash": "131f95c51cc819465fa1797f6cc461f85c4cfd8fee1b16b9c3a2995e5c4c3d9a"},
        "headers": {"Content-Type": "application/json", "User-Agent": "RansomwareDetector/2.5", "API-KEY": "f2a488ca94a8faf695ee9398352e10747c5ffd7eb774df83"},
    },
    {
        "name": "AlienVault OTX (v1)",
        "method": "GET",
        "url": "https://otx.alienvault.com/api/v1/indicators/file/sha256/131f95c51cc819465fa1797f6cc461f85c4cfd8fee1b16b9c3a2995e5c4c3d9a",
        "headers": {"User-Agent": "RansomwareDetector/2.5", "X-OTX-API-KEY": "fb1afdc5636105f1dcb6fdb39fe225867cf78d766ea126d586c5e9641d006f4a"},
    },
    {
        "name": "AlienVault OTX (v3 - latest)",
        "method": "GET",
        "url": "https://otx.alienvault.com/api/v3/indicators/file/sha256/131f95c51cc819465fa1797f6cc461f85c4cfd8fee1b16b9c3a2995e5c4c3d9a",
        "headers": {"User-Agent": "RansomwareDetector/2.5", "X-OTX-API-KEY": "fb1afdc5636105f1dcb6fdb39fe225867cf78d766ea126d586c5e9641d006f4a"},
    },
]

for t in tests:
    print(f"\n=== {t['name']} ===")
    try:
        if t["method"] == "POST":
            r = httpx.post(t["url"], json=t["json"], headers=t["headers"], timeout=15)
        else:
            r = httpx.get(t["url"], headers=t.get("headers"), timeout=15)
        print(f"Status: {r.status_code}")
        print(f"Is JSON?: {r.headers.get('content-type', '').startswith('application/json')}")
        print(f"First 400: {r.text[:400]}")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")

# Also test basic internet connectivity
print("\n=== Basic connectivity ===")
try:
    r = httpx.get("https://httpbin.org/get", timeout=5)
    print(f"httpbin.org: {r.status_code} - OK")
except Exception as e:
    print(f"httpbin.org: FAILED - {e}")

try:
    r = httpx.get("https://www.google.com", timeout=5)
    print(f"google.com: {r.status_code} - OK")
except Exception as e:
    print(f"google.com: FAILED - {e}")
