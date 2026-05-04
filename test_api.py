#!/usr/bin/env python3
"""Test MalwareBazaar API connectivity and response."""

import httpx

MB_API_V1 = "https://mb-api.abuse.ch/api/v1/"
USER_AGENT = "RansomwareDetector/2.5 (research)"

def test_api():
    """Test API with a simple tag query."""
    print("Testing MalwareBazaar API...")
    print(f"  API URL: {MB_API_V1}")
    
    with httpx.Client(
        headers={"User-Agent": USER_AGENT},
        timeout=httpx.Timeout(30.0, connect=10.0),
    ) as client:
        # Test query with lockbit tag
        print("\n[1] Query tag 'lockbit'...")
        try:
            r = client.post(MB_API_V1, data={"query": "get_taginfo", "tag": "lockbit", "limit": 10})
            print(f"  Status: {r.status_code}")
            print(f"  Content-Type: {r.headers.get('content-type')}")
            
            data = r.json()
            print(f"  query_status: {data.get('query_status')}")
            
            if data.get("query_status") == "ok" and data.get("data"):
                samples = data["data"]
                print(f"  Found {len(samples)} samples")
                if samples:
                    print(f"  First sample: {samples[0].get('sha256_hash', 'N/A')[:16]}...")
                    print(f"  File type: {samples[0].get('file_type', 'N/A')}")
                    print(f"  Signature: {samples[0].get('signature', 'N/A')}")
            else:
                print(f"  No data returned")
                print(f"  Response: {data}")
        except Exception as e:
            print(f"  Error: {e}")
        
        # Test query with filetype
        print("\n[2] Query filetype 'exe'...")
        try:
            r = client.post(MB_API_V1, data={"query": "get_filetype", "file_type": "exe", "limit": 5})
            data = r.json()
            print(f"  Status: {r.status_code}")
            print(f"  query_status: {data.get('query_status')}")
            if data.get("data"):
                print(f"  Found {len(data['data'])} samples")
        except Exception as e:
            print(f"  Error: {e}")
    
    print("\n" + "="*50)
    print("API test complete")

if __name__ == "__main__":
    test_api()
