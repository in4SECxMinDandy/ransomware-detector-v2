#!/usr/bin/env python3
"""Test API key is loaded correctly."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from scripts.download_malwarebazaar import _get_mb_api_key

api_key = _get_mb_api_key()
print(f"API Key loaded: {'Yes' if api_key else 'No'}")
if api_key:
    print(f"API Key (first 10 chars): {api_key[:10]}...")
else:
    print("API Key is empty!")
