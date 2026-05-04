#!/usr/bin/env python3
"""Prepare dataset using hash database without downloading malware."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

# Check hash database
db_path = "datasets/hash_db/malware_db.json"
if os.path.exists(db_path):
    with open(db_path) as f:
        db = json.load(f)
    print(f"[Dataset] Hash database loaded: {len(db)} malware families")
    
    # Show top families
    from collections import Counter
    families = Counter([info["family"] for info in db.values()])
    print("\n[Dataset] Top malware families:")
    for fam, count in families.most_common(10):
        print(f"  - {fam}: {count}")
    
    # Show ransomware
    ransom_path = "datasets/hash_db/ransomware_hashes.txt"
    if os.path.exists(ransom_path):
        with open(ransom_path) as f:
            ransom_count = len(f.read().strip().split('\n'))
        print(f"\n[Dataset] Ransomware samples: {ransom_count}")
else:
    print("[Dataset] Hash database not found. Run: python scripts/build_hash_db.py")

# Check local samples
local_path = "datasets/sources/safe/local_system"
if os.path.exists(local_path):
    files = [f for f in os.listdir(local_path) if os.path.isfile(os.path.join(local_path, f))]
    print(f"\n[Dataset] Local SAFE samples: {len(files)}")
else:
    print("\n[Dataset] No local SAFE samples. Run collect_local_samples.py")

print("\n" + "="*60)
print("RECOMMENDED NEXT STEPS:")
print("="*60)
print("""
1. COLLECT LOCAL SAFE SAMPLES:
   python scripts/collect_local_samples.py --output datasets/sources/safe/local_system --limit 500

2. USE EXISTING MODEL (pre-trained):
   python main.py --gui
   
3. OR USE SYNTHETIC DATA FOR QUICK TEST:
   python -c "from core.synthetic_data import create_synthetic_dataset; create_synthetic_dataset('datasets/sources/encrypted/synthetic', 1000)"
   python -c "from core.synthetic_data import create_safe_dataset; create_safe_dataset('datasets/sources/safe/synthetic', 1000)"

4. TRAIN MODEL:
   python train_model.py --encrypted-dir datasets/sources/encrypted --safe-dir datasets/sources/safe
""")
