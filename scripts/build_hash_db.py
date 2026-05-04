#!/usr/bin/env python3
"""Build malware hash database from CSV without downloading files."""

import csv
import json
import os

def build_db(csv_path: str, output_dir: str = "datasets/hash_db"):
    os.makedirs(output_dir, exist_ok=True)
    db = {}
    ransomware = set()
    
    ransom_kw = ["ransom","lockbit","blackcat","conti","revil","ryuk","wannacry","dharma","phobos","stop","makop","maze","clop","darkside","akira","blackbasta","hive","royal","medusa","play","alphv"]
    
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        header = None
        for line in f:
            if line.startswith('#') and 'first_seen_utc' in line:
                header = [h.strip().strip('"') for h in line.lstrip('#').strip().split(',')]
                break
        
        reader = csv.DictReader(f, fieldnames=header, skipinitialspace=True)
        
        for row in reader:
            sha = (row.get("sha256_hash") or "").replace('"','').replace("'",'').strip().lower()
            ftype = (row.get("file_type_guess") or "").strip().lower().replace('"','')
            mime = (row.get("mime_type") or "").strip().lower()
            sig = (row.get("signature") or "").strip().replace('"','')
            
            if len(sha) != 64:
                continue
            is_pe = ftype in ("exe","dll","sys","msi") or "x-dosexec" in mime
            is_mal = sig and sig.lower() not in ("n/a","unknown","")
            
            if is_pe and is_mal:
                db[sha] = {"family": sig, "type": ftype}
                if any(k in sig.lower() for k in ransom_kw):
                    ransomware.add(sha)
            
            if len(db) >= 50000:
                break
    
    with open(os.path.join(output_dir,"malware_db.json"), "w") as f:
        json.dump(db, f, indent=2)
    
    with open(os.path.join(output_dir,"ransomware_hashes.txt"), "w") as f:
        f.write("\n".join(ransomware))
    
    print(f"[HashDB] Total: {len(db)} PE malware")
    print(f"[HashDB] Ransomware: {len(ransomware)}")
    print(f"[HashDB] Saved to: {output_dir}")

if __name__ == "__main__":
    import sys
    csv_file = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\haqua\Documents\GitHub\ransomware-detector-v2\full.csv\full.csv"
    build_db(csv_file)
