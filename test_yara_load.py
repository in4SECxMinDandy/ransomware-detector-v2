#!/usr/bin/env python
"""Test loading external YARA rules metadata."""
import sys
sys.path.insert(0, '.')

from core.yara_engine import get_yara_engine

engine = get_yara_engine()
print(f"Built-in rules: {engine.get_rules_count()}")

result = engine.load_external_rules_metadata('data/yara_rules.json')
print(f"External rules loaded: {result['loaded']}")
print(f"External rules count: {result['count']}")

if result['rules']:
    print("\nFirst 3 rules:")
    for rule in result['rules'][:3]:
        print(f"  - {rule['name']}: {rule['description'][:50]}... (Author: {rule['author']}, Samples: {rule['sample_count']})")
