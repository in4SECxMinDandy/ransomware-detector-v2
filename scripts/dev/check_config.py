"""Quick sanity check for ``data/config.json``.

Verifies the file exists and parses as valid JSON. Intended as a
sub-second smoke check before launching the GUI / API.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    config_path = repo_root / "data" / "config.json"

    print(f"Path  : {config_path}")
    print(f"Exists: {config_path.exists()}")

    if not config_path.exists():
        return 1

    print(f"Size  : {os.path.getsize(config_path)} bytes")
    try:
        with config_path.open("r", encoding="utf-8") as f:
            json.load(f)
    except Exception as e:  # noqa: BLE001
        print(f"Valid JSON: False ({type(e).__name__}: {e})")
        return 2

    print("Valid JSON: True")
    return 0


if __name__ == "__main__":
    sys.exit(main())
