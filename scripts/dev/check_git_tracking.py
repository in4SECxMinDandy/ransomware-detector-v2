"""Verify that malware / quarantine artefacts are not tracked in git.

Compliance check: this project must never commit live malware samples
or quarantined binaries. This script:

1. Lists all tracked files under ``ransomeware/`` or ``quarantine/``
   (working-tree state).
2. Calls ``git check-ignore`` on a representative set of paths to
   confirm they would be ignored if added.
3. Scans ``git log`` history for any prior addition of those paths.

Exit codes:
    0 — clean
    1 — tracked files found OR present in history
    2 — git not available
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

REPRESENTATIVE_PATHS = [
    "ransomeware/sample.elf",
    "quarantine/quarantine_manifest.json",
    "quarantine/sample.exe.quarantined",
]


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=REPO)


def main() -> int:
    if shutil.which("git") is None:
        print("git is not on PATH", file=sys.stderr)
        return 2

    rc = 0

    print("== tracked files matching ransomeware/quarantine ==")
    out = _run(["git", "ls-files"]).stdout.splitlines()
    matches = [f for f in out if "ransomeware" in f.lower() or "quarantine" in f.lower()]
    print(f"total tracked: {len(out)}, matching: {len(matches)}")
    for m in matches:
        print(f"  TRACKED: {m}")
        rc = 1

    print("\n== check-ignore (each should be ignored) ==")
    for p in REPRESENTATIVE_PATHS:
        r = _run(["git", "check-ignore", "-v", p])
        status = "IGNORED" if r.returncode == 0 else "NOT IGNORED"
        print(f"  {status}: {p} | rule={r.stdout.strip() or '<none>'}")
        if r.returncode != 0:
            rc = 1

    print("\n== history scan (files ever added) ==")
    r = _run(
        [
            "git", "log", "--all",
            "--diff-filter=A", "--name-only",
            "--pretty=format:COMMIT %H",
        ]
    )
    hist_matches = [
        line for line in r.stdout.splitlines()
        if "ransomeware" in line.lower() or "quarantine" in line.lower()
    ]
    print(f"matches in history: {len(hist_matches)}")
    for m in hist_matches[:25]:
        print(f"  HIST: {m}")
    if hist_matches:
        # Not necessarily fatal (history is hard to rewrite) but worth flagging.
        rc = max(rc, 1)

    return rc


if __name__ == "__main__":
    sys.exit(main())
