"""Run pytest and capture stdout/stderr to a file.

Useful when invoked from a tool that cannot reliably read interactive
terminal output. Writes ``_pytest_out.txt`` at the repo root and
mirrors the last few KB to stdout for convenience.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    repo = Path(__file__).resolve().parents[2]
    out_file = repo / "_pytest_out.txt"

    test_targets = argv or ["tests/"]
    cmd = [sys.executable, "-m", "pytest", *test_targets, "-x", "-q", "--no-header"]

    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(repo))
    out_file.write_text(
        f"$ {' '.join(cmd)}\n"
        f"EXITCODE={proc.returncode}\n"
        f"=== STDOUT ===\n{proc.stdout}\n"
        f"=== STDERR ===\n{proc.stderr}",
        encoding="utf-8",
    )
    print(f"Wrote {out_file}")
    print(proc.stdout[-2000:])
    print(proc.stderr[-1000:])
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
