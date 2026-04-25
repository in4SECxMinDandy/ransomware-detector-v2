"""Helper to run pytest and write the result to disk where Cascade can read it."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
out_file = ROOT / "_pytest_out.txt"

# Allow targeting specific test files via CLI
args = sys.argv[1:] or ["tests/"]
cmd = [sys.executable, "-m", "pytest", *args, "-x", "-q", "--no-header"]

proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
out_file.write_text(
    f"$ {' '.join(cmd)}\nEXITCODE={proc.returncode}\n=== STDOUT ===\n{proc.stdout}\n=== STDERR ===\n{proc.stderr}",
    encoding="utf-8",
)
print(f"Wrote {out_file}")
print(proc.stdout[-2000:])
print(proc.stderr[-1000:])
sys.exit(proc.returncode)
