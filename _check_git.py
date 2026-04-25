"""Temporary verification script — checks whether malware/quarantine files are tracked in git."""
import subprocess
from pathlib import Path

repo = Path(__file__).parent
out = repo / "_check_git_result.txt"

lines = []
r = subprocess.run(["git", "ls-files"], capture_output=True, text=True, cwd=repo)
all_tracked = r.stdout.splitlines()
lines.append(f"Total tracked files: {len(all_tracked)}")
matches = [f for f in all_tracked if "ransomeware" in f.lower() or "quarantine" in f.lower()]
lines.append(f"Matching ransomeware/quarantine: {len(matches)}")
for m in matches:
    lines.append(f"  TRACKED: {m}")

# Check ignore status
for p in [
    "ransomeware/5677dfad26045e271272bc98be2fd24e2f6d13737850ab1d9857fd58de05e9f9.elf",
    "quarantine/quarantine_manifest.json",
    "quarantine/20260402_104016/ngrok.exe.quarantined",
]:
    r2 = subprocess.run(["git", "check-ignore", "-v", p], capture_output=True, text=True, cwd=repo)
    lines.append(f"check-ignore {p}: rc={r2.returncode} out={r2.stdout.strip()!r}")

# Check history (was it ever committed?)
r3 = subprocess.run(
    ["git", "log", "--all", "--diff-filter=A", "--name-only", "--pretty=format:COMMIT %H"],
    capture_output=True, text=True, cwd=repo
)
hist_matches = [l for l in r3.stdout.splitlines() if "ransomeware" in l.lower() or "quarantine" in l.lower()]
lines.append(f"\nFiles ever added in history matching: {len(hist_matches)}")
for m in hist_matches[:20]:
    lines.append(f"  HIST: {m}")

out.write_text("\n".join(lines), encoding="utf-8")
print(f"Wrote {out}")
