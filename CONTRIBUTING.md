# Contributing to Ransomware Detector v2

Thank you for considering a contribution. This project is a
**defensive security tool** with privileged capabilities, so quality
gates here are deliberately strict.

## Reporting security vulnerabilities

**Do not open a public GitHub issue for security reports.** Follow the
private disclosure flow described in [`SECURITY.md`](./SECURITY.md).

## Local setup

```cmd
git clone https://github.com/in4SECxMinDandy/ransomware-detector-v2.git
cd ransomware-detector-v2

python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
pip install -r requirements-dev.txt
```

The first run of `pytest` will need `RANSOMWARE_JWT_SECRET` set to
any non-empty value — `tests/conftest.py` injects a deterministic
test secret automatically, but the API will refuse to start if you
launch it manually without one.

## Quality gates

All of the following must pass locally before opening a PR:

```cmd
ruff check core api tests scripts gui main.py train_model.py
pyright
pytest tests --cov=core --cov=api --cov-fail-under=45
```

> **Coverage ratchet**: the floor is currently `45%` (actual ~47%).
> The long-term target is `60%`. When you add tests that push
> coverage up, raise the `--cov-fail-under` value in
> `.github/workflows/ci.yml` to lock in the gain. The largest under-
> tested modules are listed in that workflow file and in
> `audit-report-v2.md`.

Or use the bundled workflow shortcuts:

- `/lint` — `ruff` + `pyright`
- `/test` — `pytest` with coverage
- `/full-check` — pre-commit pipeline

CI (`.github/workflows/ci.yml`) runs the same commands across
Python 3.10 / 3.11 / 3.12 on Windows. **Do not weaken or skip tests**
to make CI green — adjust the implementation instead.

## Type-safety policy

`pyright` is enforced at **0 errors / 0 warnings**. When integrating
optional native dependencies, follow the established
`if TYPE_CHECKING:` shim pattern (see `core/yara_engine.py`,
`core/notifications.py`, `core/forensic_exporter.py` for examples)
rather than disabling the rule globally.

## Commit style

- Use [Conventional Commits](https://www.conventionalcommits.org/)
  prefixes when practical: `feat:`, `fix:`, `chore:`, `docs:`,
  `refactor:`, `test:`, `ci:`, `perf:`, `security:`.
- Keep commits scoped — a single bug fix or refactor per commit.
- Reference the audit row (e.g. `audit-report-v2.md` table row #4)
  in the body when fixing a previously catalogued issue.

## What not to commit

- **Never** commit live malware, packed binaries, EICAR-derived
  artefacts, or anything from `quarantine/`. `.gitignore` already
  excludes those paths; do not override with `git add -f`.
- **Never** commit API keys. Use environment variables and document
  them in `data/config.json.template`.
- **Never** commit `data/config.json`, `data/vt_cache.json`,
  `data/ti_cache.json`, or anything under `logs/`.

## Adding new detection engines

Detection modules live in `core/` and are registered into the
multi-stage pipeline inside `core/scanner.py`. New engines should:

1. Expose a single public callable returning a structured result
   (dataclass, not a free-form `dict`).
2. Be safe to call without the optional native dependency they rely
   on; fall back to a stub or no-op implementation.
3. Ship with a dedicated test file under `tests/` that exercises both
   the happy path and at least one failure mode (timeout, missing
   dependency, malformed input).
4. Document the false-positive / false-negative posture in the
   module docstring.

## Adding new tests

- Place tests under `tests/` so pytest auto-discovers them. Files
  outside that directory will not run in CI.
- Prefer `pytest` fixtures (`tests/conftest.py`) over hand-rolled
  setup/teardown.
- Use `mock_engine` rather than loading the real model whenever the
  test does not specifically exercise the ML pipeline.
- Cover edge cases: zero-byte files, files >2 GiB, unicode/long
  paths on Windows, symlink loops, and cancellation.

## Pull-request checklist

- [ ] Lint, type-check, and tests all pass locally.
- [ ] New behaviour is covered by tests (or you have explained why
  it is unreachable from a test harness).
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`.
- [ ] No malware, no API keys, no `.log` files in the diff.
- [ ] If touching auth, quarantine, or firewall code, the PR
  description explains the threat model considered.
