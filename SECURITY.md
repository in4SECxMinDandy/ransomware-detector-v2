# Security Policy

## Overview

Ransomware Detector v2.0 is a defensive security tool. Because it ships
with privileged capabilities (file quarantine, process termination,
firewall manipulation, optional kernel-mode monitoring), vulnerabilities
in this project can be **escalated into full-system compromise** of any
host that runs it.

We take security reports seriously and aim to respond quickly.

## Supported Versions

| Branch / Tag | Status                |
| ------------ | --------------------- |
| `main`       | Actively patched      |
| `v2.0.x`     | Security fixes only   |
| `v1.x`       | **Unsupported** — please upgrade |

If you are on an unsupported branch, the maintainers may still acknowledge
your report but will not produce a backported fix.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, send a private report using **one** of the following channels:

- **GitHub Security Advisory** (preferred): use the
  [Security tab → "Report a vulnerability"](https://github.com/in4SECxMinDandy/ransomware-detector-v2/security/advisories/new)
  link. This creates a private advisory only the maintainers and you can
  read.
- **Email**: `security@<your-domain>` (replace with the project's real
  contact before publishing). Encrypt with the maintainer GPG key when
  available — fingerprint and key will be published in this file once
  available.

When reporting, please include:

1. A clear description of the vulnerability and the affected component
   (e.g. `core/auto_responder.py`, `api/routers/scan.py`).
2. Reproduction steps or a minimal proof of concept.
3. The version / commit hash you tested against.
4. Your assessment of impact (RCE, privilege escalation, data loss,
   sandbox escape, denial of service, etc.).
5. Any suggested mitigation, if you have one.

If your report concerns a **third-party dependency** of this project,
please CC the upstream maintainers as well — we will help coordinate
disclosure but cannot patch upstream code on their behalf.

## Response SLA

| Stage                                      | Target time |
| ------------------------------------------ | ----------- |
| Acknowledgement of receipt                 | 3 business days |
| Initial triage / severity assessment       | 7 business days |
| Fix or mitigation in `main`                | 30 days for High/Critical, best-effort otherwise |
| Coordinated public disclosure              | After fix is released, typically 90 days max |

We will keep you informed throughout the process and credit you in the
release notes unless you request otherwise.

## Scope

In scope:

- All code under `api/`, `core/`, `gui/`, `scripts/`, and the top-level
  CLI entry points (`main.py`, `train_model.py`).
- Bundled YARA rules and ML model artefacts (`models/`, `data/`).
- Default configuration in `data/config.json.template`.
- CI/CD pipelines under `.github/workflows/`.

Out of scope (please do not report):

- Vulnerabilities that require an attacker who already has full
  administrative access to the host (the tool is privileged by design).
- Findings on user-supplied configurations that explicitly disable
  security controls (e.g. `api.allowed_scan_roots = ["/"]`,
  `RANSOMWARE_REQUIRE_MODEL_INTEGRITY=0`, custom whitelist that includes
  the OS root).
- Reports of *detection efficacy* (false positives / false negatives) —
  these are handled as regular issues, not security advisories.

## Hardening Notes for Operators

If you deploy this tool, please review:

- **JWT secret**: set the `RANSOMWARE_JWT_SECRET` environment variable in
  production. The auto-generated fallback is intended for development
  only and emits a WARNING.
- **Model integrity**: pin the ML model hash via
  `RANSOMWARE_MODEL_SHA256` and set
  `RANSOMWARE_REQUIRE_MODEL_INTEGRITY=1` to refuse loading unverified
  model files.
- **Scan allowlist**: configure `api.allowed_scan_roots` so the API can
  only scan paths the operator has explicitly whitelisted.
- **CORS**: do not set `cors_origins = ["*"]` in production. Wildcards
  are rejected when `allow_credentials = true`.
- **VirusTotal upload opt-in**: VT *upload* is disabled by default. Hash
  lookups are safe; do not enable upload on networks where files may be
  confidential.
- **Auto-response policy**: review `RESPONSE_POLICY` in
  `core/auto_responder.py` before enabling `auto_quarantine` for HIGH
  severity events.

## Acknowledgements

We thank the security researchers who help keep this project safe. Past
contributors will be listed here (with their permission) once the
project receives its first external advisories.
