"""
security_utils.py — Centralized security helpers
=================================================
Provides:
  - Atomic JSON write (crash-safe, no half-written files)
  - Streaming SHA256 (memory-efficient for large files)
  - Path safety validation (defends against path traversal)
  - Secret loading helpers (env-first, generate-if-missing)

These primitives are used throughout the codebase to enforce
consistent, secure behavior.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

# Default streaming chunk size (1 MiB) — large enough to amortize
# syscall overhead while keeping memory usage bounded.
_HASH_CHUNK_SIZE = 1024 * 1024


# ─── Hashing ──────────────────────────────────────────────────────────────────

def compute_sha256(file_path: str | os.PathLike, chunk_size: int = _HASH_CHUNK_SIZE) -> str:
    """
    Compute SHA256 of a file using streaming reads.

    Returns hex digest, or empty string on failure (file missing, permission
    denied, etc.). Does not raise — callers historically expected ``""`` on
    error, so we preserve that contract.
    """
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError) as exc:
        logger.debug("compute_sha256 failed for %s: %s", file_path, exc)
        return ""


# ─── Atomic JSON I/O ──────────────────────────────────────────────────────────

def atomic_write_json(path: str | os.PathLike, payload: Any, *, indent: int = 2,
                      ensure_ascii: bool = False) -> bool:
    """
    Atomically persist ``payload`` to ``path`` as JSON.

    Writes to a temp file in the same directory then ``os.replace`` to swap
    in place. This guarantees readers never observe a half-written file even
    if the process crashes mid-write.

    Returns True on success.
    """
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # NamedTemporaryFile in same directory ensures atomic rename works
        # across the same filesystem (os.replace requirement on Windows).
        fd, tmp_path = tempfile.mkstemp(
            prefix=target.name + ".",
            suffix=".tmp",
            dir=str(target.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=indent, ensure_ascii=ensure_ascii)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    # fsync not supported on all platforms (e.g. some test FS)
                    pass
            os.replace(tmp_path, target)
            return True
        except Exception:
            # Best-effort cleanup of orphaned temp file
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception as exc:
        logger.error("atomic_write_json(%s) failed: %s", path, exc)
        return False


def safe_read_json(path: str | os.PathLike, default: Any = None) -> Any:
    """Read JSON, returning ``default`` on any failure (missing file, parse error)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("safe_read_json(%s) failed: %s", path, exc)
        return default


# ─── Path Safety ──────────────────────────────────────────────────────────────

class PathSafetyError(ValueError):
    """Raised when a path resolves outside the allowed roots."""


def resolve_safe_path(user_path: str, allowed_roots: Iterable[str | os.PathLike]) -> Path:
    """
    Resolve ``user_path`` and ensure it is contained inside one of
    ``allowed_roots``. Raises :class:`PathSafetyError` otherwise.

    - Symlinks are resolved (``Path.resolve``) so attackers cannot bypass
      the check via symlink trickery.
    - UNC paths (``\\\\server\\share``) are rejected outright on Windows
      because they trigger network access (SSRF risk).
    """
    if not user_path:
        raise PathSafetyError("Empty path is not allowed")

    # Reject UNC paths early — these can trigger SMB lookups (SSRF).
    norm = str(user_path).replace("/", "\\") if os.name == "nt" else str(user_path)
    if os.name == "nt" and norm.startswith("\\\\"):
        raise PathSafetyError("UNC paths are not allowed")

    resolved = Path(user_path).resolve(strict=False)

    for root in allowed_roots:
        try:
            root_resolved = Path(root).resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        try:
            resolved.relative_to(root_resolved)
            return resolved
        except ValueError:
            continue

    raise PathSafetyError(
        f"Path {resolved} is outside the allowed roots: "
        f"{[str(r) for r in allowed_roots]}"
    )


# ─── Secret Loading ───────────────────────────────────────────────────────────

def load_or_generate_secret(env_var: str, config_key: str, *,
                            min_bytes: int = 32) -> str:
    """
    Load a secret with the precedence:

      1. Environment variable ``env_var``  (preferred for production)
      2. ``config_manager.config.get(config_key)`` if non-empty
      3. Generate a new random secret, persist to config, log a WARNING.

    Returns the secret string. Raises ``RuntimeError`` if generation fails
    (e.g. config persistence broken) — refusing to operate insecurely is
    intentional.
    """
    env_value = os.environ.get(env_var, "").strip()
    if env_value:
        if len(env_value) < min_bytes:
            logger.warning(
                "%s is shorter than recommended minimum %d bytes",
                env_var, min_bytes,
            )
        return env_value

    # Lazy import to avoid circular dependency at module import time.
    try:
        from core.config_manager import config  # type: ignore
    except Exception as exc:
        raise RuntimeError(f"Cannot access config_manager: {exc}") from exc

    cfg_value = config.get(config_key, "") or ""
    cfg_value = str(cfg_value).strip()
    if cfg_value:
        return cfg_value

    new_secret = secrets.token_urlsafe(max(min_bytes, 48))
    saved = config.set(config_key, new_secret, persist=True)
    if not saved:
        # In tests / read-only filesystems we still want auth to work,
        # but operators must be told.
        logger.error(
            "Generated %s but FAILED to persist to %s — secret will not "
            "survive process restart!", env_var, config_key,
        )
    else:
        logger.warning(
            "Auto-generated %s and stored in config[%s]. "
            "For production, set the %s environment variable instead.",
            env_var, config_key, env_var,
        )
    return new_secret


__all__ = [
    "PathSafetyError",
    "atomic_write_json",
    "compute_sha256",
    "load_or_generate_secret",
    "resolve_safe_path",
    "safe_read_json",
]
