"""
logger_setup.py
===============
Centralized, structured logging for Ransomware Detector.

Replaces all ad-hoc `print()` statements across the codebase.
Provides:
  - Console handler (WARNING+)
  - File handler with rotation (DEBUG+, 5MB × 3 backups)
  - Per-module loggers (``get_logger``)
  - Color-coded console output (when attached to a TTY)
  - JSON SIEM output when ``RANSOMWARE_LOG_FORMAT=json`` (via ``JsonFormatter``
    and ``configure_logging`` from the companion ``logging_setup`` module which
    this module fully absorbs for a single import surface).

Unified API — callers can import everything from *either* module:
    from core.logger_setup import get_logger, setup_logging
    from core.logger_setup import configure_logging, JsonFormatter  # SIEM helpers

Usage:
    from core.logger_setup import get_logger

    logger = get_logger("scanner")
    logger.info("Scan started")
    logger.warning("File skipped: %s", file_path)
    logger.error("Detection failed: %s", error)
"""

import os
import sys
import logging
import traceback
from logging.handlers import RotatingFileHandler


# ─── Directory ────────────────────────────────────────────────────────────────

_LOG_DIR  = "logs"
_LOG_FILE = os.path.join(_LOG_DIR, "detector.log")
_MAX_BYTES  = 5 * 1024 * 1024   # 5 MB
_BACKUP_COUNT = 3


# ─── Formatters ──────────────────────────────────────────────────────────────

_FILE_FORMAT  = "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_COLOR_RESET  = "\x1b[0m"
_COLOR_DEBUG  = "\x1b[38;5;245m"   # Gray
_COLOR_INFO   = "\x1b[38;5;75m"    # Blue
_COLOR_SUCCESS= "\x1b[38;5;82m"    # Green
_COLOR_WARNING= "\x1b[38;5;214m"   # Orange
_COLOR_ERROR  = "\x1b[38;5;196m"   # Red
_COLOR_CRITICAL= "\x1b[38;5;196m"  # Red + bold
_COLOR_FP     = "\x1b[38;5;183m"   # Purple


class _ColorFormatter(logging.Formatter):
    """Adds ANSI color codes to console log records."""

    COLORS = {
        logging.DEBUG:    _COLOR_DEBUG,
        logging.INFO:     _COLOR_INFO,
        logging.WARNING: _COLOR_WARNING,
        logging.ERROR:   _COLOR_ERROR,
        logging.CRITICAL: _COLOR_CRITICAL,
    }

    def __init__(self, fmt: str, datefmt: str):
        super().__init__(fmt, datefmt)

    def format(self, record: logging.LogRecord) -> str:
        if not sys.stdout.isatty():
            return super().format(record)
        color = self.COLORS.get(record.levelno, _COLOR_RESET)
        record.levelname = f"{color}{record.levelname}{_COLOR_RESET}"
        record.name      = f"\x1b[38;5;183m{record.name}\x1b[0m"  # module in purple
        return super().format(record)


# ─── Logger Registry ─────────────────────────────────────────────────────────

_initialized = False
_registry: dict[str, logging.Logger] = {}


def setup_logging(level: str = "INFO"):
    """
    One-time initialization of the root logger and handlers.
    Called automatically by get_logger(); safe to call multiple times.

    Audit P3: when ``RANSOMWARE_LOG_FORMAT=json`` is set in the environment
    both the console and rotating-file handlers emit one JSON object per
    record (see ``core.logging_setup.JsonFormatter``). This makes SIEM
    ingestion (Elastic / Splunk / Loki) trivial without replacing the
    existing colourful text format for interactive use.

    Env vars (when JSON mode is on the colour formatter is bypassed):
      - ``RANSOMWARE_LOG_LEVEL``  override default level
      - ``RANSOMWARE_LOG_FORMAT`` ``json`` | ``text`` (default: ``text``)
    """
    global _initialized
    if _initialized:
        return

    os.makedirs(_LOG_DIR, exist_ok=True)

    # Allow env var to override the function argument so deployments can
    # bump verbosity without touching code.
    env_level = os.environ.get("RANSOMWARE_LOG_LEVEL", "").strip().upper()
    effective_level_name = env_level or level.upper()

    # Root logger
    root = logging.getLogger()
    root.setLevel(getattr(logging, effective_level_name, logging.INFO))

    # Remove any pre-existing handlers
    for h in root.handlers[:]:
        root.removeHandler(h)

    use_json = os.environ.get("RANSOMWARE_LOG_FORMAT", "text").strip().lower() == "json"
    text_formatter = logging.Formatter(_FILE_FORMAT, _DATE_FORMAT)
    json_formatter: logging.Formatter | None = None
    if use_json:
        try:
            from core.logging_setup import JsonFormatter
            json_formatter = JsonFormatter()
        except Exception:
            # Fall back to text if anything goes wrong importing the
            # structured formatter — better than no logs at all.
            json_formatter = None
            use_json = False

    # File handler (DEBUG+)
    try:
        fh = RotatingFileHandler(
            _LOG_FILE,
            maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(json_formatter if use_json and json_formatter else text_formatter)
        root.addHandler(fh)
    except (IOError, OSError):
        pass  # File logging is non-critical

    # Console handler (WARNING+)
    try:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(logging.WARNING)
        if use_json and json_formatter:
            ch.setFormatter(json_formatter)
        else:
            ch.setFormatter(_ColorFormatter(_FILE_FORMAT, _DATE_FORMAT))
        root.addHandler(ch)
    except Exception:
        pass

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger for a module.

    All modules should use this instead of `logging.getLogger(__name__)` directly,
    to ensure the root logger is initialized before first use.
    """
    setup_logging()
    if name not in _registry:
        _registry[name] = logging.getLogger(name)
    return _registry[name]


# ─── Convenience: module-level logger shortcuts ───────────────────────────────

def info(msg: str, *args, **kwargs):
    get_logger("app").info(msg, *args, **kwargs)

def warning(msg: str, *args, **kwargs):
    get_logger("app").warning(msg, *args, **kwargs)

def error(msg: str, *args, **kwargs):
    get_logger("app").error(msg, *args, **kwargs)

def debug(msg: str, *args, **kwargs):
    get_logger("app").debug(msg, *args, **kwargs)

def critical(msg: str, *args, **kwargs):
    get_logger("app").critical(msg, *args, **kwargs)


# ─── Exception hook for uncaught exceptions ───────────────────────────────────

def install_excepthook():
    """Install a handler that logs uncaught exceptions before crashing."""
    def hook(type_, value, tb):
        logger = get_logger("uncaught")
        logger.critical("Uncaught exception:\n%s", "".join(traceback.format_exception(type_, value, tb)))
        sys.__excepthook__(type_, value, tb)

    sys.excepthook = hook


# ─── Unified surface: re-export SIEM helpers from logging_setup ──────────────
# This makes ``core.logger_setup`` the single import point for all logging
# needs. Callers that previously imported from ``core.logging_setup`` can
# switch to ``core.logger_setup`` without any behaviour change.

try:
    from core.logging_setup import JsonFormatter, configure_logging  # noqa: F401 (re-export)
except Exception:
    # Fallback stubs so the rest of the codebase never sees an ImportError
    # even if logging_setup has a dependency problem in certain environments.
    class JsonFormatter(logging.Formatter):  # type: ignore[no-redef]
        """Stub JSON formatter (logging_setup unavailable)."""

    def configure_logging(**kwargs) -> None:  # type: ignore[misc]
        """Stub configure_logging (logging_setup unavailable)."""
        setup_logging()


__all__ = [
    "get_logger",
    "setup_logging",
    "install_excepthook",
    "configure_logging",
    "JsonFormatter",
    "info",
    "warning",
    "error",
    "debug",
    "critical",
]
