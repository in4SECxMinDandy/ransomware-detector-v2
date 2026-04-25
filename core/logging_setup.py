"""
core.logging_setup
==================
Centralised logging configuration with optional structured JSON output
(audit P3 — DevOps & Observability).

Why
---
Plain-text logs are fine for local development but they make SIEM ingestion
(Elastic, Splunk, Loki) painful: every parser needs custom regex per line
format.  Setting ``RANSOMWARE_LOG_FORMAT=json`` switches the root handler to
emit one JSON object per line with fixed keys, keeping all existing
``logging.getLogger(__name__)`` calls unchanged.

Usage
-----
At application startup (``main.py``, ``api/main.py``, ``train_model.py``)::

    from core.logging_setup import configure_logging
    configure_logging()

Environment variables
---------------------
``RANSOMWARE_LOG_LEVEL``   — DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO).
``RANSOMWARE_LOG_FORMAT``  — ``json`` or ``text`` (default: text).
``RANSOMWARE_LOG_FILE``    — optional path; when set, logs are also written
                              to that file with rotation.

Notes
-----
Implemented purely with the stdlib so we do not pull in another runtime
dependency. ``structlog`` would be a richer alternative but adds 1.5 MiB to
the install footprint for a feature most users will never enable.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict


_RESERVED_LOG_RECORD_ATTRS = {
    # Standard LogRecord attributes we do NOT want to repeat in the "extra" map.
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime", "taskName",
}


class JsonFormatter(logging.Formatter):
    """Render a :class:`logging.LogRecord` as a single JSON line.

    Keys are stable across versions so log pipelines can rely on them:

    ``ts``        ISO-8601 UTC timestamp.
    ``level``     Upper-case level name.
    ``logger``    Dotted logger name (``core.scanner``, ``api.auth``, ...).
    ``msg``       Fully-formatted message string.
    ``module``    Source module (Python file, no extension).
    ``func``      Function name where the log call was emitted.
    ``line``      Source line number.
    ``thread``    OS thread name.
    ``exc``       Stack trace string when ``exc_info`` was passed (else absent).
    ``extra``     Any user-supplied ``logger.info(..., extra={...})`` keys.
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload: Dict[str, Any] = {
            "ts":     datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level":  record.levelname,
            "logger": record.name,
            "msg":    record.getMessage(),
            "module": record.module,
            "func":   record.funcName,
            "line":   record.lineno,
            "thread": record.threadName,
        }

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        # Pass-through any user-supplied ``extra={"key": "value"}`` fields.
        extras = {
            k: _coerce_jsonable(v)
            for k, v in record.__dict__.items()
            if k not in _RESERVED_LOG_RECORD_ATTRS and not k.startswith("_")
        }
        if extras:
            payload["extra"] = extras

        return json.dumps(payload, ensure_ascii=False, default=str)


def _coerce_jsonable(value: Any) -> Any:
    """Best-effort conversion so ``json.dumps`` never raises mid-log."""
    try:
        json.dumps(value)
        return value
    except TypeError:
        return repr(value)


def _resolve_level(name: str) -> int:
    name = (name or "").strip().upper()
    return getattr(logging, name, logging.INFO) if name else logging.INFO


def configure_logging(
    *,
    force: bool = False,
    level: str | None = None,
    fmt: str | None = None,
    log_file: str | None = None,
) -> None:
    """Configure the root logger once for the whole process.

    Parameters
    ----------
    force
        If True, replace any existing handlers. Otherwise return early when
        the root logger already has handlers (so importing this module
        twice from tests does not duplicate output).
    level / fmt / log_file
        Override the ENV defaults. Mostly useful for tests.
    """

    root = logging.getLogger()
    if root.handlers and not force:
        return
    if force:
        for h in list(root.handlers):
            root.removeHandler(h)

    log_level = _resolve_level(level or os.environ.get("RANSOMWARE_LOG_LEVEL", "INFO"))
    log_format = (fmt or os.environ.get("RANSOMWARE_LOG_FORMAT", "text")).lower()
    log_path   = log_file or os.environ.get("RANSOMWARE_LOG_FILE", "")

    if log_format == "json":
        formatter: logging.Formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    stream = logging.StreamHandler(stream=sys.stderr)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    if log_path:
        os.makedirs(os.path.dirname(os.path.abspath(log_path)) or ".", exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,  # 10 MiB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    root.setLevel(log_level)

    # Quiet down chatty third-party libraries unless the user asked for DEBUG.
    if log_level > logging.DEBUG:
        for noisy in ("urllib3", "httpx", "httpcore", "matplotlib", "PIL"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


__all__ = ["configure_logging", "JsonFormatter"]
