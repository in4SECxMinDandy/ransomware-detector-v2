"""
test_logging_setup.py
=====================
Audit P3 regression tests for ``core.logging_setup.JsonFormatter``.
"""

import io
import json
import logging

import pytest

from core.logging_setup import JsonFormatter, configure_logging


@pytest.fixture
def json_logger():
    """A fresh logger writing JSON lines to a StringIO sink."""
    sink = io.StringIO()
    handler = logging.StreamHandler(sink)
    handler.setFormatter(JsonFormatter())

    log = logging.getLogger("test.logging_setup")
    log.handlers.clear()
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    log.propagate = False
    yield log, sink
    log.removeHandler(handler)


class TestJsonFormatter:
    def test_basic_record_emits_valid_json(self, json_logger):
        log, sink = json_logger
        log.info("hello %s", "world")
        line = sink.getvalue().strip()
        payload = json.loads(line)
        assert payload["level"] == "INFO"
        assert payload["msg"] == "hello world"
        assert payload["logger"] == "test.logging_setup"
        # Keys we promised the SIEM:
        for key in ("ts", "level", "logger", "msg", "module", "func", "line", "thread"):
            assert key in payload, f"missing key: {key}"

    def test_extra_fields_pass_through(self, json_logger):
        log, sink = json_logger
        log.warning("uploading", extra={"path": "C:/x.bin", "bytes": 1024})
        payload = json.loads(sink.getvalue().strip())
        assert payload["extra"]["path"] == "C:/x.bin"
        assert payload["extra"]["bytes"] == 1024

    def test_exception_info_serialised(self, json_logger):
        log, sink = json_logger
        try:
            raise ValueError("boom")
        except ValueError:
            log.exception("caught it")
        payload = json.loads(sink.getvalue().strip())
        assert "exc" in payload
        assert "ValueError" in payload["exc"]
        assert "boom" in payload["exc"]

    def test_non_jsonable_extra_is_repr_fallback(self, json_logger):
        log, sink = json_logger

        class _Weird:
            def __repr__(self): return "<Weird>"

        log.info("x", extra={"thing": _Weird()})
        payload = json.loads(sink.getvalue().strip())
        assert payload["extra"]["thing"] == "<Weird>"


class TestConfigureLogging:
    def test_idempotent_when_handlers_present(self, monkeypatch):
        # Reset and add a fake handler.
        root = logging.getLogger()
        for h in list(root.handlers):
            root.removeHandler(h)
        sentinel = logging.NullHandler()
        root.addHandler(sentinel)

        # Without force=True, configure_logging must NOT replace handlers.
        configure_logging(force=False)
        assert sentinel in root.handlers

    def test_force_replaces_handlers(self):
        configure_logging(force=True, fmt="text")
        root = logging.getLogger()
        # At least one stream handler attached.
        assert any(isinstance(h, logging.StreamHandler) for h in root.handlers)
