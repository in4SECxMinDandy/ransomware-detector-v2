"""
test_watchdog_handler.py
========================
Audit P2-12 regression tests for ``core.watchdog_monitor._EventHandler``.

We do NOT spin up a real ``Observer`` — that would race against tmpfs
flushes on Windows and is the wrong layer to test. Instead we feed
synthetic ``FileSystemEvent``-shaped dummies into the handler and check
the queue + debounce + ignore-root semantics.
"""

import queue
import time

import pytest

from core import watchdog_monitor as wm


class _DummyEvent:
    """Mimics the shape of a watchdog ``FileSystemEvent``."""

    def __init__(self, src_path: str, is_directory: bool = False):
        self.src_path = src_path
        self.is_directory = is_directory
        # Newer watchdog versions expose dest_path/event_type — provide stubs.
        self.dest_path = ""
        self.event_type = "modified"


@pytest.fixture
def handler_factory(tmp_path):
    """Return ``(handler, q, file_path)`` ready for tests."""
    def _make(ignored_roots=None, file_size: int = 4096):
        q: "queue.Queue" = queue.Queue(maxsize=10)
        debounce: dict = {}
        h = wm._EventHandler(
            file_queue=q,
            debounce_cache=debounce,
            ignored_roots=ignored_roots or [],
        )

        target = tmp_path / "victim.bin"
        target.write_bytes(b"x" * file_size)
        return h, q, str(target)

    return _make


class TestEventDispatch:
    def test_created_event_enqueued(self, handler_factory):
        h, q, path = handler_factory()
        h.on_created(_DummyEvent(path))
        assert q.qsize() == 1
        kind, p = q.get_nowait()
        assert kind == "created"
        assert p == path

    def test_modified_event_enqueued(self, handler_factory):
        h, q, path = handler_factory()
        h.on_modified(_DummyEvent(path))
        kind, _ = q.get_nowait()
        assert kind == "modified"

    def test_directory_events_ignored(self, handler_factory):
        h, q, path = handler_factory()
        h.on_created(_DummyEvent(path, is_directory=True))
        h.on_modified(_DummyEvent(path, is_directory=True))
        assert q.empty()


class TestDebounce:
    def test_second_event_within_debounce_dropped(self, handler_factory):
        h, q, path = handler_factory()
        h.on_modified(_DummyEvent(path))
        h.on_modified(_DummyEvent(path))  # same file, immediate
        assert q.qsize() == 1, "debounce should suppress the second event"

    def test_event_after_debounce_window_processed(self, handler_factory, monkeypatch):
        """Audit: respect ``DEBOUNCE_SECONDS`` cooldown.

        We monkeypatch the constant down to a tiny value so the test runs
        quickly without a real 2-second sleep.
        """
        monkeypatch.setattr(wm, "DEBOUNCE_SECONDS", 0.05)
        h, q, path = handler_factory()
        h.on_modified(_DummyEvent(path))
        time.sleep(0.06)
        h.on_modified(_DummyEvent(path))
        assert q.qsize() == 2


class TestFilters:
    def test_ignored_root_skipped(self, handler_factory, tmp_path):
        ignored = str(tmp_path)  # parent of the test file ⇒ everything in it skipped
        h, q, path = handler_factory(ignored_roots=[ignored])
        h.on_created(_DummyEvent(path))
        assert q.empty(), "events under an ignored root must be dropped"

    def test_skip_extension_filtered(self, handler_factory, tmp_path):
        h, q, _ = handler_factory()
        skipped = tmp_path / "boot.sys"
        skipped.write_bytes(b"x" * 4096)
        h.on_created(_DummyEvent(str(skipped)))
        # ``.sys`` is in core.scanner.SKIP_EXTENSIONS; must be filtered.
        assert q.empty()

    def test_too_small_file_filtered(self, handler_factory, tmp_path):
        h, q, _ = handler_factory()
        tiny = tmp_path / "blank.txt"
        tiny.write_bytes(b"")  # 0 bytes < MIN_FILE_SIZE
        h.on_created(_DummyEvent(str(tiny)))
        assert q.empty()

    def test_nonexistent_path_filtered(self, handler_factory):
        h, q, _ = handler_factory()
        h.on_created(_DummyEvent(r"C:\definitely\not\there.bin"))
        assert q.empty()


class TestThreatEventDataclass:
    def test_to_dict_round_trip(self):
        from core.scanner import ScanResult
        # ScanResult only takes a path positionally; everything else is
        # populated post-construction.
        result = ScanResult("C:/tmp/x.bin")
        result.probability = 0.8765
        result.risk_level  = "HIGH"
        result.entropy     = 7.5432

        ev = wm.ThreatEvent(result, "modified")
        d = ev.to_dict()
        assert d["filename"] == "x.bin"
        assert d["risk_level"] == "HIGH"
        assert d["probability"] == 0.8765
        assert d["entropy"] == 7.5432
        assert "timestamp" in d
