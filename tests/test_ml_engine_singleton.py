"""Regression test for the get_engine() Phase 1 fix.

The previous implementation returned an unloaded engine which silently
classified every input as SAFE. This test asserts the singleton now
auto-loads (or at least *attempts* to load) and is thread-safe.
"""

from __future__ import annotations

import threading

import numpy as np


def test_get_engine_loads_or_attempts_to_load(monkeypatch):
    from core import ml_engine

    ml_engine.reset_engine()

    called = {"n": 0}

    real_load = ml_engine.CalibratedMalwareDetector.load_model

    def spy_load(self, *args, **kwargs):
        called["n"] += 1
        return real_load(self, *args, **kwargs)

    monkeypatch.setattr(ml_engine.CalibratedMalwareDetector, "load_model", spy_load)

    engine = ml_engine.get_engine()
    assert engine is not None
    assert called["n"] == 1, "get_engine() must call load_model exactly once"


def test_get_engine_thread_safe(monkeypatch):
    """Concurrent first calls must produce a single instance, not race."""
    from core import ml_engine

    ml_engine.reset_engine()

    instances: list = []

    def grab():
        instances.append(ml_engine.get_engine())

    threads = [threading.Thread(target=grab) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(instances) == 8
    assert all(x is instances[0] for x in instances), "singleton broken"


def test_predict_returns_safe_when_model_absent(monkeypatch, tmp_path):
    """If no model exists, predict() must return (0, 0.0) rather than crash."""
    from core import ml_engine

    monkeypatch.setattr(ml_engine, "MODEL_PATH", str(tmp_path / "nope.joblib"))
    ml_engine.reset_engine()

    engine = ml_engine.get_engine(auto_load=False)
    label, proba = engine.predict(np.zeros(16, dtype=np.float32))
    assert label == 0
    assert proba == 0.0
