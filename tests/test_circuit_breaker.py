"""
test_circuit_breaker.py
=======================
Audit P4-10 regression tests for ``core.threat_intel_client.CircuitBreaker``.

Checks the closed/open/half-open state machine, cooldown timing, and the
half-open probe semantics (only one probe in flight).
"""

import time

from core.threat_intel_client import CircuitBreaker


class TestCircuitBreakerStates:
    def test_starts_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitBreaker.STATE_CLOSED
        assert cb.allow() is True

    def test_failures_below_threshold_stay_closed(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitBreaker.STATE_CLOSED
        assert cb.allow() is True

    def test_threshold_failures_open(self):
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitBreaker.STATE_OPEN
        # While OPEN we short-circuit subsequent calls.
        assert cb.allow() is False

    def test_success_in_closed_resets_failure_count(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        # Two more failures should NOT trip — count was reset.
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitBreaker.STATE_CLOSED


class TestCooldown:
    def test_open_breaker_unblocks_after_cooldown(self):
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.05)
        cb.record_failure()
        cb.record_failure()
        assert cb.allow() is False  # OPEN

        time.sleep(0.06)
        # After the cooldown the FIRST call moves us into HALF_OPEN.
        assert cb.allow() is True
        assert cb.state == CircuitBreaker.STATE_HALF_OPEN
        # Subsequent calls during HALF_OPEN are blocked until probe finishes.
        assert cb.allow() is False

    def test_half_open_success_closes_breaker(self):
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.05)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.06)
        cb.allow()  # → HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitBreaker.STATE_CLOSED
        assert cb.allow() is True

    def test_half_open_failure_reopens(self):
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.05)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.06)
        cb.allow()  # → HALF_OPEN
        cb.record_failure()
        # Re-opens immediately even though only ONE failure happened in
        # HALF_OPEN — that is the point of the half-open probe.
        assert cb.state == CircuitBreaker.STATE_OPEN
        assert cb.allow() is False


class TestEdgeCases:
    def test_threshold_floor_is_one(self):
        """failure_threshold=0 should be coerced to 1, not infinite-trust."""
        cb = CircuitBreaker(failure_threshold=0)
        cb.record_failure()
        assert cb.state == CircuitBreaker.STATE_OPEN

    def test_cooldown_floor(self):
        """``cooldown_seconds=0`` is coerced up to the 1 ms floor."""
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.0)
        assert cb.cooldown_seconds == 0.001
        cb.record_failure()
        # Even at the floor we must SHORT-CIRCUIT immediately (state OPEN
        # before cooldown elapses).
        assert cb.allow() is False
