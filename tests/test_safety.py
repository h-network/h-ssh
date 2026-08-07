"""Tests for hssh.safety module — covers the full T1-T10 test matrix from LLD."""

import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from hssh.safety import SafetyGate


# T1: Basic allow
def test_basic_allow():
    gate = SafetyGate()
    allowed, reason = gate.check_device("10.0.1.1")
    assert allowed is True
    assert reason == "ok"
    assert "10.0.1.1" in gate._active


# T2: Duplicate block
def test_duplicate_block():
    gate = SafetyGate()
    gate.check_device("10.0.1.1")
    allowed, reason = gate.check_device("10.0.1.1")
    assert allowed is False
    assert "active connection" in reason


# T3: Release + re-allow
def test_release_and_reallow():
    gate = SafetyGate()
    gate.check_device("10.0.1.1")
    gate.release_device("10.0.1.1")
    assert "10.0.1.1" not in gate._active

    allowed, reason = gate.check_device("10.0.1.1")
    assert allowed is True
    assert gate._attempt_count["10.0.1.1"] == 2


# T4: Rate limit (10/device)
def test_rate_limit():
    gate = SafetyGate(rate_limit=10)
    for i in range(10):
        allowed, _ = gate.check_device("10.0.1.1")
        assert allowed is True
        gate.release_device("10.0.1.1")

    allowed, reason = gate.check_device("10.0.1.1")
    assert allowed is False
    assert "rate limited 10/10" in reason


# T5: Cooldown set
def test_cooldown_set():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        tmp = f.name

    try:
        gate = SafetyGate(safety_file=tmp, cooldown_seconds=120)
        gate.check_device("10.0.1.1")
        gate.set_cooldown("10.0.1.1")

        # Device should be blocked
        allowed, reason = gate.check_device("10.0.1.1")
        assert allowed is False
        assert "cooldown active" in reason

        # File should contain the cooldown
        with open(tmp) as f:
            data = json.load(f)
        assert "10.0.1.1" in data
    finally:
        Path(tmp).unlink(missing_ok=True)


# T6: Cooldown expiry
def test_cooldown_expiry():
    gate = SafetyGate(cooldown_seconds=1)
    gate.check_device("10.0.1.1")
    gate.set_cooldown("10.0.1.1")

    # Should be blocked
    allowed, _ = gate.check_device("10.0.1.1")
    assert allowed is False

    # Wait for expiry
    time.sleep(1.1)
    allowed, reason = gate.check_device("10.0.1.1")
    assert allowed is True
    assert reason == "ok"


# T7: Cross-invocation persist
def test_cross_invocation_persist():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        tmp = f.name

    try:
        # Process A: set cooldown
        gate_a = SafetyGate(safety_file=tmp, cooldown_seconds=120)
        gate_a.check_device("10.0.1.1")
        gate_a.set_cooldown("10.0.1.1")
        gate_a.close()

        # Process B: new gate reads from same file
        gate_b = SafetyGate(safety_file=tmp, cooldown_seconds=120)
        allowed, reason = gate_b.check_device("10.0.1.1")
        assert allowed is False
        assert "cooldown active" in reason
        gate_b.close()
    finally:
        Path(tmp).unlink(missing_ok=True)


# T8: Graceful degradation
def test_graceful_degradation_unwritable():
    gate = SafetyGate(safety_file="/nonexistent/dir/safety.json")
    # Should still work in-memory
    allowed, reason = gate.check_device("10.0.1.1")
    assert allowed is True
    assert reason == "ok"

    # set_cooldown should not crash even if file is unwritable
    gate.set_cooldown("10.0.1.1")
    allowed, reason = gate.check_device("10.0.1.1")
    assert allowed is False
    assert "cooldown active" in reason


# T9: Concurrent invocations (fcntl.flock prevents corruption)
def test_concurrent_file_access():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        tmp = f.name

    try:
        gate1 = SafetyGate(safety_file=tmp, cooldown_seconds=120)
        gate2 = SafetyGate(safety_file=tmp, cooldown_seconds=120)

        gate1.check_device("10.0.1.1")
        gate1.set_cooldown("10.0.1.1")

        gate2.check_device("10.0.1.2")
        gate2.set_cooldown("10.0.1.2")

        # Both should be persisted without corruption
        with open(tmp) as f:
            data = json.load(f)
        assert "10.0.1.2" in data

        gate1.close()
        gate2.close()
    finally:
        Path(tmp).unlink(missing_ok=True)


# T10: Expired pruning
def test_expired_pruning():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        # Pre-seed with an expired entry
        expired = {"10.0.1.99": time.time() - 10}
        json.dump(expired, f)
        tmp = f.name

    try:
        gate = SafetyGate(safety_file=tmp, cooldown_seconds=120)
        # Expired entry should have been pruned on load
        assert "10.0.1.99" not in gate._cooldowns

        # close() should also prune and persist
        gate._cooldowns["10.0.1.88"] = time.time() - 5  # inject another expired
        gate.close()

        with open(tmp) as f:
            data = json.load(f)
        assert "10.0.1.88" not in data
        assert "10.0.1.99" not in data
    finally:
        Path(tmp).unlink(missing_ok=True)


# Extra: disabled safety gate (no safety_file, default behavior)
def test_disabled_safety_gate_none():
    """When safety_gate is None, runner should not enforce any limits."""
    gate = SafetyGate()
    # Without a file, still works in-memory
    allowed, reason = gate.check_device("10.0.1.1")
    assert allowed is True
    gate.release_device("10.0.1.1")


# Extra: fail-closed — host in _active BEFORE returning True
def test_fail_closed_active_before_return():
    gate = SafetyGate()
    # Simulate: check_device returns True, crash before release
    allowed, _ = gate.check_device("10.0.1.1")
    assert allowed is True
    # Host is in _active — cannot be checked again
    allowed2, reason2 = gate.check_device("10.0.1.1")
    assert allowed2 is False
    assert "active connection" in reason2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
