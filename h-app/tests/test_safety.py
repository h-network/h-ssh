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
    assert len(gate._attempt_timestamps["10.0.1.1"]) == 2


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


def test_the_rate_limit_counts_logins_only():
    """An attempt that opens no session of its own (a job's later entry on
    the pooled NETCONF session, a dry run of a read) is not a login (#145):
    past the limit it still goes, and it is not counted; a cooldown and an
    active mark turn it away as before."""
    gate = SafetyGate(rate_limit=2)
    for _ in range(2):
        assert gate.check_device("10.0.1.1") == (True, "ok")
        gate.release_device("10.0.1.1")
    assert gate.check_device("10.0.1.1") == (False, "rate limited 2/2")
    assert gate.check_device("10.0.1.1", login=False) == (True, "ok")
    assert gate.check_device("10.0.1.1", login=False) == (False, "active connection")
    gate.release_device("10.0.1.1")
    assert len(gate._attempt_timestamps["10.0.1.1"]) == 2
    gate.set_cooldown("10.0.1.1")
    allowed, reason = gate.check_device("10.0.1.1", login=False)
    assert not allowed and reason.startswith("cooldown active")


def test_a_device_is_its_host_and_its_port(tmp_path):
    """Two routers behind one address are two devices (#145): each is
    marked active, counted and cooled on its own, and the file keeps a
    cooldown as `host|port`. An entry kept under the host alone (a caller
    that names no port, a file an older h-ssh wrote) holds every port, and
    such a caller asks for the host as a whole, held while any port of it
    is cooling: a script on the old API, sharing the file with h-ssh runs,
    sees their cooldowns."""
    path = str(tmp_path / "safety.json")
    gate = SafetyGate(safety_file=path, rate_limit=1)
    assert gate.check_device("10.0.0.1", 8301) == (True, "ok")
    assert gate.check_device("10.0.0.1", 8302) == (True, "ok")          # not an "active connection"
    gate.release_device("10.0.0.1", 8302)
    assert gate.check_device("10.0.0.1", 8302) == (False, "rate limited 1/1")
    gate.set_cooldown("10.0.0.1", 8301)
    with open(path) as f:
        assert list(json.load(f)) == ["10.0.0.1|8301"]
    assert gate.check_device("10.0.0.1", 8301)[1].startswith("cooldown active")
    assert list(gate.holds([("10.0.0.1", 8301), ("10.0.0.1", 8302)])) == [("10.0.0.1", 8301)]
    gate.set_cooldown("10.0.0.20", 22)
    script = SafetyGate(safety_file=path)                                 # the old API, on the same file
    allowed, reason = script.check_device("10.0.0.1")                     # no port: the host as a whole
    assert not allowed and reason.startswith("cooldown active")
    assert list(script.holds(["10.0.0.1", "10.0.0.2"])) == ["10.0.0.1"]  # 10.0.0.20 is not 10.0.0.2
    assert script.check_device("10.0.0.1", 8302) == (True, "ok")         # the other port still goes
    gate.set_cooldown("10.0.0.1")                                         # the host alone: every port of it
    assert sorted(gate.holds([("10.0.0.1", 8302), ("10.0.0.1", 22), ("10.0.0.2", 22)])) == [
        ("10.0.0.1", 22), ("10.0.0.1", 8302)]
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"10.0.0.9": time.time() + 300}))           # as an h-ssh before #145 kept it
    gate = SafetyGate(safety_file=str(old))
    allowed, reason = gate.check_device("10.0.0.9", 830)
    assert not allowed and reason.startswith("cooldown active")
    assert list(gate.holds([("10.0.0.9", 22)])) == [("10.0.0.9", 22)]
    assert gate.check_device("10.0.0.8", 830) == (True, "ok")


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


def test_the_directories_made_for_the_safety_file_are_private_whatever_the_umask(tmp_path):
    """The parents made for the safety file were the umask's, 0777 under
    umask 000 (#149): each one made is 0700, the file 0600 as before."""
    old = os.umask(0o000)
    try:
        gate = SafetyGate(safety_file=str(tmp_path / "a" / "b" / "safety.json"))
        gate.set_cooldown("10.0.1.1")
        gate.close()
    finally:
        os.umask(old)
    assert [os.stat(tmp_path / d).st_mode & 0o777 for d in ("a", "a/b")] == [0o700, 0o700]
    assert os.stat(tmp_path / "a" / "b" / "safety.json").st_mode & 0o777 == 0o600


# T8: a gate that cannot keep its file refuses to exist (#64); the
# in-memory gate is still the one without a file.
def test_an_unwritable_safety_file_refuses_the_gate(tmp_path):
    (tmp_path / "afile").write_text("x")          # a directory cannot be made inside a file, root or not
    bad = tmp_path / "afile" / "dir" / "safety.json"
    with pytest.raises(OSError, match=f"safety file {bad}: cannot create its directory"):
        SafetyGate(safety_file=str(bad))
    gate = SafetyGate(safety_file=None)
    allowed, reason = gate.check_device("10.0.1.1")
    assert allowed is True and reason == "ok"
    gate.set_cooldown("10.0.1.1")
    allowed, reason = gate.check_device("10.0.1.1")
    assert allowed is False and "cooldown active" in reason


# T9: two gates on one file, one after the other: the second's save merges
# the first's cooldown from the file (two at once: the two-process test below)
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
        assert "10.0.1.1" in data
        assert "10.0.1.2" in data

        gate1.close()
        gate2.close()
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(f"{tmp}.lock").unlink(missing_ok=True)


def _save_a_cooldown(path, host, start, inside, wait):
    """One run's set_cooldown(host) on the shared file, in a process of its
    own. The two runs start together (`start`); each then stops inside its
    save, after reading the file and just before its os.replace, until the
    other is there too or `wait` seconds pass (`inside`)."""
    import threading
    from hssh import safety
    gate = SafetyGate(safety_file=path, cooldown_seconds=300)
    real_replace = safety.os.replace

    def replace(src, dst):
        try:
            inside.wait(wait)
        except threading.BrokenBarrierError:
            pass                    # the other run is not in here: it waits for the lock
        return real_replace(src, dst)
    safety.os.replace = replace
    start.wait(60)
    gate.set_cooldown(host)


def test_two_runs_saving_at_the_same_moment_keep_both_cooldowns(tmp_path):
    """The flock around a save is all that keeps two runs from losing each
    other's cooldowns (#145): a save reads the file, merges its own hosts
    and replaces the file. Here two processes save at once. Under the lock
    only one is inside at a time: the first writes after its wait, the
    second then reads that file, and both hosts are kept. Without it both
    read the file before either wrote it, and the second os.replace drops
    the first one's host: with every fcntl.flock in safety.py stubbed out
    this fails, where T9, whose two gates take turns, passed."""
    import multiprocessing
    path = str(tmp_path / "safety.json")
    ctx = multiprocessing.get_context("spawn")          # no fork of a process with threads in it
    start, inside = ctx.Barrier(2), ctx.Barrier(2)
    runs = [ctx.Process(target=_save_a_cooldown, args=(path, host, start, inside, 1.0))
            for host in ("10.0.0.1", "10.0.0.2")]
    try:
        for p in runs:
            p.start()
        for p in runs:
            p.join(60)
        assert [p.exitcode for p in runs] == [0, 0]
    finally:
        for p in runs:
            if p.is_alive():
                p.terminate()
    with open(path) as f:
        assert sorted(json.load(f)) == ["10.0.0.1", "10.0.0.2"]


def test_fail_closed_on_corrupt_file():
    """Corrupted safety file must cause check_device to fail-closed."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("{this is invalid json content")
        tmp = f.name

    try:
        gate = SafetyGate(safety_file=tmp)
        allowed, reason = gate.check_device("10.0.1.1")
        assert allowed is False
        assert "corrupt" in reason.lower()
        assert f"{tmp}.corrupt" in reason      # names the sentinel to clear (#39)
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(f"{tmp}.lock").unlink(missing_ok=True)
        Path(f"{tmp}.corrupt").unlink(missing_ok=True)


def test_file_permissions_0600():
    """Safety file and lockfile must be created with 0600 permissions."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        tmp = f.name

    try:
        gate = SafetyGate(safety_file=tmp, cooldown_seconds=120)
        gate.set_cooldown("10.0.1.1")
        gate.close()

        # Check permissions
        mode = os.stat(tmp).st_mode & 0o777
        assert mode == 0o600
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(f"{tmp}.lock").unlink(missing_ok=True)


def test_thread_safety_active_set():
    """Concurrent threads checking distinct devices must all succeed safely."""
    import threading

    gate = SafetyGate(rate_limit=100)
    errors = []

    def worker(idx):
        try:
            allowed, _ = gate.check_device(f"10.0.1.{idx}")
            if not allowed:
                errors.append(f"Worker {idx} not allowed")
            gate.release_device(f"10.0.1.{idx}")
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors


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


def test_sliding_window_budget_frees():
    """H1: Rate limit budget frees after rate_window expires without accumulating permanently."""
    gate = SafetyGate(rate_limit=3, rate_window=0.2)
    host = "10.0.1.1"

    # Exhaust budget of 3
    for _ in range(3):
        allowed, reason = gate.check_device(host)
        assert allowed is True
        gate.release_device(host)

    # 4th attempt immediately should be blocked
    allowed, reason = gate.check_device(host)
    assert allowed is False
    assert "rate limited 3/3" in reason

    # Wait for the sliding window to expire
    time.sleep(0.25)

    # Budget should now be freed
    allowed, reason = gate.check_device(host)
    assert allowed is True
    assert reason == "ok"
    gate.release_device(host)


def test_corrupt_file_rename_no_silent_heal():
    """M1: Corrupted safety file is renamed to .corrupt and fails closed across runs without silent heal."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("{invalid: json,")
        tmp = f.name
    corrupt_file = Path(f"{tmp}.corrupt")

    try:
        gate1 = SafetyGate(safety_file=tmp)
        allowed, reason = gate1.check_device("10.0.1.1")
        assert allowed is False
        assert "corrupt" in reason.lower()
        assert corrupt_file.exists()

        # close() should NOT overwrite with {} or heal the file
        gate1.close()
        assert corrupt_file.exists()

        # Second instance must also fail closed
        gate2 = SafetyGate(safety_file=tmp)
        allowed2, reason2 = gate2.check_device("10.0.1.1")
        assert allowed2 is False
        assert "corrupt" in reason2.lower()
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(f"{tmp}.lock").unlink(missing_ok=True)
        corrupt_file.unlink(missing_ok=True)


def test_safety_file_null_values():
    """M1: Null values in JSON cooldowns must not raise TypeError."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        future = time.time() + 300
        json.dump({"10.0.1.1": None, "10.0.1.2": future}, f)
        tmp = f.name

    try:
        gate = SafetyGate(safety_file=tmp)
        # 10.0.1.1 has null cooldown, should be allowed
        allowed1, _ = gate.check_device("10.0.1.1")
        assert allowed1 is True
        gate.release_device("10.0.1.1")

        # 10.0.1.2 has active cooldown, should be blocked
        allowed2, reason2 = gate.check_device("10.0.1.2")
        assert allowed2 is False
        assert "cooldown active" in reason2
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(f"{tmp}.lock").unlink(missing_ok=True)


def test_safety_file_zero_byte():
    """M1: 0-byte safety file is treated as empty dictionary without corrupting."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        tmp = f.name  # 0 bytes

    try:
        gate = SafetyGate(safety_file=tmp)
        allowed, reason = gate.check_device("10.0.1.1")
        assert allowed is True
        assert reason == "ok"
        gate.release_device("10.0.1.1")
        assert not Path(f"{tmp}.corrupt").exists()
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(f"{tmp}.lock").unlink(missing_ok=True)


def test_file_lock_passes_a_body_error_through():
    """An OSError raised inside the locked body is the caller's error, not a
    lock failure: it must come back as itself, not as contextlib's RuntimeError
    for a generator that yielded twice."""
    with tempfile.TemporaryDirectory() as d:
        gate = SafetyGate(safety_file=os.path.join(d, "safety.json"))
        with pytest.raises(PermissionError):
            with gate._file_lock():
                raise PermissionError(13, "simulated EACCES inside the locked body")


def test_set_cooldown_survives_a_stat_failure(monkeypatch):
    """set_cooldown runs from the runner's except handler. A safety file that
    cannot be stat'ed must log and keep the cooldown, not abort the whole run."""
    with tempfile.TemporaryDirectory() as d:
        tmp = os.path.join(d, "safety.json")
        gate = SafetyGate(safety_file=tmp, cooldown_seconds=120)
        real_stat = Path.stat

        def stat(self, *args, **kwargs):
            if str(self) == tmp:
                raise PermissionError(13, "simulated EACCES", tmp)
            return real_stat(self, *args, **kwargs)

        # The file has to exist and be non-empty first, or exists() short-
        # circuits the stat (on 3.13+ it is os.path.exists and never calls
        # Path.stat at all) and the patched stat is never reached.
        gate.set_cooldown("10.0.1.2")
        monkeypatch.setattr(Path, "stat", stat)
        gate.set_cooldown("10.0.1.1")
        monkeypatch.undo()

        assert "10.0.1.1" in gate._cooldowns
        with open(tmp) as f:
            assert "10.0.1.1" in json.load(f)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


def test_lock_file_that_is_a_symlink_is_not_followed(tmp_path):
    """The lock open once followed a planted symlink (#41); now the gate runs
    unlocked and the link's target is left alone."""
    victim = tmp_path / "victim"
    victim.write_text("keep")
    os.chmod(victim, 0o644)
    sf = tmp_path / "gate.json"
    (tmp_path / "gate.json.lock").symlink_to(victim)
    with pytest.raises(OSError, match="gate.json.lock: cannot be created or opened"):
        SafetyGate(safety_file=str(sf))             # #64: refused outright, not run unlocked
    assert victim.read_text() == "keep" and oct(victim.stat().st_mode & 0o777) == "0o644"


# --- #152: a cooldown that is not a finite number ---------------------------------

HUGE_INT = pytest.param('{"h": 1' + "0" * 400 + '}', id="huge-int")   # an int no float can hold: json gives 10**400

@pytest.mark.parametrize("content", ['{"h": 1e400}', '{"h": Infinity}', '{"h": NaN}', '{"h": "inf"}', '{"h": "never"}',
                                     '{"h": {"until": 1}}', '{"h": true}', HUGE_INT])
def test_a_cooldown_that_is_not_a_finite_number_is_a_corrupt_file(tmp_path, content):
    """1e400 and Infinity loaded as inf (json.load allows them, and float()
    takes "inf" too), and check_device and holds then raised OverflowError
    at int(expires - now); "never" and an object passed as no cooldown and
    were erased by the next save, with no .corrupt (#152). A value that is
    not a finite number or null is not h-ssh's writing: the file is kept as
    .corrupt, the gate fails closed and writes nothing over it. An integer
    too large for a float (the review's repro) is the same, not an
    OverflowError out of the constructor."""
    path = tmp_path / "safety.json"
    path.write_text(content)
    gate = SafetyGate(safety_file=str(path))
    allowed, reason = gate.check_device("h")
    assert allowed is False and "corrupt" in reason, reason
    assert gate.holds(["h", ("other", 22)]) == {"h": reason, ("other", 22): reason}
    assert path.with_name("safety.json.corrupt").read_text() == content and not path.exists()
    gate.set_cooldown("other", 22)
    gate.close()
    assert not path.exists()


@pytest.mark.parametrize("content", ['[123]', '{"h": 1e400}', '{"h": "never"}', HUGE_INT])
def test_a_file_gone_wrong_between_the_load_and_the_save_is_corrupt_too(tmp_path, content):
    """The save's merge read took the file as the loader did, but a value
    that was no number, or a root that was no object, went through its
    catch-all (or was ignored) and the file was written over with `{}`:
    fail-open, with no .corrupt (the review's repro). What the loader calls
    corrupt the merge calls corrupt: the bytes are kept as .corrupt, nothing
    is written, and the gate is closed from there."""
    path = tmp_path / "safety.json"
    gate = SafetyGate(safety_file=str(path))
    assert gate.check_device("a", 22) == (True, "ok")
    gate.release_device("a", 22)
    path.write_text(content)                    # another hand, between this run's reads
    gate.set_cooldown("b", 22)                  # the save's merge read finds it
    assert path.with_name("safety.json.corrupt").read_text() == content and not path.exists()
    allowed, reason = gate.check_device("b", 22)
    assert allowed is False and "corrupt" in reason, reason
    gate.close()
    assert not path.exists() and path.with_name("safety.json.corrupt").read_text() == content


def test_the_gate_never_holds_a_cooldown_that_is_not_a_finite_number(tmp_path):
    """SafetyGate(cooldown_seconds=inf) was accepted and wrote `Infinity`
    into the file, which is not JSON and crashed the next run (#152)."""
    path = tmp_path / "safety.json"
    for bad in (float("inf"), float("nan"), "120", None):
        with pytest.raises(ValueError, match="cooldown_seconds"):
            SafetyGate(safety_file=str(path), cooldown_seconds=bad)
    with pytest.raises(ValueError, match="rate_limit"):
        SafetyGate(rate_limit=float("inf"))
    assert not path.exists()
    gate = SafetyGate(safety_file=str(path), cooldown_seconds=120)
    gate.set_cooldown("h", 22)
    gate.close()
    (expires,) = json.loads(path.read_text()).values()
    assert isinstance(expires, float) and time.time() < expires <= time.time() + 120
