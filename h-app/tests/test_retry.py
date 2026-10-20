"""Retry classification and the attempt budget."""
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh.runner import _with_retry, is_permanent_failure, _backoff


@pytest.mark.parametrize("message", [
    "Authentication failed.",
    "Permission denied (publickey,password).",
    "Host key verification failed for 10.0.1.1.",
    "Cannot resolve r1.",
    "Unknown vendor 'nope'.",
    "--commit-confirmed is not supported by the 'openssh' transport",
    "password authentication needs OpenSSH >= 8.4",
    "Junos rejected the operational command",
])
def test_permanent_failures_are_recognised(message):
    assert is_permanent_failure(Exception(message))


@pytest.mark.parametrize("message", [
    "ssh exit 255: ssh: connect to host 192.0.2.1 port 22: Connection timed out",
    "Connection refused by 10.0.1.1.",
    "ssh: connect to host r1 port 22: No route to host",
    "ssh: connect to host r1 port 22: Network is unreachable",
    "[Errno None] Unable to connect to port 22 on 10.0.1.1",
])
def test_unreachable_is_permanent_for_the_run(message):
    """A connect-phase failure has already spent the full ConnectTimeout."""
    assert is_permanent_failure(Exception(message))


@pytest.mark.parametrize("message", [
    "Command timed out after 50s: show version",
    "SSH transport failed: [Errno 104] Connection reset by peer",
    "SSH transport failed: [Errno 32] Broken pipe",
])
def test_failures_after_connect_are_retried(message):
    """The session was established, so the next attempt may well succeed."""
    assert not is_permanent_failure(Exception(message))


def test_permanent_failure_is_attempted_once():
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError("Authentication failed.")

    with pytest.raises(RuntimeError):
        _with_retry(boom, "r1", True, 3)
    assert len(calls) == 1


def test_transient_failure_uses_the_whole_budget(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError("Command timed out after 50s: show version")

    with pytest.raises(RuntimeError):
        _with_retry(boom, "r1", True, 3)
    assert len(calls) == 3


def test_budget_of_one_never_retries(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError("Command timed out after 50s: show version")

    with pytest.raises(RuntimeError):
        _with_retry(boom, "r1", True, 1)
    assert len(calls) == 1


def test_zero_budget_is_clamped_to_one_attempt(monkeypatch):
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError("Command timed out after 50s: show version")

    with pytest.raises(RuntimeError):
        _with_retry(boom, "r1", True, 0)
    assert len(calls) == 1


def test_success_returns_without_retrying():
    assert _with_retry(lambda: "ok", "r1", True, 3) == "ok"


def test_recovers_on_a_later_attempt(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    state = {"n": 0}

    def flaky():
        state["n"] += 1
        if state["n"] < 3:
            raise RuntimeError("Command timed out after 50s: show version")
        return "ok"

    assert _with_retry(flaky, "r1", True, 3) == "ok"
    assert state["n"] == 3


def test_backoff_extends_past_the_table():
    assert _backoff(1) == 1
    assert _backoff(2) == 3
    assert _backoff(9) == 3  # last step repeats rather than indexing off the end


def test_workers_are_clamped_to_a_usable_range():
    from hssh.cli import resolve_workers, MAX_WORKERS
    assert resolve_workers(8) == 8
    assert resolve_workers(0) == 1
    assert resolve_workers(-5) == 1
    assert resolve_workers(10_000) == MAX_WORKERS
    assert resolve_workers("nonsense") == 8


def test_workers_actually_run_in_parallel(tmp_path):
    """--workers must not silently cap at the default executor's min(32, cpu+4)."""
    import stat
    import subprocess
    import time

    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "ssh"
    stub.write_text("#!/bin/sh\nsleep 1\necho ok\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    devices = tmp_path / "devices.csv"
    devices.write_text("name,ip,vendor\n" +
                       "".join("R%02d,10.0.0.%d,openssh\n" % (i, i + 1) for i in range(24)))

    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"])
    hssh = os.path.join(os.path.dirname(__file__), "..", "h-ssh.py")

    start = time.time()
    subprocess.run([sys.executable, hssh, "--devices", str(devices), "--user", "x",
                    "--password", "", "-sC", "show version", "--raw", "--workers", "24"],
                   capture_output=True, text=True, timeout=120, env=env)
    elapsed = time.time() - start

    # 24 devices x 1s. One batch is ~1s; a capped pool needs two or more.
    assert elapsed < 2.0, "24 workers took %.1fs, so they did not run concurrently" % elapsed
