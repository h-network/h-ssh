"""Retry classification and the attempt budget."""
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh.errors import ConnectTimeoutError, NotAppliedError
from hssh.runner import (CONNECT_BACKOFF, _retry_loop, _with_retry, is_connect_failure, is_connect_timeout,
                         is_permanent_failure, _backoff)


@pytest.mark.parametrize("message", [
    "Authentication failed.",
    "Permission denied (publickey,password).",
    "Host key verification failed for 10.0.1.1.",
    "Cannot resolve r1.",
    "Unknown vendor 'nope'.",
    "--commit-confirmed is not supported by the 'openssh' transport",
    "'uptime' was refused by the device: error: unknown command: uptime",
    "password authentication needs OpenSSH >= 8.4",
    "Junos rejected the operational command",
    "login failed: Login incorrect",
    "login failed: the device asked for credentials again",
])
def test_permanent_failures_are_recognised(message):
    assert is_permanent_failure(Exception(message))


@pytest.mark.parametrize("message", [
    "Connection refused by 10.0.1.1.",
    "ssh: connect to host r1 port 22: No route to host",
    "ssh: connect to host r1 port 22: Network is unreachable",
    "[Errno None] Unable to connect to port 22 on 10.0.1.1",
    # #126: the SSH transports say what the OS answered
    "connection refused by 10.0.1.1:22",
    "no route to host 10.91.0.252:22",
    "network is unreachable for 10.0.1.1:22",
    "NETCONF connect failed: no route to host 10.91.0.252:830",
    "cannot resolve r1.lab",
])
def test_a_clear_answer_in_the_connect_phase_is_permanent_for_the_run(message):
    """Refused, no route, a name that does not resolve: the same call gets
    the same answer. (A connect phase that got no answer at all is tried
    again: see the #126 tests below.)"""
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
    env.pop("HSSH_PASSWORD", None)   # no password: keys would do, and the stub never asks
    hssh = os.path.join(os.path.dirname(__file__), "..", "h-ssh.py")

    start = time.time()
    proc = subprocess.run([sys.executable, hssh, "--devices", str(devices), "--user", "x",
                           "-sC", "show version", "--raw", "--workers", "24"],
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, env=env)
    elapsed = time.time() - start

    # The timing means nothing unless the run completed: an early exit is fast too.
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.count("ok") == 24, proc.stdout
    # 24 devices x 1s. One batch is ~1s; a capped pool needs two or more.
    assert elapsed < 2.0, "24 workers took %.1fs, so they did not run concurrently" % elapsed


@pytest.mark.parametrize("message", [
    "NETCONF connect failed: connection refused by 10.0.0.1:830",
    "NETCONF connect failed: ConnectRefusedError(10.0.0.1)",
    "NETCONF connect failed: ConnectUnknownHostError(r1.lab.example)",
    "NETCONF connect failed: ConnectAuthError(10.0.0.1)",
    "NETCONF connect failed: ConnectError(host: 10.0.0.1, msg: [Errno 113] No route to host)",
])
def test_pyez_connect_failures_are_permanent(message):
    """PyEZ names the connect phase by exception class and the junos driver
    wraps that in NotAppliedError. Neither coat may hide a clear answer; only
    the connect phase running out (#126) is tried again."""
    assert is_permanent_failure(NotAppliedError(message))


@pytest.mark.parametrize("message", [
    "ConnectClosedError(10.0.0.1)",
    "RpcTimeoutError(host: 10.0.0.1, cmd: get-software-information, timeout: 20)",
    "Failed to lock config: LockError(severity: error, bad_element: None, "
    "message: configuration database locked by: admin terminal pts/0 (pid 1234))",
])
def test_pyez_session_failures_are_retried(message):
    """These arrive after the NETCONF session was up, so the next attempt may succeed."""
    assert not is_permanent_failure(RuntimeError(message))


@pytest.mark.parametrize("message", [
    "Invalid SSH banner",
    "Invalid packet blocking",
    "[Errno 22] Invalid argument",
])
def test_transport_level_invalid_is_retried(message):
    """paramiko and the OS say 'Invalid ...' about a mangled transport, which
    is nothing like a device rejecting the command: the next attempt may succeed."""
    assert not is_permanent_failure(Exception(message))


@pytest.mark.parametrize("message", [
    "Error [1002]: CLI command 1 of 1 'show foo' failed: invalid command "
    "[Invalid input (at token 1: 'foo')]",
    "% Invalid input detected at '^' marker.",
])
def test_rejected_command_is_permanent(message):
    """A device that rejected the command will reject it again."""
    assert is_permanent_failure(Exception(message))


def test_an_edit_to_a_router_that_refuses_is_attempted_once(monkeypatch):
    """NotAppliedError is the one failure an edit may retry, but a router
    that refused the connect will refuse it again: one attempt, not three
    plus backoff. (One that did not answer at all is tried again: #126.)"""
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    calls = []

    def boom():
        calls.append(1)
        raise NotAppliedError("NETCONF connect failed: connection refused by 10.0.0.1:830")

    with pytest.raises(NotAppliedError):
        _retry_loop(boom, "r1", True, 3, lambda e: isinstance(e, NotAppliedError))
    assert len(calls) == 1


# --- #126: a connect phase that ran out is tried again, after a short pause ------------

@pytest.mark.parametrize("message", [
    "TCP connect to 10.0.0.1:22 timed out after 3s",
    "no SSH banner from 10.0.0.1:22 within 3s",
    "NETCONF connect failed: TCP connect to 10.0.0.1:830 timed out after 3s",
    "NETCONF connect failed: no SSH banner from [2001:db8::1]:830 within 3s",
    "ssh exit 255: ssh: connect to host 192.0.2.1 port 22: Connection timed out",     # OpenSSH's own ConnectTimeout
    "kex_exchange_identification: Connection timed out during banner exchange",
])
def test_a_connect_phase_that_ran_out_is_a_connect_failure_and_not_permanent(message):
    """No TCP answer, or no banner, within --connect-timeout: nothing was
    sent, and a booting box or a busy sshd may answer the next attempt. On
    junos and openssh this was permanent ("netconf connect failed",
    "connection timed out")."""
    for exc in (RuntimeError(message), NotAppliedError(message), ConnectTimeoutError(message)):
        assert is_connect_timeout(exc) and is_connect_failure(exc) and not is_permanent_failure(exc), exc
    assert is_connect_timeout(ConnectTimeoutError("the class says it, whatever the words"))


@pytest.mark.parametrize("message", [
    "Command timed out after 50s: show version",
    "no SSH session to 10.0.0.1 within 30s: the banner came, but key exchange did not finish",
    "connection refused by 10.0.0.1:22",
    "TCP connect to 10.0.0.1:22 failed: Operation not permitted",
    "'show tcp connect to x timed out' was refused by the device: error: syntax error",
])
def test_anything_else_is_not_a_connect_timeout(message):
    assert not is_connect_timeout(RuntimeError(message))


def test_a_connect_phase_that_ran_out_is_tried_again_after_a_short_pause(monkeypatch, capsys):
    """0.5 s and then 1 s: three attempts at the defaults (3 s each,
    --retries 2) take about 10 s. Every other failure keeps its pauses."""
    pauses = []
    monkeypatch.setattr(time, "sleep", pauses.append)
    calls = []

    def dead():
        calls.append(1)
        raise ConnectTimeoutError("TCP connect to 10.0.0.1:22 timed out after 3s")

    with pytest.raises(ConnectTimeoutError):
        _with_retry(dead, "r1", False, 3)
    assert len(calls) == 3 and pauses == [0.5, 1]
    out = capsys.readouterr().out
    assert "RETRY 1/2 in 0.5s (TCP connect to 10.0.0.1:22 timed out after 3s)" in out
    assert "RETRY 2/2 in 1s (TCP connect to 10.0.0.1:22 timed out after 3s)" in out
    pauses.clear()

    def slow():
        raise RuntimeError("Command timed out after 50s: show version")

    with pytest.raises(RuntimeError):
        _with_retry(slow, "r1", True, 3)
    assert pauses == [1, 3]
    assert [_backoff(n, CONNECT_BACKOFF) for n in (1, 2, 9)] == [0.5, 1, 1]


def test_an_edit_whose_connect_phase_ran_out_is_tried_again(monkeypatch):
    """Nothing was sent, so it is safe for an edit too: a connect phase that
    ran out is a NotAppliedError, the one failure an edit may retry."""
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    calls = []

    def dead():
        calls.append(1)
        raise ConnectTimeoutError("NETCONF connect failed: no SSH banner from 10.0.0.1:830 within 3s")

    with pytest.raises(ConnectTimeoutError):
        _retry_loop(dead, "r1", True, 3, lambda e: isinstance(e, NotAppliedError))
    assert len(calls) == 3
