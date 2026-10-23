"""#65: a failure the same call cannot fix is reported once, in words that
say what happened; a device the operator interrupted while it was still
being connected to is interrupted, not failed."""
import asyncio
import json
import os
import socket
import sys
import time
import types
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, vendors
from hssh.errors import NotAppliedError
from hssh.runner import _retry_loop, is_connect_failure, is_permanent_failure
from hssh.vendors import generic, junos


# --- M7: permanent means one attempt -------------------------------------------

@pytest.mark.parametrize("message", [
    "No structured binding for 'show foo' on junos. Add a \"structured\" key to the entry in commands/junos.json.",
    "No authentication methods available for u@10.0.0.1: no password was given and no key was found in ~/.ssh or from an agent.",
    "ssh exit 255: hostname contains invalid characters",
    "ssh exit 255: remote username contains invalid characters",
    "/home/x/.h-ssh/known_hosts: malformed known_hosts line: 'r1 ssh-rsa not-base64!!'; fix or remove it",
    "NETCONF connect failed: PyEZ does not accept host '2001:db8::1': Invalid 'host' value",
    "NETCONF connect failed: connection refused by 10.0.0.1:830 (nothing listening, or no route)",
    "NETCONF connect failed: 10.0.0.1:830 is not an SSH server: the banner is not text",
])
def test_the_request_itself_is_wrong_so_it_is_not_retried(message):
    assert is_permanent_failure(RuntimeError(message))
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError(message)
    with pytest.raises(RuntimeError):
        _retry_loop(boom, "r1", True, 3, lambda e: True)
    assert len(calls) == 1


@pytest.mark.parametrize("message", [
    "Invalid SSH banner",
    "RpcTimeoutError(host: 10.0.0.1, cmd: get-software-information, timeout: 20)",
    "ConnectClosedError(10.0.0.1)",
])
def test_transport_trouble_after_the_session_is_still_retried(message):
    assert not is_permanent_failure(RuntimeError(message))


def test_connect_phase_failures_are_told_from_command_failures():
    for text in ("NETCONF connect failed: connect to 10.0.0.1:830 timed out after 10s",
                 "timed out", "[Errno None] Unable to connect to port 22 on 10.0.0.1",
                 "Error reading SSH protocol banner", "connection refused by 10.0.0.1"):
        assert is_connect_failure(text), text
    for text in ("Command timed out after 30s: show version",
                 "'show version': no output within the command timeout",
                 "Failed to lock config: LockError(...)", "RpcTimeoutError(host: 10.0.0.1, ...)"):
        assert not is_connect_failure(text), text


# --- L5: the junos driver says what happened, not what the clock said --------------

class _Ctx(Exception):
    pass


class SSHError(_Ctx):
    pass


class SSHUnknownHostError(SSHError):
    pass


class AuthenticationError(_Ctx):
    pass


def _pyez(kind, cause=None, orig=None):
    """A PyEZ connect exception as open() raises it: named by class, the
    exception it was handling chained as __context__ (or ._orig)."""
    exc = type(kind, (Exception,), {})(f"{kind}(10.0.0.1)")
    if cause is not None:
        exc.__context__ = cause
    if orig is not None:
        exc._orig = orig
    return exc


@pytest.mark.parametrize("exc, elapsed, expect", [
    (_pyez("ConnectRefusedError", SSHError("Could not open socket to 10.0.0.1:830")), 0.01,
     "connection refused by 10.0.0.1:830 (nothing listening, or no route)"),
    (_pyez("ConnectTimeoutError", SSHError("Could not open socket to 10.0.0.1:830")), 10.0,
     "connect to 10.0.0.1:830 timed out after 10s (filtered, or down)"),
    (_pyez("ConnectRefusedError", SSHError("Negotiation failed: Error reading SSH protocol banner'utf-8' codec can't decode byte 0xff in position 0: invalid start byte")), 0.2,
     "10.0.0.1:830 is not an SSH server: the banner is not text"),
    (_pyez("ConnectRefusedError", SSHError("Negotiation failed: Error reading SSH protocol banner[Errno 104] Connection reset by peer")), 0.1,
     "10.0.0.1:830 dropped the session before login after 0.1s ([Errno 104] Connection reset by peer; sshd connection limit?)"),
    (_pyez("ConnectRefusedError", SSHError("Negotiation failed: Error reading SSH protocol banner")), 0.1,
     "10.0.0.1:830 dropped the session before login after 0.1s (sshd connection limit?)"),
    (_pyez("ConnectError", orig=SSHError("Negotiation failed: Error reading SSH protocol banner")), 15.0,
     "no SSH banner from 10.0.0.1:830 within 15s (sshd busy, or filtered)"),
    (_pyez("ConnectRefusedError", SSHUnknownHostError("Unknown host key [ab:cd] for [10.0.0.1]")), 0.3,
     "host key verification failed for 10.0.0.1:830: not in ~/.ssh/known_hosts, or changed (HSSH_NETCONF_HOSTKEY=yes); nothing was sent"),
    (_pyez("ConnectAuthError", AuthenticationError("Authentication failed")), 0.5,
     "authentication failed for u at 10.0.0.1:830"),
    (_pyez("ConnectUnknownHostError", socket.gaierror(-2, "Name or service not known")), 0.0,
     "cannot resolve 10.0.0.1"),
    (_pyez("ConnectError", orig=SSHError("Negotiation failed: Incompatible ssh peer (no acceptable kex algorithm)")), 0.4,
     "SSH negotiation with 10.0.0.1:830 failed: Incompatible ssh peer (no acceptable kex algorithm)"),
])
def test_connect_reason_reads_the_exception_pyez_was_handling(exc, elapsed, expect):
    assert junos._connect_reason(exc, "10.0.0.1", "u", 830, 10, elapsed) == expect


def test_an_ipv6_literal_is_named_as_the_reason():
    exc = _pyez("ConnectUnknownHostError", socket.gaierror(-2, "Name or service not known"))
    assert junos._connect_reason(exc, "[2001:db8::1]", "u", 830, 10, 0.0) == \
        "cannot resolve [2001:db8::1] (an IPv6 literal is not accepted by this PyEZ/ncclient; use a name)"


def test_open_wraps_pyez_host_validation_as_a_connect_failure(monkeypatch):
    class Dev:
        def __init__(self, **kw):
            raise ValueError("Invalid 'host' value 'fd00::1': only alphanumerics, dots, underscores, "
                             "hyphens, or bracketed IPv6 literals are permitted.")
    monkeypatch.setattr(junos, "JunosDevice", Dev)
    with pytest.raises(NotAppliedError, match="NETCONF connect failed: PyEZ does not accept host 'fd00::1'"):
        junos._open("fd00::1", "u", "p", 10, 30, None)


def test_open_reports_the_reason_and_closes_the_device(monkeypatch):
    closed = []

    class Dev:
        def __init__(self, **kw):
            self.kw = kw

        def open(self):
            try:
                raise SSHError("Could not open socket to 10.0.0.1:830")
            except SSHError:
                raise junos.ConnectError("ConnectRefusedError(10.0.0.1)")

        def close(self):
            closed.append(1)
    monkeypatch.setattr(junos, "JunosDevice", Dev)
    with pytest.raises(NotAppliedError, match=r"NETCONF connect failed: .*10\.0\.0\.1:830"):
        junos._open("10.0.0.1", "u", "p", 10, 30, None)
    assert closed == [1]


# --- the generic transport: a pin file that cannot be read, nothing to log in with --

def test_a_malformed_known_hosts_line_is_refused_before_connecting(monkeypatch, tmp_path):
    paramiko = pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(tmp_path)))
    (tmp_path / ".ssh").mkdir(mode=0o700)
    (tmp_path / ".ssh" / "known_hosts").write_text("r1 ssh-ed25519 not-base64!!\n")
    connected = []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda self, **kw: connected.append(kw))
    with pytest.raises(ValueError, match=r"\.ssh/known_hosts: malformed known_hosts line: 'r1 ssh-ed25519 not-base64!!'; fix or remove it"):
        generic._connect("10.0.0.1", "u", "p", 5, None)
    assert connected == []
    assert is_permanent_failure(ValueError("x: malformed known_hosts line: 'r1'; fix or remove it"))


def test_no_credential_at_all_is_said_in_words(monkeypatch, tmp_path):
    paramiko = pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(tmp_path)))

    def connect(self, **kw):
        raise paramiko.SSHException("No authentication methods available")
    monkeypatch.setattr(paramiko.SSHClient, "connect", connect)
    with pytest.raises(RuntimeError, match="No authentication methods available for u@10.0.0.1: no password was given"):
        generic._connect("10.0.0.1", "u", None, 5, None)


# --- M8: Ctrl-C during a connect is interrupted, not a failed device --------------

async def _reachable(target, timeout=2):
    return (target.name, True, "reachable")


def _main_cancelled_after(delay):
    async def go():
        asyncio.get_running_loop().call_later(delay, asyncio.current_task().cancel)
        return await cli.main()
    return asyncio.run(go())


def _cli_env(monkeypatch, driver):
    monkeypatch.setitem(vendors.VENDORS, "junos", driver)
    monkeypatch.setitem(cli.VENDOR_MODULES, "junos", driver)
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)


def test_ctrl_c_during_a_connect_is_interrupted_not_failed(monkeypatch, capsys, tmp_path):
    seen = []

    def show(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        seen.append(host)
        time.sleep(0.8)                  # the connect runs out on its own after Ctrl-C
        raise NotAppliedError("NETCONF connect failed: connect to %s:830 timed out after 10s" % host)
    _cli_env(monkeypatch, types.SimpleNamespace(AVAILABLE=True, show=show))
    log = tmp_path / "run.jsonl"
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--password", "p",
                                      "--target", "R1:10.0.0.1:junos", "--target", "R2:10.0.0.2:junos",
                                      "--workers", "1", "-sC", "show version", "--log", str(log)])
    rc = _main_cancelled_after(0.3)
    out, err = capsys.readouterr()
    assert rc == 130 and seen == ["10.0.0.1"]
    assert "R1" in out and "INTERRUPTED" in out and "FAIL" not in out
    assert "Interrupted. Completed 0 of 2 device(s); 1 interrupted while connecting." in err
    summary = json.loads(err.split("[h-ssh] ", 1)[1].splitlines()[0])
    assert summary["targets"] == 1 and summary["ok"] == 0 and summary["fail"] == 0 and summary["interrupted"] == 1
    line = json.loads(log.read_text().splitlines()[0])
    assert line["device"] == "R1" and line["ok"] is False and line["interrupted"] is True
    assert line["error"].startswith("interrupted while connecting: NETCONF connect failed")


def test_ctrl_c_after_the_session_was_up_keeps_a_real_failure(monkeypatch, capsys):
    def show(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        time.sleep(0.8)
        raise RuntimeError("RpcTimeoutError(host: %s, cmd: get-software-information, timeout: 20)" % host)
    _cli_env(monkeypatch, types.SimpleNamespace(AVAILABLE=True, show=show))
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--password", "p",
                                      "--target", "R1:10.0.0.1:junos", "--workers", "1", "--retries", "0",
                                      "-sC", "show version"])
    rc = _main_cancelled_after(0.3)
    out, err = capsys.readouterr()
    assert rc == 130 and "FAIL" in out
    assert "Interrupted. Completed 1 of 1 device(s)." in err
    summary = json.loads(err.split("[h-ssh] ", 1)[1].splitlines()[0])
    assert summary["fail"] == 1 and summary["interrupted"] == 0
