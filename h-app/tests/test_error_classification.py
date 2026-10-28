"""#65: a failure the same call cannot fix is reported once, in words that
say what happened; a device the operator interrupted while it was still
being connected to is interrupted, not failed."""
import asyncio
import errno
import json
import os
import socket
import sys
import time
import types
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, drivers
from hssh.errors import ConnectTimeoutError, NotAppliedError
from hssh.runner import _retry_loop, is_connect_failure, is_permanent_failure
from hssh.transports import netconf, ssh


# --- M7: permanent means one attempt -------------------------------------------

@pytest.mark.parametrize("message", [
    "No structured binding for 'show foo' on junos. Add a \"structured\" key to the entry in hssh/dialects/junos.json.",
    "No authentication methods available for u@10.0.0.1: no password was given and no key was found in ~/.ssh or from an agent.",
    "ssh exit 255: hostname contains invalid characters",
    "ssh exit 255: remote username contains invalid characters",
    "/home/x/.h-ssh/known_hosts: malformed known_hosts line 1: 'r1 ssh-rsa not-base64!!' (the key is not base64); fix or remove it",
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
    for text in ("NETCONF connect failed: TCP connect to 10.0.0.1:830 timed out after 10s",
                 "timed out", "[Errno None] Unable to connect to port 22 on 10.0.0.1",
                 "Error reading SSH protocol banner", "connection refused by 10.0.0.1",
                 # #126: the SSH transports' own words for the connect phase
                 "TCP connect to 10.0.0.1:22 timed out after 3s", "no SSH banner from 10.0.0.1:22 within 3s",
                 "no route to host 10.0.0.1:22", "TCP connect to 10.0.0.1:22 failed: Operation not permitted",
                 "cannot resolve r1.lab"):
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
     "TCP connect to 10.0.0.1:830 timed out after 10s"),
    (_pyez("ConnectRefusedError", SSHError("Negotiation failed: Error reading SSH protocol banner'utf-8' codec can't decode byte 0xff in position 0: invalid start byte")), 0.2,
     "10.0.0.1:830 is not an SSH server: the banner is not text"),
    (_pyez("ConnectRefusedError", SSHError("Negotiation failed: Error reading SSH protocol banner[Errno 104] Connection reset by peer")), 0.1,
     "10.0.0.1:830 dropped the session before login after 0.1s ([Errno 104] Connection reset by peer; sshd connection limit?)"),
    (_pyez("ConnectRefusedError", SSHError("Negotiation failed: Error reading SSH protocol banner")), 0.1,
     "10.0.0.1:830 dropped the session before login after 0.1s (sshd connection limit?)"),
    (_pyez("ConnectError", orig=SSHError("Negotiation failed: Error reading SSH protocol banner")), 15.0,
     "no SSH banner from 10.0.0.1:830 within 10s"),
    (_pyez("ConnectRefusedError", SSHUnknownHostError("Unknown host key [ab:cd] for [10.0.0.1]")), 0.3,
     "host key verification failed for 10.0.0.1:830: not in ~/.ssh/known_hosts, or changed (HSSH_NETCONF_HOSTKEY=yes); nothing was sent"),
    (_pyez("ConnectAuthError", AuthenticationError("Authentication failed")), 0.5,
     "authentication failed for u at 10.0.0.1:830"),
    (_pyez("ConnectUnknownHostError", socket.gaierror(-2, "Name or service not known")), 0.0,
     "cannot resolve 10.0.0.1"),
    (_pyez("ConnectError", orig=SSHError("Negotiation failed: Incompatible ssh peer (no acceptable kex algorithm)")), 0.4,
     "SSH negotiation with 10.0.0.1:830 failed: Incompatible ssh peer (no acceptable kex algorithm)"),
    # #114 G4: the banner came and the key exchange did not finish, by the deadline or a drop
    (_pyez("ConnectError", orig=SSHError("Negotiation failed: the banner came, but key exchange did not finish")), 10.0,
     "no SSH session to 10.0.0.1:830 within 10s: the banner came, but key exchange did not finish"),
    (_pyez("ConnectRefusedError", SSHError("Negotiation failed: the banner came, but key exchange did not finish")), 0.2,
     "10.0.0.1:830 dropped the session before login after 0.2s (the banner came, but key exchange did not finish)"),
    # #114 G2: HSSH_NETCONF_HOSTKEY=yes reads ~/.ssh/known_hosts as the ssh transport does
    (_pyez("ConnectError", orig=_Ctx("its key is marked @revoked in /h/.ssh/known_hosts")), 0.3,
     "host key verification failed for 10.0.0.1:830: its key is marked @revoked in /h/.ssh/known_hosts; nothing was sent"),
    (_pyez("ConnectError", orig=ValueError("/h/.ssh/known_hosts: malformed known_hosts line 2: '@revoked *' "
                                           "(expected host, key type and key); fix or remove it")), 0.0,
     "/h/.ssh/known_hosts: malformed known_hosts line 2: '@revoked *' (expected host, key type and key); fix or remove it"),
])
def test_connect_reason_reads_the_exception_pyez_was_handling(exc, elapsed, expect):
    assert netconf._connect_reason(exc, "10.0.0.1", "u", 830, 10, elapsed) == expect


@pytest.mark.parametrize("os_error, expect", [
    (ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"), "connection refused by 10.0.0.1:830"),
    (OSError(errno.EHOSTUNREACH, "No route to host"), "no route to host 10.0.0.1:830"),
    (OSError(errno.ENETUNREACH, "Network is unreachable"), "network is unreachable for 10.0.0.1:830"),
    (socket.timeout("timed out"), "TCP connect to 10.0.0.1:830 timed out after 3s"),
    (OSError(errno.ETIMEDOUT, "Connection timed out"), "TCP connect to 10.0.0.1:830 timed out after 3s"),
    (OSError(errno.EPERM, "Operation not permitted"), "TCP connect to 10.0.0.1:830 failed: Operation not permitted"),
])
def test_the_tcp_connect_is_said_as_the_os_answered_it(os_error, expect):
    """#126: ncclient says "Could not open socket" whatever happened and PyEZ
    calls anything under 3 s refused, so an on-link address nobody answers
    ARP for was "connection refused ... (nothing listening, or no route)".
    The socket ncclient opens now keeps the OS's answer, and that is said."""
    exc = _pyez("ConnectRefusedError", SSHError("Could not open socket to 10.0.0.1:830"))
    assert netconf._connect_reason(exc, "10.0.0.1", "u", 830, 30, 0.01, connect_timeout=3, os_error=os_error) == expect


@pytest.mark.parametrize("exc, os_error, expect", [
    # the socket refused (ncclient swallows it and says "Could not open socket")
    (_pyez("ConnectRefusedError", SSHError("Could not open socket to 10.0.0.1:830")),
     OSError(errno.EMFILE, "Too many open files"), "ulimit -n 1024"),
    (_pyez("ConnectRefusedError", SSHError("Could not open socket to 10.0.0.1:830")),
     OSError(errno.ENFILE, "Too many open files in system"), "the system's file table is full: fs.file-max, not ulimit -n"),
    # ncclient's selector or paramiko's pipe refused after the socket
    (_pyez("ConnectError", orig=OSError(errno.EMFILE, "Too many open files")), None, "ulimit -n 1024"),
])
def test_out_of_descriptors_is_said_as_the_local_open_file_limit(monkeypatch, exc, os_error, expect):
    """#147: ncclient swallows what the socket's creation raised, so a
    process out of descriptors read "connection refused by HOST:PORT
    (nothing listening, or no route)" for a port that was listening: a
    failure tried once, and a 120 s cooldown under --safety-file. It is
    this machine's open-file limit, and said so."""
    monkeypatch.setattr(netconf.limits, "open_file_limit", lambda: 1024)
    said = netconf._connect_reason(exc, "10.0.0.1", "u", 830, 30, 0.01, connect_timeout=3, os_error=os_error)
    assert said == (f"local open-file limit reached ({expect}): this machine had no descriptor for a session to "
                    "10.0.0.1:830; nothing was sent")


def test_a_socket_the_open_file_limit_refuses_is_a_local_error_not_a_refused_connection(monkeypatch, tmp_path):
    """The socket ncclient opens keeps what refused its creation, as it
    keeps what the OS answered its connect (#126): with PyEZ and ncclient
    as they are, EMFILE there is the local limit, a NotAppliedError and a
    LocalError (no cooldown), and permanent (not tried again)."""
    pytest.importorskip("jnpr.junos")
    from hssh.errors import LocalError
    from hssh.runner import _is_local_error
    monkeypatch.setenv("HOME", str(tmp_path))
    real_init = socket.socket.__init__

    def no_descriptor(self, *args, **kwargs):
        if isinstance(self, netconf._ConnectSocket):
            raise OSError(errno.EMFILE, "Too many open files")
        real_init(self, *args, **kwargs)
    monkeypatch.setattr(socket.socket, "__init__", no_descriptor)
    with pytest.raises(NotAppliedError) as failed:
        netconf.show("127.0.0.1", "u", "p", "show version", 5, 5, port=9)
    said = str(failed.value)
    assert said.startswith("NETCONF connect failed: local open-file limit reached (ulimit -n"), said
    assert said.endswith("this machine had no descriptor for a session to 127.0.0.1:9; nothing was sent")
    assert "refused" not in said
    assert isinstance(failed.value, LocalError) and _is_local_error(failed.value)
    assert is_permanent_failure(failed.value) and is_connect_failure(failed.value)


def test_out_of_descriptors_is_tried_once_and_cools_no_device(monkeypatch, tmp_path):
    """Said as "connection refused", the device was cooled 120 s under
    --safety-file for this machine's limit. A local error now: one attempt,
    and the gate lets the device through again."""
    from hssh import runner
    from hssh.core import Target
    from hssh.safety import SafetyGate
    opened = []

    class Dev:
        def __init__(self, **kw):
            self.kw = kw

        def open(self):
            opened.append(1)
            try:
                raise OSError(errno.EMFILE, "Too many open files")      # ncclient's selector, say
            except OSError as e:
                err = netconf.ConnectError("ConnectError(10.0.0.1)")
                err._orig = e
                raise err

        def close(self):
            pass
    monkeypatch.setattr(netconf, "AVAILABLE", True)
    monkeypatch.setattr(netconf, "JunosDevice", Dev)
    gate = SafetyGate(safety_file=str(tmp_path / "safety.json"))
    result = runner.run_for_target(t=Target("R1", "10.0.0.1", "junos"), transport="junos", mode="show",
                                   show_cmd="show version", edit_cmd=None, config_dir=None, broadcast_file=None,
                                   user="u", passwd="p", session_timeout=10, command_timeout=10, dry_run=False,
                                   commit_confirmed=None, save_dir=None, quiet=True, max_attempts=3,
                                   safety_gate=gate)
    assert not result.ok and opened == [1]
    assert result.error.startswith("NETCONF connect failed: local open-file limit reached (ulimit -n")
    assert gate.check_device("10.0.0.1", 830, login=False) == (True, "ok")


def test_open_says_a_descriptor_pyez_cannot_have_for_the_ssh_config_as_the_limit(monkeypatch):
    from hssh.errors import LocalError

    class Dev:
        def __init__(self, **kw):
            raise OSError(errno.EMFILE, "Too many open files", "/home/u/.ssh/config")
    monkeypatch.setattr(netconf, "JunosDevice", Dev)
    monkeypatch.setattr(netconf.limits, "open_file_limit", lambda: 256)
    with pytest.raises(LocalError, match=r"^NETCONF connect failed: local open-file limit reached \(ulimit -n "
                                         r"256\): this machine had no descriptor for a session to 10\.0\.0\.1:830"):
        netconf._open("10.0.0.1", "u", "p", 10, 30, None)


def test_a_banner_that_never_came_is_told_from_a_server_that_closed_first():
    """paramiko says "Error reading SSH protocol banner" for both; what it
    was handling, a timeout or an EOF, tells them apart where the clock
    alone guessed (#126)."""
    def negotiation(inner):
        paramiko_said = _Ctx("Error reading SSH protocol banner")
        paramiko_said.__context__ = inner
        ncclient_said = SSHError("Negotiation failed: Error reading SSH protocol banner")
        ncclient_said.__context__ = paramiko_said
        return _pyez("ConnectError", orig=ncclient_said)
    assert netconf._connect_reason(negotiation(socket.timeout()), "10.0.0.1", "u", 830, 30, 0.3,
                                   connect_timeout=3) == "no SSH banner from 10.0.0.1:830 within 3s"
    assert netconf._connect_reason(negotiation(EOFError()), "10.0.0.1", "u", 830, 30, 2.9, connect_timeout=3) == \
        "10.0.0.1:830 dropped the session before login after 2.9s (sshd connection limit?)"


def test_open_raises_a_connect_phase_that_ran_out_as_a_connect_timeout(monkeypatch):
    """The class says it as well as the words: nothing was sent, try again."""
    class Dev:
        def __init__(self, **kw):
            self.kw = kw

        def open(self):
            # what the socket ncclient opened left behind: no answer in time
            netconf._DEADLINE.connect_error = socket.timeout("timed out")
            try:
                raise SSHError("Could not open socket to 10.0.0.1:830")
            except SSHError:
                raise netconf.ConnectError("ConnectRefusedError(10.0.0.1)")

        def close(self):
            pass
    made = []
    monkeypatch.setattr(netconf, "JunosDevice", lambda **kw: made.append(kw) or Dev(**kw))
    with pytest.raises(ConnectTimeoutError, match=r"^NETCONF connect failed: TCP connect to 10\.0\.0\.1:830 "
                                                  r"timed out after 2s$"):
        netconf._open("10.0.0.1", "u", "p", 2, 30, None, connect_timeout=5)    # never more than the session timeout
    assert made[0]["conn_open_timeout"] == 2
    assert netconf._DEADLINE.at is None and netconf._DEADLINE.connect_at is None
    with pytest.raises(ConnectTimeoutError):
        netconf._open("10.0.0.1", "u", "p", 30, 30, None, connect_timeout=5)
    # ncclient waits as long for the router's hello (PyEZ's console on port
    # 23 for its whole login): the session timeout; the socket holds the TCP
    # connect to the connect phase.
    assert made[1]["conn_open_timeout"] == 30


def test_an_ipv6_literal_is_named_as_the_reason():
    exc = _pyez("ConnectUnknownHostError", socket.gaierror(-2, "Name or service not known"))
    assert netconf._connect_reason(exc, "[2001:db8::1]", "u", 830, 10, 0.0) == \
        "cannot resolve [2001:db8::1] (an IPv6 literal is not accepted by this PyEZ/ncclient; use a name)"


def test_open_wraps_pyez_host_validation_as_a_connect_failure(monkeypatch):
    class Dev:
        def __init__(self, **kw):
            raise ValueError("Invalid 'host' value 'fd00::1': only alphanumerics, dots, underscores, "
                             "hyphens, or bracketed IPv6 literals are permitted.")
    monkeypatch.setattr(netconf, "JunosDevice", Dev)
    with pytest.raises(NotAppliedError, match="NETCONF connect failed: PyEZ does not accept host 'fd00::1'"):
        netconf._open("fd00::1", "u", "p", 10, 30, None)


def test_open_reports_the_reason_and_closes_the_device(monkeypatch):
    closed = []

    class Dev:
        def __init__(self, **kw):
            self.kw = kw

        def open(self):
            try:
                raise SSHError("Could not open socket to 10.0.0.1:830")
            except SSHError:
                raise netconf.ConnectError("ConnectRefusedError(10.0.0.1)")

        def close(self):
            closed.append(1)
    monkeypatch.setattr(netconf, "JunosDevice", Dev)
    with pytest.raises(NotAppliedError, match=r"NETCONF connect failed: .*10\.0\.0\.1:830"):
        netconf._open("10.0.0.1", "u", "p", 10, 30, None)
    assert closed == [1]


# --- the generic transport: a pin file that cannot be read, nothing to log in with --

def test_a_malformed_known_hosts_line_is_refused_before_connecting(monkeypatch, tmp_path):
    paramiko = pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(tmp_path)))
    (tmp_path / ".h-ssh").mkdir(mode=0o700)
    (tmp_path / ".h-ssh" / "known_hosts").write_text("r1 ssh-ed25519 not-base64!!\n")
    connected = []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda self, **kw: connected.append(kw))
    with pytest.raises(ValueError, match=r"\.h-ssh/known_hosts: malformed known_hosts line 1: 'r1 ssh-ed25519 not-base64!!' "
                                         r"\(the key is not base64\); fix or remove it"):
        ssh._connect("10.0.0.1", "u", "p", 5, None)
    assert connected == []
    assert is_permanent_failure(ValueError("x: malformed known_hosts line 1: 'r1' (expected host, key type and key); "
                                           "fix or remove it"))


def test_no_credential_at_all_is_said_in_words(monkeypatch, tmp_path):
    paramiko = pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(tmp_path)))

    def connect(self, **kw):
        raise paramiko.SSHException("No authentication methods available")
    monkeypatch.setattr(paramiko.SSHClient, "connect", connect)
    with pytest.raises(RuntimeError, match="No authentication methods available for u@10.0.0.1: no password was given"):
        ssh._connect("10.0.0.1", "u", None, 5, None)


# --- M8: Ctrl-C during a connect is interrupted, not a failed device --------------

def _main_cancelled_after(delay):
    async def go():
        asyncio.get_running_loop().call_later(delay, asyncio.current_task().cancel)
        return await cli.main()
    return asyncio.run(go())


class _CtrlC:
    """cli.main() with a Ctrl-C a fake driver presses from inside its call:
    the call is in flight when it comes, however slowly the run got there,
    and runs out on its own half a second after."""

    def run(self):
        async def go():
            self.loop, self.main = asyncio.get_running_loop(), asyncio.current_task()
            return await cli.main()
        return asyncio.run(go())

    def press(self):
        self.loop.call_soon_threadsafe(self.main.cancel)
        time.sleep(0.5)


def _cli_env(monkeypatch, driver, name="junos@netconf"):
    monkeypatch.setitem(drivers.MODULES, name, driver)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")


def test_ctrl_c_during_a_connect_is_interrupted_not_failed(monkeypatch, capsys, tmp_path):
    seen = []

    def show(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        seen.append(host)
        time.sleep(0.8)                  # the connect runs out on its own after Ctrl-C
        raise NotAppliedError("NETCONF connect failed: TCP connect to %s:830 timed out after 10s" % host)
    _cli_env(monkeypatch, types.SimpleNamespace(AVAILABLE=True, show=show))
    log = tmp_path / "run.jsonl"
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u",
                                      "--target", "R1:10.0.0.1:junos", "--target", "R2:10.0.0.2:junos",
                                      "--workers", "1", "-sC", "show version", "--log", str(log)])
    rc = _main_cancelled_after(0.3)
    out, err = capsys.readouterr()
    # A connect that ran out is tried again (#126), but not once the
    # operator has stopped the run: its attempt in flight was its last.
    assert rc == 130 and seen == ["10.0.0.1"] and "RETRY" not in out
    assert "R1" in out and "INTERRUPTED" in out and "FAIL" not in out
    assert "Interrupted. Completed 0 of 2 device(s); 1 interrupted while connecting." in err
    summary = json.loads(err.split("[h-ssh] ", 1)[1].splitlines()[0])
    assert summary["targets"] == 1 and summary["ok"] == 0 and summary["fail"] == 0 and summary["interrupted"] == 1
    line = json.loads(log.read_text().splitlines()[0])
    assert line["device"] == "R1" and line["ok"] is False and line["interrupted"] is True
    assert line["error"].startswith("interrupted while connecting: NETCONF connect failed")


def test_an_edit_whose_connect_runs_out_after_ctrl_c_is_not_sent_again(monkeypatch, capsys):
    """#126 made a connect that ran out a NotAppliedError, the one failure an
    edit is tried again on: one that ran out after Ctrl-C was tried again
    and committed after the operator had stopped the run ("R1 RETRY 1/2",
    then "R1 OK COMMIT OK"). The attempt in flight runs out; no other starts."""
    calls, ctrl_c = [], _CtrlC()

    def edit(host, user, passwd, payload, st, ct, *a, **kw):
        calls.append(host)
        if len(calls) > 1:
            return "COMMIT OK\n"
        ctrl_c.press()                   # with this connect under way, which then runs out
        raise ConnectTimeoutError(f"NETCONF connect failed: TCP connect to {host}:830 timed out after 3s")
    _cli_env(monkeypatch, types.SimpleNamespace(AVAILABLE=True, edit=edit))
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "-y",
                                      "--target", "R1:10.0.0.1:junos", "--target", "R2:10.0.0.2:junos",
                                      "--workers", "1", "-eC", "set system host-name x"])
    rc = ctrl_c.run()
    out, err = capsys.readouterr()
    assert rc == 130 and calls == ["10.0.0.1"]
    assert "INTERRUPTED" in out and "RETRY" not in out and "COMMIT OK" not in out
    assert "Interrupted. Completed 0 of 2 device(s); 1 interrupted while connecting." in err


def test_a_show_diff_preview_whose_connect_runs_out_after_ctrl_c_is_not_tried_again(monkeypatch, capsys):
    """The --show-diff preview is a dry run per device before the question.
    Ctrl-C there did not stop the retries the run itself stops: a preview
    whose connect ran out was tried twice more, each a new session that
    locks, loads and discards the candidate, after the operator stopped."""
    calls, ctrl_c = [], _CtrlC()

    def edit(host, user, passwd, payload, st, ct, *a, **kw):
        calls.append(host)
        if len(calls) == 1:
            ctrl_c.press()               # with this preview's connect under way, which then runs out
        raise ConnectTimeoutError(f"NETCONF connect failed: TCP connect to {host}:830 timed out after 3s")
    _cli_env(monkeypatch, types.SimpleNamespace(AVAILABLE=True, edit=edit))
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "-y", "--show-diff",
                                      "--target", "R1:10.0.0.1:junos", "-eC", "set system host-name x"])
    with pytest.raises(asyncio.CancelledError):      # the h-ssh entry point makes this exit 130
        ctrl_c.run()
    out, err = capsys.readouterr()
    assert calls == ["10.0.0.1"]
    assert "RETRY" not in out + err


def test_an_edit_that_applied_lines_before_a_connect_ran_out_is_failed_not_interrupted(monkeypatch, capsys):
    """openssh sends a none-dialect edit a line an ssh. A later line whose
    connect ran out after Ctrl-C was "interrupted while connecting", which
    says nothing reached the device, and was counted with the interrupted:
    the lines before it had been applied."""
    ctrl_c = _CtrlC()

    def edit(host, user, passwd, payload, st, ct, *a, **kw):
        ctrl_c.press()                   # with line 2's connect under way
        raise RuntimeError(f"TCP connect to {host}:22 timed out after 3s; the 1 line(s) before it were applied")
    _cli_env(monkeypatch, types.SimpleNamespace(AVAILABLE=True, edit=edit), "none@openssh")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "-y",
                                      "--target", "R1:10.0.0.1:openssh", "-eC", "set a 1"])
    rc = ctrl_c.run()
    out, err = capsys.readouterr()
    assert rc == 130 and "INTERRUPTED" not in out and "interrupted while connecting" not in out + err
    assert "ERROR: TCP connect to 10.0.0.1:22 timed out after 3s; the 1 line(s) before it were applied" in out
    summary = json.loads(err.split("[h-ssh] ", 1)[1].splitlines()[0])
    assert summary["fail"] == 1 and summary["interrupted"] == 0


def test_ctrl_c_after_the_session_was_up_keeps_a_real_failure(monkeypatch, capsys):
    def show(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        time.sleep(0.8)
        raise RuntimeError("RpcTimeoutError(host: %s, cmd: get-software-information, timeout: 20)" % host)
    _cli_env(monkeypatch, types.SimpleNamespace(AVAILABLE=True, show=show))
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u",
                                      "--target", "R1:10.0.0.1:junos", "--workers", "1", "--retries", "0",
                                      "-sC", "show version"])
    rc = _main_cancelled_after(0.3)
    out, err = capsys.readouterr()
    assert rc == 130 and "FAIL" in out
    assert "Interrupted. Completed 1 of 1 device(s)." in err
    summary = json.loads(err.split("[h-ssh] ", 1)[1].splitlines()[0])
    assert summary["fail"] == 1 and summary["interrupted"] == 0
