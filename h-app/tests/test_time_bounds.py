"""#66: --session-timeout and --workers bound everything that touches a
device, the pre-flight included; a router that accepts TCP and then says
nothing costs the session timeout, not a library default."""
import asyncio
import os
import socket
import stat
import sys
import threading
import time
import types
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, drivers
from hssh.errors import NotAppliedError
from hssh.runner import is_connect_failure, is_permanent_failure
from hssh.transports import netconf, openssh, ssh


# --- H1: the pre-flight runs like the run ------------------------------------------

def _edit_cli(monkeypatch, capsys, probe, n, extra):
    driver = types.SimpleNamespace(AVAILABLE=True,
                                   edit=lambda host, user, passwd, payload, st, ct, *a, **kw: "COMMIT OK\n")
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", driver)
    monkeypatch.setattr(cli, "check_reachability", probe)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    targets = [a for i in range(n) for a in ("--target", f"R{i}:10.0.0.{i + 1}:junos")]
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "-y",
                                      *targets, "-eC", "set system host-name x", *extra])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    return rc, out, err


def test_preflight_probes_workers_at_a_time_with_the_session_timeout(monkeypatch, capsys):
    state = {"now": 0, "peak": 0, "timeouts": set()}

    async def probe(target, timeout=2):
        state["timeouts"].add(timeout)
        state["now"] += 1
        state["peak"] = max(state["peak"], state["now"])
        await asyncio.sleep(0.02)
        state["now"] -= 1
        return (target.name, True, "reachable")
    rc, out, err = _edit_cli(monkeypatch, capsys, probe, 9, ["--workers", "3", "--session-timeout", "7"])
    assert rc == 0, err
    assert state["peak"] == 3 and state["timeouts"] == {7}
    assert "Pre-flight check: Validating device reachability (3 at a time, 7s each)" in out


def test_a_probe_that_fails_once_is_tried_again_before_the_device_is_called_unreachable(monkeypatch, capsys):
    calls = {}

    async def probe(target, timeout=2):
        calls[target.name] = calls.get(target.name, 0) + 1
        if target.name == "R1" and calls["R1"] == 1:
            return (target.name, False, "connection timeout")      # lost in the burst
        if target.name == "R2":
            return (target.name, False, "port 830 not responding")  # really down
        return (target.name, True, "reachable")
    rc, out, err = _edit_cli(monkeypatch, capsys, probe, 3, ["--workers", "8"])
    assert rc == 2 and calls == {"R0": 1, "R1": 2, "R2": 2}
    assert "[PASS] R1" in out and "[FAIL] R2" in out and "1 device(s) unreachable: R2" in out


# --- H3: the junos session set-up has one deadline ---------------------------------

def _silent_listener(greeting=b""):
    """Accepts, says `greeting` (nothing by default), and then nothing."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def run():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.sendall(greeting)
            time.sleep(60)
    threading.Thread(target=run, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_paramiko_timeouts_answer_with_what_is_left_of_the_deadline():
    pytest.importorskip("paramiko")
    a, b = socket.socketpair()
    try:
        t = netconf._DeadlineTransport(a)
        assert (t.banner_timeout, t.handshake_timeout, t.auth_timeout) == (15, 15, 30)   # no deadline: paramiko's own
        t.banner_timeout = 4                       # paramiko's own assignment still lands
        assert t.banner_timeout == 4
        netconf._DEADLINE.at = time.monotonic() + 2.0
        try:
            t = netconf._DeadlineTransport(a)        # the deadline is taken at construction, on this thread
        finally:
            netconf._DEADLINE.at = None
        assert 1.5 < t.banner_timeout <= 2.0 and 1.5 < t.handshake_timeout <= 2.0 and 1.5 < t.auth_timeout <= 2.0
        result = {}
        threading.Thread(target=lambda: result.setdefault("t", t.banner_timeout)).start()
        time.sleep(0.05)
        assert 1.0 < result["t"] <= 2.0            # read on another thread, as paramiko does
        t._hssh_deadline = time.monotonic() - 5
        assert t.banner_timeout == 0.1             # past the deadline: give up at once
    finally:
        a.close()
        b.close()


def test_ncclient_builds_the_deadline_transport():
    ncssh = pytest.importorskip("ncclient.transport.ssh")
    assert ncssh.paramiko.Transport is netconf._DeadlineTransport
    assert ncssh.paramiko.SSHException is netconf._paramiko.SSHException      # everything else as it was


def test_a_router_that_accepts_tcp_and_says_nothing_costs_the_session_timeout():
    pytest.importorskip("jnpr.junos")
    srv, port = _silent_listener()
    try:
        started = time.monotonic()
        with pytest.raises(NotAppliedError, match=rf"NETCONF connect failed: no SSH banner from 127.0.0.1:{port} within 2s"):
            netconf._open("127.0.0.1", "u", "p", 2, 30, port)
        elapsed = time.monotonic() - started
        assert elapsed < 3.5, f"{elapsed:.1f}s: paramiko's 15 s banner timeout won"
        assert netconf._DEADLINE.at is None
    finally:
        srv.close()


# --- #114 G4: the banner, then a key exchange that does not finish ---------------

BANNER = b"SSH-2.0-OpenSSH_9.6\r\n"


def _banner_then_close():
    """Says the banner, reads what the client sends (its own banner and its
    key exchange init), and closes."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def run():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.sendall(BANNER)
            conn.settimeout(0.3)
            try:
                while conn.recv(65536):
                    pass
            except OSError:
                pass
            conn.close()
    threading.Thread(target=run, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_a_key_exchange_that_never_finishes_costs_the_session_timeout_and_says_so(monkeypatch, tmp_path):
    """The ssh transport said 'No existing session', which no marker knows,
    so it was retried twice; above 15 s it was an empty EOFError at
    paramiko's 15 s, and the FAIL line and the --json error were empty."""
    pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    srv, port = _silent_listener(BANNER)
    try:
        started = time.monotonic()
        with pytest.raises(RuntimeError) as failed:
            ssh._connect("127.0.0.1", "u", "p", 1, port)
        elapsed = time.monotonic() - started
    finally:
        srv.close()
    assert str(failed.value) == "no SSH session to 127.0.0.1 within 1s: the banner came, but key exchange did not finish"
    assert elapsed < 3, f"{elapsed:.1f}s"
    assert is_connect_failure(failed.value) and is_permanent_failure(failed.value)


def test_a_server_that_closes_in_the_key_exchange_is_named_and_still_retried(monkeypatch, tmp_path):
    """An empty EOFError too: retried with nothing in the RETRY line's
    parentheses. A drop may pass, so it is still retried."""
    pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    srv, port = _banner_then_close()
    try:
        with pytest.raises(RuntimeError, match=r"^127\.0\.0\.1 dropped the session before login after \d+\.\ds "
                                               r"\(the banner came, but key exchange did not finish\)$") as failed:
            ssh._connect("127.0.0.1", "u", "p", 10, port)
    finally:
        srv.close()
    assert is_connect_failure(failed.value) and not is_permanent_failure(failed.value)


def test_a_router_that_sends_the_banner_and_then_nothing_is_named_on_junos_too():
    """PyEZ rendered paramiko's bare EOFError as `ConnectError for HOST:PORT`
    with nothing after it."""
    pytest.importorskip("jnpr.junos")
    srv, port = _silent_listener(BANNER)
    try:
        started = time.monotonic()
        with pytest.raises(NotAppliedError, match=rf"^NETCONF connect failed: no SSH session to 127\.0\.0\.1:{port} "
                                                  r"within 2s: the banner came, but key exchange did not finish$"):
            netconf._open("127.0.0.1", "u", "p", 2, 30, port)
        assert time.monotonic() - started < 3.5
    finally:
        srv.close()


# --- L9: the openssh transport keeps its own clock ---------------------------------

@pytest.fixture
def fake_ssh(tmp_path, monkeypatch):
    """A stub ssh that logs what FAKE_SSH_LOG says to the -E file, sleeps
    FAKE_SSH_SLEEP, and exits FAKE_SSH_RC."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "ssh"
    script.write_text(
        "#!/bin/sh\n"
        'while [ $# -gt 0 ]; do case "$1" in -E) shift; LOG="$1";; esac; shift; done\n'
        'if [ -n "$LOG" ]; then printf "%b" "$FAKE_SSH_LOG" >> "$LOG"; fi\n'
        'if [ -n "$FAKE_SSH_STDERR" ]; then echo "$FAKE_SSH_STDERR" >&2; fi\n'
        'echo "device output"\n'
        'sleep "${FAKE_SSH_SLEEP:-0}"\n'
        'exit "${FAKE_SSH_RC:-0}"\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(openssh, "AVAILABLE", True)
    for var in ("FAKE_SSH_LOG", "FAKE_SSH_STDERR", "FAKE_SSH_SLEEP", "FAKE_SSH_RC"):
        monkeypatch.delenv(var, raising=False)
    return script


def test_no_session_within_the_session_timeout_is_abandoned_then(fake_ssh, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_SLEEP", "5")
    monkeypatch.setenv("FAKE_SSH_LOG", "debug1: Connecting to h port 22.\\ndebug1: Connection established.\\n")
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="no SSH session to h within 1s: connected, but no SSH banner came"):
        openssh.show("h", "u", None, "show version", 1, 10)
    assert time.monotonic() - started < 2.5
    assert is_permanent_failure(RuntimeError("no SSH session to h within 1s")) \
        and is_connect_failure("no SSH session to h within 1s")


def test_a_kex_hang_after_the_banner_is_named(fake_ssh, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_SLEEP", "5")
    monkeypatch.setenv("FAKE_SSH_LOG", "debug1: Connection established.\\ndebug1: Remote protocol version 2.0, remote software version OpenSSH_9.6\\n")
    with pytest.raises(RuntimeError, match="the banner came, but key exchange or authentication did not finish"):
        openssh.show("h", "u", None, "show version", 1, 10)


def test_the_command_timeout_starts_when_the_session_is_up(fake_ssh, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_SLEEP", "5")
    monkeypatch.setenv("FAKE_SSH_LOG", "Authenticated to h ([10.0.0.1]:22) using publickey.\\ndebug1: Entering interactive session.\\n")
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="Command timed out after 1s: show version"):
        openssh.show("h", "u", None, "show version", 3, 1)
    assert time.monotonic() - started < 2.5          # 1 s after the session, not session + command


def test_a_multiplexed_command_counts_as_a_session_too(fake_ssh, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_SLEEP", "5")
    monkeypatch.setenv("FAKE_SSH_LOG", "debug1: mux_client_request_session: master session id: 2\\n")
    with pytest.raises(RuntimeError, match="Command timed out after 1s"):
        openssh.show("h", "u", None, "show version", 3, 1)


def test_ssh_diagnostics_come_from_its_log_and_device_stderr_stays_the_devices(fake_ssh, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_LOG", "OpenSSH_9.6p1, OpenSSL 3.0.13\\nWarning: Permanently added 'h' (ED25519) to the list of known hosts.\\ndebug1: Exit status 0\\nTransferred: sent 1, received 2, in 0.1 seconds\\n")
    monkeypatch.setenv("FAKE_SSH_STDERR", "warning from the device")
    out = openssh.show("h", "u", None, "show version", 3, 3)
    assert "device output" in out and "STDERR:\nwarning from the device" in out
    assert "Permanently added" not in out and "Transferred" not in out
    monkeypatch.setenv("FAKE_SSH_LOG", "u@h: Permission denied (publickey,password).\\n")
    monkeypatch.setenv("FAKE_SSH_RC", "255")
    monkeypatch.delenv("FAKE_SSH_STDERR")
    with pytest.raises(RuntimeError, match="Authentication failed"):
        openssh.show("h", "u", None, "show version", 3, 3)


def test_the_log_file_is_removed(fake_ssh, monkeypatch, tmp_path):
    monkeypatch.setattr(openssh.tempfile, "tempdir", str(tmp_path))
    openssh.show("h", "u", None, "show version", 3, 3)
    assert not [p for p in tmp_path.iterdir() if p.name.startswith("hssh-ssh-")]
