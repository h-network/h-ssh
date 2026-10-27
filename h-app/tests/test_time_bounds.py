"""#66: --session-timeout and --workers bound everything that touches a
device; a router that accepts TCP and then says nothing costs the session
timeout, not a library default. #126: the TCP connect and the SSH banner
have --connect-timeout, on all three SSH transports, and a connect phase
that runs out is named and tried again. #127: the probe before the run
gives its TCP connect and its banner --connect-timeout each, runs 100 boxes
at a time whatever --workers says, and tries a box that failed once more."""
import asyncio
import errno
import inspect
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import types
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, drivers, probe, runner
from hssh.core import Target
from hssh.errors import ConnectTimeoutError, NotAppliedError
from hssh.runner import is_connect_failure, is_connect_timeout, is_permanent_failure
from hssh.transports import netconf, openssh, ssh, telnet


# --- #127: the probe runs within --connect-timeout, 100 at a time --------------------

def _edit_cli(monkeypatch, capsys, attempt, n, extra):
    """An edit of n routers through main(), each try of the probe answered
    by `attempt`; nothing is contacted."""
    driver = types.SimpleNamespace(AVAILABLE=True,
                                   edit=lambda host, user, passwd, payload, st, ct, *a, **kw: "COMMIT OK\n")
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", driver)
    monkeypatch.setattr(probe, "attempt", attempt)
    monkeypatch.setattr(probe, "RETRY_PAUSE", 0.01)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    targets = [a for i in range(n) for a in ("--target", f"R{i}:10.0.0.{i + 1}:junos")]
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "-y",
                                      *targets, "-eC", "set system host-name x", *extra])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    return rc, out, err


def _live(host, port):
    return probe.Answer(probe.LIVE, connect_ms=0.3, banner_ms=7.0, banner="SSH-2.0-OpenSSH_9.6")


def test_the_probe_runs_100_at_a_time_whatever_the_workers_within_the_connect_timeout(monkeypatch, capsys):
    """The old pre-flight probed --workers at a time with --session-timeout
    for each wait (H1); the probe has a ceiling of its own and the connect
    timeout, never more than the session timeout, as the run's connect."""
    state = {"now": 0, "peak": 0, "seconds": set()}

    async def attempt(host, port, banner, seconds):
        state["seconds"].add(seconds)
        state["now"] += 1
        state["peak"] = max(state["peak"], state["now"])
        await asyncio.sleep(0.2)
        state["now"] -= 1
        return _live(host, port)
    rc, out, err = _edit_cli(monkeypatch, capsys, attempt, 150, ["--workers", "3", "--connect-timeout", "7"])
    assert rc == 0, err
    assert state["peak"] == 100 and state["seconds"] == {7}
    assert "Probe: 150 box(es) in " in out and ": 150 live" in out
    state.update(peak=0, seconds=set())
    rc, out, err = _edit_cli(monkeypatch, capsys, attempt, 3, ["--session-timeout", "5", "--connect-timeout", "7"])
    assert rc == 0, err
    assert state["peak"] == 3 and state["seconds"] == {5}


def test_a_probe_that_fails_once_is_tried_again_before_the_box_is_called_dead(monkeypatch, capsys):
    calls = {}

    async def attempt(host, port, banner, seconds):
        calls[host] = calls.get(host, 0) + 1
        if host == "10.0.0.2" and calls[host] == 1:
            return probe.Answer(probe.TIMED_OUT, "TCP connect to 10.0.0.2:830 timed out after 3s")   # lost in the burst
        if host == "10.0.0.3":
            return probe.Answer(probe.REFUSED, "connection refused by 10.0.0.3:830")                  # really down
        return _live(host, port)
    rc, out, err = _edit_cli(monkeypatch, capsys, attempt, 3, ["--workers", "8"])
    assert rc == 2 and calls == {"10.0.0.1": 1, "10.0.0.2": 2, "10.0.0.3": 2}
    assert "R2               (10.0.0.3) refused (connection refused by 10.0.0.3:830)" in out
    assert "1 device(s) unreachable: R2" in out and "R1" not in out.split("unreachable", 1)[1]


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
    """Connected, and no banner: since #126 the connect phase's clock, which
    never gets more than the session timeout, is the one that says so."""
    monkeypatch.setenv("FAKE_SSH_SLEEP", "5")
    monkeypatch.setenv("FAKE_SSH_LOG", "debug1: Connecting to h port 22.\\ndebug1: Connection established.\\n")
    started = time.monotonic()
    with pytest.raises(ConnectTimeoutError, match="^no SSH banner from h:22 within 1s$"):
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


# --- #126: the connect phase has --connect-timeout -----------------------------------

def _full_listener():
    """A port whose accept queue is full: the kernel drops the next SYN, so a
    TCP connect to it gets no answer at all, as one to a blackholed address.
    Returns (the sockets to close, the port)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(0)
    port = srv.getsockname()[1]
    held = [srv]
    for _ in range(16):
        filler = socket.socket()
        filler.setblocking(False)
        try:
            filler.connect(("127.0.0.1", port))
        except BlockingIOError:
            pass
        held.append(filler)
        probe = socket.socket()
        probe.settimeout(0.3)
        try:
            probe.connect(("127.0.0.1", port))
        except TimeoutError:
            probe.close()
            return held, port                   # no answer: the queue is full
        except OSError as e:
            probe.close()
            for s in held:
                s.close()
            pytest.skip(f"this kernel answers a connect to a full accept queue ({e})")
        held.append(probe)
    for s in held:
        s.close()
    pytest.skip("the accept queue never filled")


def _refused_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def listening():
    """listening(kind) -> a port on 127.0.0.1, closed after the test:
    "silent" accepts and never says a word, "full" never completes the TCP
    handshake, "refused" has nobody listening."""
    opened = []

    def make(kind):
        if kind == "silent":
            srv, port = _silent_listener()
            opened.append(srv)
            return port
        if kind == "full":
            held, port = _full_listener()
            opened.extend(held)
            return port
        return _refused_port()
    yield make
    for s in opened:
        s.close()


@pytest.fixture
def real_ssh(tmp_path, monkeypatch):
    """The OpenSSH client on PATH, behind a wrapper that keeps the user's
    ~/.ssh/config out of it; skipped where there is none."""
    found = shutil.which("ssh")
    if found is None:
        pytest.skip("no ssh binary on PATH")
    bindir = tmp_path / "realbin"
    bindir.mkdir()
    wrapper = bindir / "ssh"
    wrapper.write_text(f'#!/bin/sh\nexec {shlex.quote(found)} -F /dev/null "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(openssh, "AVAILABLE", True)


# What a connect phase that ran out is called, at --connect-timeout 1.
RAN_OUT = {"silent": "no SSH banner from 127.0.0.1:{port} within 1s",
           "full": "TCP connect to 127.0.0.1:{port} timed out after 1s"}


def _run(vendor, port, **kw):
    """run_for_target for one show on 127.0.0.1, three attempts, --connect-timeout 1."""
    args = dict(t=Target("R1", "127.0.0.1", vendor, port), transport=vendor, mode="show",
                show_cmd="show version", edit_cmd=None, config_dir=None, broadcast_file=None,
                user="u", passwd="p", session_timeout=30, command_timeout=10, dry_run=False,
                commit_confirmed=None, save_dir=None, quiet=True, max_attempts=3, connect_timeout=1)
    args.update(kw)
    return runner.run_for_target(**args)


@pytest.mark.parametrize("kind", ["silent", "full"])
def test_junos_gives_the_connect_phase_the_connect_timeout_and_says_which_part_ran_out(listening, kind):
    """A box that did not answer cost the whole session timeout, 30 s at the
    defaults, and failed once: "NETCONF connect failed" was permanent."""
    pytest.importorskip("jnpr.junos")
    port = listening(kind)
    started = time.monotonic()
    with pytest.raises(ConnectTimeoutError) as failed:
        netconf.show("127.0.0.1", "u", "p", "show version", 30, 10, port=port, connect_timeout=1)
    elapsed = time.monotonic() - started
    assert str(failed.value) == "NETCONF connect failed: " + RAN_OUT[kind].format(port=port)
    assert 0.9 <= elapsed < 2.5, f"{elapsed:.1f}s"
    assert isinstance(failed.value, NotAppliedError) and not is_permanent_failure(failed.value)


@pytest.mark.parametrize("kind", ["silent", "full"])
def test_ssh_gives_the_connect_phase_the_connect_timeout_and_says_which_part_ran_out(listening, kind,
                                                                                    monkeypatch, tmp_path):
    """The silent port cost a session timeout three times, about 94 s at the
    defaults, and ended in a bare "No existing session"."""
    pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    port = listening(kind)
    started = time.monotonic()
    with pytest.raises(ConnectTimeoutError) as failed:
        ssh.show("127.0.0.1", "u", "p", "show version", 30, 10, port=port, connect_timeout=1)
    elapsed = time.monotonic() - started
    assert str(failed.value) == RAN_OUT[kind].format(port=port)
    assert 0.9 <= elapsed < 2.5, f"{elapsed:.1f}s"
    assert is_connect_failure(failed.value) and not is_permanent_failure(failed.value)


@pytest.mark.parametrize("kind", ["silent", "full"])
def test_openssh_gives_the_connect_phase_the_connect_timeout_and_says_which_part_ran_out(listening, kind, real_ssh):
    """The real client against the same ports: its ConnectTimeout and the
    transport's own clock both say it the transport's way. It cost the
    whole session timeout, 30 s at the defaults, and failed once."""
    port = listening(kind)
    started = time.monotonic()
    with pytest.raises(ConnectTimeoutError) as failed:
        openssh.show("127.0.0.1", "u", None, "show version", 30, 10, port=port, connect_timeout=1)
    elapsed = time.monotonic() - started
    assert str(failed.value) == RAN_OUT[kind].format(port=port)
    assert 0.9 <= elapsed < 2.5, f"{elapsed:.1f}s"


def test_the_connect_phase_never_gets_more_than_the_session_timeout(listening, monkeypatch, tmp_path):
    pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    port = listening("silent")
    started = time.monotonic()
    with pytest.raises(ConnectTimeoutError, match=rf"^no SSH banner from 127\.0\.0\.1:{port} within 1s$"):
        ssh.show("127.0.0.1", "u", "p", "show version", 1, 10, port=port, connect_timeout=3)
    assert time.monotonic() - started < 2.5


# A NETCONF server's hello, base:1.0 only, so both sides frame with ]]>]]>.
_NETCONF_HELLO = (b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>'
                  b'<capability>urn:ietf:params:netconf:base:1.0</capability></capabilities>'
                  b'<session-id>1</session-id></hello>]]>]]>')


@pytest.fixture
def late_sshd():
    """late_sshd(kex=, login=, hello=) -> the port of an SSH server on
    127.0.0.1 whose banner comes at once and whose key exchange, login or
    NETCONF hello comes that many seconds late: a proxy in front holds what
    the server says after its banner, the password is answered late, the
    hello is said late. paramiko lets anyone in with a password; an exec
    answers "fake COMMAND", the netconf subsystem a <command> with
    "fake version" and a <close-session> with <ok/>."""
    paramiko = pytest.importorskip("paramiko")
    key = paramiko.ECDSAKey.generate()
    opened, transports = [], []

    class Sshd(paramiko.ServerInterface):
        def __init__(self, login, hello):
            self.login, self.hello = login, hello

        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, password):
            time.sleep(self.login)
            return paramiko.AUTH_SUCCESSFUL

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_channel_exec_request(self, channel, command):
            def run():
                channel.sendall(b"fake " + command + b"\n")
                channel.send_exit_status(0)
                channel.shutdown_write()
            threading.Thread(target=run, daemon=True).start()
            return True

        def check_channel_subsystem_request(self, channel, name):
            if name != "netconf":
                return False

            def run():
                time.sleep(self.hello)
                channel.sendall(_NETCONF_HELLO)
                pending = b""
                while True:
                    data = channel.recv(65536)
                    if not data:
                        return
                    pending += data
                    while b"]]>]]>" in pending:
                        message, pending = pending.split(b"]]>]]>", 1)
                        mid = re.search(rb'message-id="([^"]+)"', message)
                        if mid is None:
                            continue                         # the client's hello
                        reply = (b'<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="'
                                 + mid.group(1) + b'">')
                        if b"close-session" in message:
                            channel.sendall(reply + b"<ok/></rpc-reply>]]>]]>")
                            channel.close()
                            return
                        channel.sendall(reply + b"<output>fake version</output></rpc-reply>]]>]]>")
            threading.Thread(target=run, daemon=True).start()
            return True

    def listen():
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        opened.append(srv)
        return srv

    def pump(src, dst, hold):
        """src to dst; with `hold`, the first line (the banner) at once and
        the rest `hold` seconds later."""
        try:
            if hold:
                line = b""
                while not line.endswith(b"\n"):
                    byte = src.recv(1)
                    if not byte:
                        return
                    line += byte
                dst.sendall(line)
                time.sleep(hold)
            while True:
                data = src.recv(65536)
                if not data:
                    return
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def make(kex=0.0, login=0.0, hello=0.0):
        sshd, front = listen(), listen()

        def serve():
            while True:
                try:
                    conn, _ = sshd.accept()
                except OSError:
                    return
                t = paramiko.Transport(conn)
                t.add_server_key(key)
                transports.append(t)
                try:
                    t.start_server(server=Sshd(login, hello))
                except (paramiko.SSHException, EOFError, OSError):
                    pass

        def proxy():
            while True:
                try:
                    client, _ = front.accept()
                except OSError:
                    return
                server = socket.create_connection(sshd.getsockname())
                opened.extend((client, server))
                threading.Thread(target=pump, args=(server, client, kex), daemon=True).start()
                threading.Thread(target=pump, args=(client, server, 0), daemon=True).start()
        threading.Thread(target=serve, daemon=True).start()
        threading.Thread(target=proxy, daemon=True).start()
        return front.getsockname()[1]
    yield make
    for t in transports:
        t.close()
    for s in opened:
        s.close()


@pytest.mark.parametrize("late", ["kex", "login"])
def test_ssh_gives_what_comes_after_the_banner_the_session_timeout(late_sshd, late, monkeypatch, tmp_path):
    """Only the TCP connect and the banner have --connect-timeout: a key
    exchange or a login slower than that (a busy RE) has the session
    timeout, as it had before #126."""
    monkeypatch.setenv("HOME", str(tmp_path))
    port = late_sshd(**{late: 1.5})
    started = time.monotonic()
    out = ssh.show("127.0.0.1", "u", "p", "show version", 30, 10, port=port, connect_timeout=1)
    assert out == "$ show version\nfake show version\n"
    assert time.monotonic() - started >= 1.5


@pytest.mark.parametrize("late", ["kex", "login", "hello"])
def test_junos_gives_what_comes_after_the_banner_the_session_timeout(late_sshd, late):
    """The same on NETCONF, the hello too: ncclient waits for the router's
    hello as long as PyEZ's conn_open_timeout, which had the connect
    timeout, so a hello 1.5 s late at --connect-timeout 1 was "Capability
    exchange timed out", and failed for good."""
    pytest.importorskip("jnpr.junos")
    port = late_sshd(**{late: 1.5})
    started = time.monotonic()
    out = netconf.show("127.0.0.1", "u", "p", "show version", 30, 10, port=port, connect_timeout=1)
    assert out == "fake version"
    assert time.monotonic() - started >= 1.5
    netconf.wait_for_closes(5)


@pytest.mark.parametrize("vendor, said", [("junos", "NETCONF connect failed: connection refused by 127.0.0.1:{port}"),
                                          ("ssh", "connection refused by 127.0.0.1:{port}")])
def test_a_refused_port_fails_once_at_once_in_the_oss_words(listening, monkeypatch, tmp_path, capsys, vendor, said):
    """A clear answer is the same answer next time: one attempt, no pause.
    junos said "(nothing listening, or no route)" whatever the OS said, and
    ssh "[Errno None] Unable to connect to port 22 on HOST"."""
    pytest.importorskip("jnpr.junos" if vendor == "junos" else "paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    port = listening("refused")
    started = time.monotonic()
    result = _run(vendor, port, quiet=False)
    assert time.monotonic() - started < 1.5            # three attempts would have paused 1.5 s
    assert not result.ok and result.error == said.format(port=port)
    assert "RETRY" not in capsys.readouterr().out


def test_a_box_that_never_answers_gets_three_attempts_with_short_pauses(listening, monkeypatch, tmp_path, capsys):
    """Nothing was sent, and a booting box or a busy sshd may answer the
    next attempt: tried again after 0.5 s and then 1 s, so three attempts at
    --connect-timeout 1 take about 4.5 s (3 s each at the defaults: about
    10 s)."""
    pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    port = listening("silent")
    started = time.monotonic()
    result = _run("ssh", port, quiet=False)
    elapsed = time.monotonic() - started
    out = capsys.readouterr().out
    said = f"no SSH banner from 127.0.0.1:{port} within 1s"
    assert not result.ok and result.error == said
    assert f"RETRY 1/2 in 0.5s ({said})" in out and f"RETRY 2/2 in 1s ({said})" in out
    assert 4.4 <= elapsed < 7.5, f"{elapsed:.1f}s"


def test_three_attempts_at_the_defaults_take_about_ten_seconds(monkeypatch, capsys):
    """--retries 2 and --connect-timeout 3, as shipped, on a clock of the
    test's own: three connect timeouts and two short pauses, 10.5 s, where a
    blackholed or silent box cost 30 s on junos and openssh and about 94 s
    on ssh."""
    clock, pauses, given = [0.0], [], []

    def show(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None, connect_timeout=None):
        given.append(connect_timeout)
        clock[0] += connect_timeout                     # the wait the transport makes
        raise ConnectTimeoutError(f"TCP connect to {host}:22 timed out after {connect_timeout}s")

    def sleep(seconds):
        pauses.append(seconds)
        clock[0] += seconds
    monkeypatch.setitem(drivers.MODULES, "none@ssh", types.SimpleNamespace(AVAILABLE=True, show=show))
    monkeypatch.setattr(runner.time, "sleep", sleep)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "-sC", "show version",
                                      "R1:10.0.0.1:ssh"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 1 and given == [3, 3, 3] and pauses == [0.5, 1]
    assert clock[0] == 10.5
    assert "RETRY 1/2 in 0.5s (TCP connect to 10.0.0.1:22 timed out after 3s)" in out
    assert "ERROR: TCP connect to 10.0.0.1:22 timed out after 3s" in out


def test_the_runner_hands_the_connect_timeout_to_every_function_that_takes_it(monkeypatch):
    """Every function of the three SSH transports takes it; telnet's do not
    (frozen), and neither may a stand-in or a driver from another package,
    which are called as before."""
    for mod in (netconf, ssh, openssh):
        for name in ("show", "show_batch", "show_structured", "edit", "confirm", "rollback",
                     "commit_status", "rpc", "rpc_batch", "begin", "guarded_commit"):
            fn = getattr(mod, name, None)
            if callable(fn):
                assert "connect_timeout" in inspect.signature(fn).parameters, f"{mod.__name__}.{name}"
    for name in ("show", "show_batch", "edit", "confirm"):
        assert "connect_timeout" not in inspect.signature(getattr(telnet, name)).parameters
    seen = []

    def takes(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None, connect_timeout="its own"):
        seen.append(connect_timeout)
        return "ok"

    def plain(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        seen.append("plain")
        return "ok"
    for show, kw in ((takes, {"connect_timeout": 7}), (takes, {}), (takes, {"connect_timeout": None}),
                     (plain, {"connect_timeout": 7})):
        monkeypatch.setitem(drivers.MODULES, "none@ssh", types.SimpleNamespace(AVAILABLE=True, show=show))
        assert _run("ssh", None, **kw).ok
    assert seen == [7, 1, None, "plain"]          # None as given: the session timeout, below


def test_a_connect_timeout_of_none_gives_the_connect_phase_the_session_timeout(listening, fake_ssh,
                                                                              monkeypatch, tmp_path):
    """A library caller's connect_timeout=None was a TypeError on all three
    transports ('<' not supported between instances of 'int' and
    'NoneType'): it is the connect phase with no clock of its own, the
    session timeout's, as before #126."""
    pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    port = listening("refused")
    with pytest.raises(RuntimeError, match=rf"^connection refused by 127\.0\.0\.1:{port}$"):
        ssh.show("127.0.0.1", "u", "p", "show version", 30, 10, port=port, connect_timeout=None)
    if netconf.AVAILABLE:
        with pytest.raises(NotAppliedError, match=rf"^NETCONF connect failed: connection refused by "
                                                  rf"127\.0\.0\.1:{port}$"):
            netconf.show("127.0.0.1", "u", "p", "show version", 30, 10, port=port, connect_timeout=None)
    seen = []
    real = subprocess.Popen

    def spy(argv, **kwargs):
        seen.append(argv)
        return real(argv, **kwargs)
    monkeypatch.setattr(subprocess, "Popen", spy)
    assert "device output" in openssh.show("h", "u", None, "show version", 7, 10, connect_timeout=None)
    assert "ConnectTimeout=7" in seen[0]
    assert "ConnectTimeout=7" in openssh.ssh_command_line("h", "u", "show version", 7, connect_timeout=None)


def test_opensshs_connect_timeout_is_the_connect_timeout(fake_ssh, monkeypatch):
    seen = []
    real = subprocess.Popen

    def spy(argv, **kwargs):
        seen.append(argv)
        return real(argv, **kwargs)
    monkeypatch.setattr(subprocess, "Popen", spy)
    openssh.show("h", "u", None, "show version", 30, 10, connect_timeout=4)
    openssh.show("h", "u", None, "show version", 2, 10, connect_timeout=4)
    assert "ConnectTimeout=4" in seen[0] and "ConnectTimeout=2" in seen[1]
    assert "ConnectTimeout=3" in openssh.ssh_command_line("h", "u", "show version", session_timeout=30)


def test_openssh_names_the_part_of_the_connect_phase_that_ran_out_on_its_own_clock(fake_ssh, monkeypatch):
    """No TCP connection in ssh's log by then; the port is the one ssh says
    it connected to, which ~/.ssh/config may have set."""
    monkeypatch.setenv("FAKE_SSH_SLEEP", "5")
    monkeypatch.setenv("FAKE_SSH_LOG", "debug1: Connecting to h [10.0.0.9] port 2222.\\n")
    started = time.monotonic()
    with pytest.raises(ConnectTimeoutError, match="^TCP connect to h:2222 timed out after 1s$"):
        openssh.show("h", "u", None, "show version", 30, 10, connect_timeout=1)
    assert time.monotonic() - started < 2.5


@pytest.mark.parametrize("log, said", [
    ("debug1: Connecting to h port 22.\\nssh: connect to host h port 22: Connection timed out\\n",
     "TCP connect to h:22 timed out after 3s"),
    ("debug1: Connecting to h port 22.\\ndebug1: Connection established.\\n"
     "Connection timed out during banner exchange\\nConnection to h port 22 timed out\\n",
     "no SSH banner from h:22 within 3s"),
])
def test_opensshs_own_connect_timeout_is_said_the_same_way(fake_ssh, monkeypatch, log, said):
    """When ssh's ConnectTimeout fires before the transport's clock, ssh
    ends the session itself, and that used to be "ssh exit 255: ...",
    permanent: the transport's words, and tried again, all the same."""
    monkeypatch.setenv("FAKE_SSH_LOG", log)
    monkeypatch.setenv("FAKE_SSH_RC", "255")
    with pytest.raises(ConnectTimeoutError) as failed:
        openssh.show("h", "u", None, "show version", 30, 10)
    assert str(failed.value) == said and not is_permanent_failure(failed.value)


def test_an_openssh_batch_whose_connect_runs_out_fails_as_one(fake_ssh, monkeypatch):
    """Each command of a batch is an ssh of its own: one that got no answer
    was followed by the next, another connect timeout for the same silence.
    Now the batch fails as a whole, as where a batch is one connection, and
    the runner may try it again."""
    monkeypatch.setenv("FAKE_SSH_SLEEP", "5")
    monkeypatch.setenv("FAKE_SSH_LOG", "debug1: Connecting to h port 22.\\n")
    started = time.monotonic()
    with pytest.raises(ConnectTimeoutError, match="^TCP connect to h:22 timed out after 1s$"):
        openssh.show_batch("h", "u", None, ["show version", "show chassis hardware", "show route"], 30, 10,
                           connect_timeout=1)
    assert time.monotonic() - started < 2.5            # one connect timeout, not one a command


def _ssh_that_answers_once(tmp_path, monkeypatch, said):
    """A stub ssh whose first run is a session that prints `said` and exits
    0, and whose every later run gets no TCP answer. Returns the file that
    counts the runs."""
    count = tmp_path / "count"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "ssh"
    script.write_text(
        "#!/bin/sh\n"
        'while [ $# -gt 0 ]; do case "$1" in -E) shift; LOG="$1";; esac; shift; done\n'
        f'n=$(cat {shlex.quote(str(count))} 2>/dev/null || echo 0); n=$((n + 1)); echo $n > {shlex.quote(str(count))}\n'
        'if [ "$n" -eq 1 ]; then echo "Authenticated to h ([10.0.0.1]:22) using publickey." >> "$LOG"; '
        f'echo {shlex.quote(said)}; exit 0; fi\n'
        'echo "debug1: Connecting to h port 22." >> "$LOG"\n'
        'sleep 5\n'
        'exit 255\n')
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(openssh, "AVAILABLE", True)
    return count


def test_an_openssh_batch_keeps_what_ran_before_a_connect_ran_out(tmp_path, monkeypatch):
    """Once a command has run, a connect that runs out after it is that
    command's failure: the whole batch was thrown away as one connect
    timeout, a reboot's record and output with it, and a batch that acts
    on the device gets no second attempt to bring them back."""
    count = _ssh_that_answers_once(tmp_path, monkeypatch, "rebooting")
    results = openssh.show_batch("h", "u", None, ["request system reboot", "show chassis alarms"], 30, 10,
                                 connect_timeout=1)
    assert list(results) == [
        {"command": "request system reboot", "ok": True, "output": "$ request system reboot\nrebooting"},
        {"command": "show chassis alarms", "ok": False, "error": "TCP connect to h:22 timed out after 1s"}]
    assert count.read_text().strip() == "2"


def test_an_openssh_edit_whose_second_line_gets_no_answer_is_not_tried_again(tmp_path, monkeypatch):
    """The none dialect sends each line as its own ssh. A connect that runs
    out before the first line sent nothing, and is tried again, an edit too;
    one that runs out after a line was applied did send something: it is
    reported, never repeated."""
    count = _ssh_that_answers_once(tmp_path, monkeypatch, "applied")
    monkeypatch.setattr(runner.time, "sleep", lambda s: None)
    result = runner.run_for_target(
        t=Target("R1", "h", "openssh"), transport="openssh", mode="edit-cmd", show_cmd=None,
        edit_cmd="set a 1\nset b 2", config_dir=None, broadcast_file=None, user="u", passwd=None,
        session_timeout=30, command_timeout=10, dry_run=False, commit_confirmed=None, save_dir=None,
        quiet=True, max_attempts=3, connect_timeout=1)
    assert not result.ok
    assert result.error == "TCP connect to h:22 timed out after 1s; the 1 line(s) before it were applied"
    assert count.read_text().strip() == "2"            # the first line, the second, and no attempt after
    # Something reached the device: not a connect failure (after Ctrl-C the
    # CLI called it "interrupted while connecting"), nor one to try again.
    assert not is_connect_failure(result.error) and not is_connect_timeout(result.error)


def test_ssh_says_what_the_os_answered_the_tcp_connect(monkeypatch, tmp_path):
    """The lab's on-link address nobody answers ARP for: paramiko puts the
    OS's "no route to host" in NoValidConnectionsError, whose message is
    "[Errno None] Unable to connect to port 22 on 10.91.0.252"; and a name
    that does not resolve was retried."""
    paramiko = pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))

    def unreachable(self, **kw):
        raise paramiko.ssh_exception.NoValidConnectionsError(
            {("10.91.0.252", 22): OSError(errno.EHOSTUNREACH, "No route to host")})
    monkeypatch.setattr(paramiko.SSHClient, "connect", unreachable)
    with pytest.raises(RuntimeError, match=r"^no route to host 10\.91\.0\.252:22$") as failed:
        ssh.show("10.91.0.252", "u", "p", "show version", 30, 10)
    assert is_permanent_failure(failed.value) and is_connect_failure(failed.value)

    def unknown(self, **kw):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    monkeypatch.setattr(paramiko.SSHClient, "connect", unknown)
    with pytest.raises(RuntimeError, match=r"^cannot resolve r1\.lab$") as failed:
        ssh.show("r1.lab", "u", "p", "show version", 30, 10)
    assert is_permanent_failure(failed.value) and is_connect_failure(failed.value)
    assert not is_connect_timeout(failed.value)


def test_a_resolver_that_did_not_answer_in_time_is_tried_again_on_ssh(monkeypatch, tmp_path, capsys):
    """Only a name the resolver says does not exist is "cannot resolve HOST",
    which fails once. EAI_AGAIN (no answer from the resolver in time) was
    that too, so a DNS hiccup failed the device after one attempt where it
    had been tried again. Said in the OS's words, nothing sent: tried again,
    an edit too."""
    paramiko = pytest.importorskip("paramiko")
    monkeypatch.setenv("HOME", str(tmp_path))
    lookups = []

    def lookup(self, **kw):
        lookups.append(kw["hostname"])
        raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
    monkeypatch.setattr(paramiko.SSHClient, "connect", lookup)
    said = "name lookup for r1.lab failed: Temporary failure in name resolution"
    with pytest.raises(NotAppliedError, match=f"^{said}$") as failed:
        ssh.show("r1.lab", "u", "p", "show version", 30, 10)
    assert not is_permanent_failure(failed.value) and is_connect_failure(failed.value)
    monkeypatch.setattr(runner.time, "sleep", lambda s: None)
    lookups.clear()
    result = _run("ssh", None, t=Target("R1", "r1.lab", "ssh"), mode="edit-cmd", show_cmd=None,
                  edit_cmd="set a 1", quiet=False)
    assert not result.ok and result.error == said and lookups == ["r1.lab"] * 3
    assert f"RETRY 2/2 in 3s ({said})" in capsys.readouterr().out


def test_the_socket_ncclient_opens_keeps_the_oss_answer_and_the_connect_phases_clock(listening):
    """ncclient says only "Could not open socket", and gives every address of
    a name its whole timeout again: the socket it opens keeps what the OS
    answered, and connects within what is left of the connect phase."""
    pytest.importorskip("ncclient")
    assert netconf._ncclient_ssh.socket.socket is netconf._ConnectSocket
    refused, full = listening("refused"), listening("full")
    try:
        netconf._DEADLINE.connect_at = time.monotonic() + 5
        netconf._DEADLINE.connect_error = None
        s = netconf._ConnectSocket()
        s.settimeout(30)
        with pytest.raises(ConnectionRefusedError):
            s.connect(("127.0.0.1", refused))
        s.close()
        assert isinstance(netconf._DEADLINE.connect_error, ConnectionRefusedError)
        netconf._DEADLINE.connect_at = time.monotonic() + 0.5
        s = netconf._ConnectSocket()
        s.settimeout(30)
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            s.connect(("127.0.0.1", full))
        s.close()
        assert time.monotonic() - started < 1.5
        assert isinstance(netconf._DEADLINE.connect_error, TimeoutError)
    finally:
        netconf._DEADLINE.connect_at = netconf._DEADLINE.connect_error = None
