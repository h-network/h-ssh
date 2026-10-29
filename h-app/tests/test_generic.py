"""paramiko transport tests — host-key pinning and exit statuses, no live devices needed."""
import io
import os
import stat
import sys
import threading
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import paramiko

from hssh import runner
from hssh.core import Target
from hssh.transports import ssh


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    """A private HOME: pins land in tmp_path/.h-ssh and nothing in ~/.ssh is read."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("HSSH_HOST_KEY_POLICY", raising=False)
    return tmp_path


def pin_file(home):
    return home / ".h-ssh" / "known_hosts"


class FakeChannel:
    eof_received = True          # its streams are files that end: the device's EOF

    def __init__(self, rc):
        self.rc = rc

    def recv_exit_status(self):
        return self.rc


class FakeStream(io.BytesIO):
    """What exec_command hands back: a file with the channel behind it."""

    def __init__(self, data, rc):
        super().__init__(data)
        self.channel = FakeChannel(rc)


def exec_result(out=b"", err=b"", rc=0):
    return FakeStream(b"", rc), FakeStream(out, rc), FakeStream(err, rc)


class FakeParamiko:
    """The real paramiko with SSHClient swapped for a fake."""

    def __init__(self, client_cls):
        self.SSHClient = client_cls

    def __getattr__(self, name):
        return getattr(paramiko, name)


# --- host keys: paramiko's real connect() on a fake transport ------------------

class FakeSock:
    def __init__(self, key):
        self.server_key = key


class FakeTransport:
    """Only what SSHClient.connect() touches between the socket and auth."""

    def __init__(self, sock, disabled_algorithms=None):
        self.sock = sock

    def use_compression(self, compress=False):
        pass

    def set_log_channel(self, name):
        pass

    def get_security_options(self):
        return types.SimpleNamespace(key_types=[
            "ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"])

    def start_client(self, timeout=None):
        pass

    def _log(self, level, msg):
        pass

    def get_remote_server_key(self):
        return self.sock.server_key

    def close(self):
        pass


class OfflineSSHClient(paramiko.SSHClient):
    """paramiko's own connect() — host-key logic included — with no socket.

    The server presents whatever key the class attribute holds; auth records
    the credentials it was handed instead of sending them anywhere. The fake
    transport stands in for the one the ssh transport's factory would build.
    """
    server_key = None
    auth_calls = []
    transport = FakeTransport

    def connect(self, hostname, port=22, transport_factory=None, **kw):
        return super().connect(hostname, port=port, sock=FakeSock(type(self).server_key),
                               transport_factory=type(self).transport, **kw)

    def _auth(self, username, password, *args, **kwargs):
        type(self).auth_calls.append((username, password))

    def exec_command(self, cmd, timeout=None, **kw):
        return exec_result(b"output-for: " + cmd.encode())


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setattr(ssh, "paramiko", FakeParamiko(OfflineSSHClient))
    monkeypatch.setattr(OfflineSSHClient, "auth_calls", [])
    monkeypatch.setattr(OfflineSSHClient, "server_key", paramiko.ECDSAKey.generate())
    return OfflineSSHClient


def test_first_contact_pins_the_key(offline, home):
    out = ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert "output-for: show version" in out
    lines = pin_file(home).read_text().splitlines()
    assert len(lines) == 1 and lines[0].startswith("10.0.0.1 ecdsa-sha2-nistp256 ")
    assert stat.S_IMODE(pin_file(home).stat().st_mode) == 0o600
    assert offline.auth_calls == [("admin", "s3cret")]


def test_a_changed_key_is_refused_before_any_credential_is_sent(offline, home):
    """Regression: WarningPolicy let an impostor on a known address have the password."""
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    pinned = pin_file(home).read_text()
    offline.auth_calls.clear()
    offline.server_key = paramiko.ECDSAKey.generate()
    with pytest.raises(RuntimeError, match="Host key verification failed for 10.0.0.1"):
        ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert offline.auth_calls == []
    assert pin_file(home).read_text() == pinned


def test_a_pinned_key_is_accepted_again(offline, home):
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert len(pin_file(home).read_text().splitlines()) == 1
    assert len(offline.auth_calls) == 2


def test_a_pin_is_not_overridden_through_the_system_known_hosts(offline, home):
    """paramiko looks a host up in ~/.ssh/known_hosts first and reads the
    pin file only when the host is absent there (#150): one openssh first
    contact, or one manual ssh, that took an impostor's key K2 made this
    transport take K2 too, with K1 still pinned in ~/.h-ssh/known_hosts,
    and the impostor got the password. When the two files hold different
    keys for a host, the host is refused before any credential is sent,
    whichever key the server shows: one of the files is wrong, and the
    message names both."""
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)       # K1 pinned
    k1, k2 = offline.server_key, paramiko.ECDSAKey.generate()
    system = home / ".ssh" / "known_hosts"
    system.parent.mkdir()
    system.write_text(f"10.0.0.1 {k2.get_name()} {k2.get_base64()}\n")
    pinned = pin_file(home).read_text()
    for shown in (k2, k1):
        offline.auth_calls.clear()
        offline.server_key = shown
        with pytest.raises(RuntimeError) as refused:
            ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
        assert str(refused.value).startswith("Host key verification failed for 10.0.0.1: ")
        assert str(pin_file(home)) in str(refused.value) and "~/.ssh/known_hosts" in str(refused.value)
        assert "different" in str(refused.value) and offline.auth_calls == []
    assert pin_file(home).read_text() == pinned
    # One file alone still decides as it did: K2 known from ~/.ssh/known_hosts only is accepted.
    pin_file(home).write_text("")
    offline.server_key = k2
    assert "output-for" in ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)


def test_strict_policy_refuses_an_unknown_host(offline, home, monkeypatch):
    monkeypatch.setenv("HSSH_HOST_KEY_POLICY", "yes")
    with pytest.raises(RuntimeError, match="Host key verification failed for 10.0.0.1"):
        ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert offline.auth_calls == []
    assert pin_file(home).read_text() == ""


def test_strict_policy_accepts_a_pinned_host(offline, home, monkeypatch):
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    monkeypatch.setenv("HSSH_HOST_KEY_POLICY", "yes")
    out = ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert "output-for: show version" in out


def test_no_policy_warns_and_pins_nothing(offline, home, monkeypatch):
    monkeypatch.setenv("HSSH_HOST_KEY_POLICY", "no")
    with pytest.warns(UserWarning, match="Unknown ecdsa-sha2-nistp256 host key for 10.0.0.1"):
        ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert pin_file(home).read_text() == ""


@pytest.mark.parametrize("policy", ["maybe", "ask", "off"])
def test_unknown_policy_is_refused(offline, home, monkeypatch, policy):
    """OpenSSH's own `ask` and `off` included (#150): `ask` with a password
    had the openssh transport put the yes/no question to the askpass
    helper, which answered with the password, thousands of times."""
    monkeypatch.setenv("HSSH_HOST_KEY_POLICY", policy)
    with pytest.raises(RuntimeError, match="invalid HSSH_HOST_KEY_POLICY"):
        ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert offline.auth_calls == [] and pin_file(home).read_text() == ""


def test_another_port_is_pinned_under_its_own_name(offline, home):
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10, port=2222)
    assert pin_file(home).read_text().startswith("[10.0.0.1]:2222 ecdsa-sha2-nistp256 ")


def test_parallel_first_contacts_are_all_pinned(offline, home):
    """Workers of one run pin at the same time; the file must end up with every host."""
    hosts = ["10.0.0.%d" % i for i in range(1, 9)]
    errors = []

    def contact(host):
        try:
            ssh.show(host, "admin", "s3cret", "show version", 5, 10)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=contact, args=(h,)) for h in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    pinned = sorted(line.split()[0] for line in pin_file(home).read_text().splitlines())
    assert pinned == sorted(hosts)


# --- exit status: a fake client whose every command ends the same way ---------

class ExitClient:
    rc = 0
    stdout = b"output-for: %s"
    stderr = b""

    def load_system_host_keys(self):
        pass

    def load_host_keys(self, path):
        pass

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, **kw):
        pass

    def exec_command(self, cmd, timeout=None):
        cls = type(self)
        return exec_result(cls.stdout % cmd.encode(), cls.stderr, cls.rc)

    def close(self):
        pass


@pytest.fixture
def exits_with(monkeypatch):
    def install(rc, stderr=b"", stdout=b"output-for: %s"):
        client_cls = type("Client", (ExitClient,), {"rc": rc, "stderr": stderr, "stdout": stdout})
        monkeypatch.setattr(ssh, "paramiko", FakeParamiko(client_cls))
    return install


def test_edit_raises_on_a_non_zero_exit(exits_with):
    """Regression: a failed config line came back as output and the runner printed OK."""
    exits_with(127, stderr=b"sh: 1: configure: not found\n")
    with pytest.raises(RuntimeError, match="exit 127 from 'configure terminal': sh: 1: configure: not found"):
        ssh.edit("10.0.0.1", "u", "p", "configure terminal\nhostname NEW\n", 5, 10)


def test_batch_marks_a_non_zero_exit_per_command(exits_with):
    exits_with(1, stderr=b"error: syntax error\n")
    results = ssh.show_batch("10.0.0.1", "u", "p", ["show foo"], 5, 10)
    assert results[0]["ok"] is False
    assert "exit 1" in results[0]["error"] and "syntax error" in results[0]["error"]


def test_exit_zero_returns_the_output_block(exits_with):
    exits_with(0)
    assert ssh.show("10.0.0.1", "u", "p", "show version", 5, 10) == (
        "$ show version\noutput-for: show version\n")
    results = ssh.show_batch("10.0.0.1", "u", "p", ["show version"], 5, 10)
    assert results == [{"command": "show version", "ok": True,
                        "output": "$ show version\noutput-for: show version"}]


def test_no_exit_status_from_the_server_is_not_a_failure(exits_with):
    exits_with(-1)
    assert "output-for: show version" in ssh.show("10.0.0.1", "u", "p", "show version", 5, 10)


def test_failure_detail_falls_back_to_stdout(exits_with):
    """Network OSes tend to print their errors on stdout."""
    exits_with(1, stdout=b"error: unknown command: %s\n")
    with pytest.raises(RuntimeError, match="exit 1 from 'show foo': error: unknown command: show foo"):
        ssh.show("10.0.0.1", "u", "p", "show foo", 5, 10)


def test_runner_reports_a_failed_edit_as_fail(exits_with):
    exits_with(127, stderr=b"sh: 1: configure: not found\n")
    name, ok, out, _ = runner.run_for_target(
        t=Target("R1", "10.0.0.1", "ssh"), transport="ssh", mode="edit-cmd",
        show_cmd=None, edit_cmd="configure terminal", config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=False, commit_confirmed=None, save_dir=None, quiet=True, max_attempts=1)
    assert ok is False
    assert "exit 127" in out and "configure: not found" in out


def test_edit_refuses_a_rollback_timer_instead_of_dropping_it(monkeypatch):
    """commit_confirmed= was accepted and the change committed with no timer (#40)."""
    class NoClient:
        def __init__(self, *a, **k):
            raise AssertionError("connected although the timer cannot be armed over exec")
    monkeypatch.setattr(ssh, "paramiko", FakeParamiko(NoClient))
    with pytest.raises(ValueError, match="not supported by the 'ssh' transport; nothing was sent"):
        ssh.edit("10.0.0.1", "u", "p", "hostname NEW\n", 5, 10, commit_confirmed=5)

def test_a_failed_connect_closes_the_client(monkeypatch):
    """A refused login left paramiko's Transport thread and socket behind (#43)."""
    closes = []

    class Refusing(paramiko.SSHClient):
        def connect(self, **kw):
            raise paramiko.AuthenticationException("Authentication failed.")

        def close(self):
            closes.append(1)
            super().close()
    monkeypatch.setattr(ssh, "paramiko", FakeParamiko(Refusing))
    with pytest.raises(paramiko.AuthenticationException):
        ssh.show("10.0.0.1", "u", "wrong", "show version", 5, 10)
    assert closes == [1]


def test_every_phase_of_the_connect_has_a_timeout_the_channel_open_too(monkeypatch):
    """paramiko gives connect, banner, auth and the channel open each their
    own clock; the last one defaults to an hour. A device that authenticates
    and then never answers the shell's channel open held a worker that long.
    The TCP connect and the banner share --connect-timeout (#126); the
    negotiation, the key exchange, auth and the channel open have the
    session timeout."""
    import socket
    seen = {}

    class Recording(paramiko.SSHClient):
        def connect(self, **kw):
            seen.update(kw)

        def exec_command(self, cmd, timeout=None, **kw):
            return exec_result(b"ok")
    monkeypatch.setattr(ssh, "paramiko", FakeParamiko(Recording))
    ssh.show("10.0.0.1", "u", "p", "show version", 7, 10)
    assert (seen["timeout"], seen["auth_timeout"], seen["channel_timeout"]) == (3.0, 7.0, 7.0)
    a, b = socket.socketpair()
    try:
        t = seen["transport_factory"](a)
        assert 2.0 < t.banner_timeout <= 3.0                  # what is left of the connect phase
        assert t.handshake_timeout == 7.0 and t._hssh_negotiation == 7.0
        t.banner_timeout = 15                                 # connect()'s own assignment lands nowhere
        assert t.banner_timeout <= 3.0
    finally:
        a.close()
        b.close()
    ssh.show("10.0.0.1", "u", "p", "show version", 2, 10, connect_timeout=5)
    assert seen["timeout"] == 2.0                             # never more than the session timeout

# --- #45: every wait in exec is bounded ----------------------------------------

import time as _time


class StuckChannel(FakeChannel):
    """A device that sends EOF and then neither a status nor a close."""
    def __init__(self, rc, status_set):
        super().__init__(rc)
        self.status_event = threading.Event()
        if status_set:
            self.status_event.set()
        self.closed = False

    def close(self):
        self.closed = True


def _stuck_client(status_set):
    class Client(ExitClient):
        def exec_command(self, cmd, timeout=None):
            out = FakeStream(b"partial output", 0)
            out.channel = StuckChannel(0, status_set)
            return FakeStream(b"", 0), out, FakeStream(b"", 0)
    return Client


def test_eof_without_an_exit_status_ends_in_a_timeout_not_a_pinned_worker(monkeypatch):
    """ssh.show(command_timeout=3) was still blocked after 20 s in
    recv_exit_status; Ctrl-C could not end the run."""
    monkeypatch.setattr(ssh, "paramiko", FakeParamiko(_stuck_client(status_set=False)))
    t0 = _time.monotonic()
    with pytest.raises(TimeoutError, match="no exit status within 1s"):
        ssh.show("10.0.0.1", "u", "p", "show version", 5, 1)
    assert _time.monotonic() - t0 < 3


def test_a_status_that_does_arrive_is_read_as_before(monkeypatch):
    monkeypatch.setattr(ssh, "paramiko", FakeParamiko(_stuck_client(status_set=True)))
    assert "partial output" in ssh.show("10.0.0.1", "u", "p", "show version", 5, 1)


def test_a_device_that_never_stops_sending_hits_the_deadline(monkeypatch):
    class Endless(io.RawIOBase):
        channel = FakeChannel(0)

        def read(self, n=-1):
            _time.sleep(0.05)
            return b"x" * 1024

    class Client(ExitClient):
        def exec_command(self, cmd, timeout=None):
            return FakeStream(b"", 0), Endless(), FakeStream(b"", 0)
    monkeypatch.setattr(ssh, "paramiko", FakeParamiko(Client))
    t0 = _time.monotonic()
    with pytest.raises(TimeoutError, match="still sending"):
        ssh.show("10.0.0.1", "u", "p", "show version", 5, 1)
    assert _time.monotonic() - t0 < 3

def test_pinning_takes_a_file_lock_so_two_processes_keep_each_others_pins(offline, home, monkeypatch):
    """The pin file was rewritten whole under a per-process lock (#47)."""
    import fcntl
    locks = []
    real = fcntl.flock

    def recording(fd, op):
        locks.append(op)
        return real(fd, op)
    monkeypatch.setattr(ssh.fcntl, "flock", recording)
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert any(op & fcntl.LOCK_EX for op in locks) and fcntl.LOCK_UN in locks
    assert pin_file(home).read_text().startswith("10.0.0.1 ")


# --- #67 (M6): the reply is the verdict too ---------------------------------------

def test_edit_is_failed_when_the_cli_refuses_a_line_and_exits_zero(exits_with):
    exits_with(0, stdout=b"error: syntax error, expecting <statement> for %s\n")
    with pytest.raises(RuntimeError, match="'set system host-name x' was refused by the device: error: syntax error"):
        ssh.edit("10.0.0.1", "u", "p", "set system host-name x\n", 5, 10)
    exits_with(0, stdout=b"%% Invalid input detected at '^' marker. (%s)\n")
    with pytest.raises(RuntimeError, match="was refused by the device: % Invalid input"):
        ssh.edit("10.0.0.1", "u", "p", "hostname x\n", 5, 10)


def test_a_show_that_prints_error_is_still_output(exits_with):
    exits_with(0, stdout=b"log: error: link down on ge-0/0/0 (%s)\n")
    assert "link down" in ssh.show("10.0.0.1", "u", "p", "show log", 5, 10)
    exits_with(0, stdout=b"Oct 24 12:00:00 r1 rpd[1]: up\nerror: link down on ge-0/0/0 (%s)\n")
    assert "link down" in ssh.show("10.0.0.1", "u", "p", "show log", 5, 10)


def test_a_show_the_cli_refuses_at_exit_zero_is_failed(exits_with):
    """#88: the Junos CLI over an exec channel writes its refusal to stdout
    and exits 0; that is no answer, and NETCONF fails the same show."""
    exits_with(0, stdout=b"error: unknown command: %s\n")
    with pytest.raises(RuntimeError, match="'uptime' was refused by the device: error: unknown command: uptime"):
        ssh.show("10.0.0.1", "u", "p", "uptime", 5, 10)
    exits_with(0, stdout=b"          ^\n%% Invalid input detected at '^' marker. (%s)\n")
    with pytest.raises(RuntimeError, match="'show versionx' was refused by the device: % Invalid input"):
        ssh.show("10.0.0.1", "u", "p", "show versionx", 5, 10)


def test_a_batch_marks_the_refused_command_and_keeps_the_rest(exits_with):
    exits_with(0, stdout=b"reply to %s\n")
    ok = ssh.show_batch("10.0.0.1", "u", "p", ["show version"], 5, 10)
    assert ok[0]["ok"] and "reply to show version" in ok[0]["output"]
    exits_with(0, stdout=b"error: unknown command: %s\n")
    bad = ssh.show_batch("10.0.0.1", "u", "p", ["uptime"], 5, 10)
    assert bad == [{"command": "uptime", "ok": False,
                    "error": "'uptime' was refused by the device: error: unknown command: uptime"}]


# --- #83: a dialect's edits and confirms go through the CLI engine on a shell channel ---

import socket

from hssh.drivers import results as R
from hssh.errors import NotAppliedError, NothingToConfirmError


class FakeShell:
    """What invoke_shell() hands back: a paramiko-shaped channel playing a
    device CLI from a script. Each typed line is echoed like a tty and then
    answered; recv() hands out the queued bytes or, with nothing queued,
    times out as paramiko's does."""

    def __init__(self, banner, reply):
        self.queue = bytearray(banner.encode())
        self.reply = reply          # typed line -> what the device prints after the echo
        self.typed = []
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, n):
        if not self.queue:
            _time.sleep(min(self.timeout or 0, 0.01))
            raise socket.timeout()
        chunk, self.queue = bytes(self.queue[:n]), self.queue[n:]
        return chunk

    def sendall(self, data):
        for line in data.decode().splitlines():
            self.typed.append(line)
            self.queue += (line + self.reply(line)).encode()

    def close(self):
        self.closed = True


JUNOS_BANNER = "--- JUNOS 23.4R2.13 Kernel 64-bit  JNPR-12.1-20240711.ae2a6ee_buil\r\nlab@r1> "
EDIT = "\r\n[edit]\r\nlab@r1# "
PENDING = "0   2026-10-22 08:00:00 UTC by lab via cli commit confirmed, rollback in 5mins"
CLEAN = "0   2026-10-22 08:00:00 UTC by lab via cli"
LOCKED = ("\r\nerror: configuration database locked by:\r\n"
          "  admin terminal p0 (pid 1234) on since 2026-10-22 08:00:00 UTC, idle 00:01:02\r\n"
          "      exclusive\r\n\r\nlab@r1> ")


def junos_cli(lock="\r\nEntering configuration mode" + EDIT, commit="\r\ncommit complete" + EDIT,
              history=PENDING):
    """A Junos CLI at `lab@r1> `: the reply to each typed line."""
    def reply(line):
        if line == "configure exclusive":
            return lock
        if line.startswith("set "):
            return EDIT
        if line == "show | compare":
            return "\r\n[edit system]\r\n+  host-name test;" + EDIT
        if line == "commit" or line.startswith("commit "):
            return commit
        if line == "rollback 0":
            return "\r\nload complete" + EDIT
        if line == "exit":
            return "\r\nExiting configuration mode\r\n\r\nlab@r1> "
        if line == "show system commit":
            return f"\r\n{history}\r\n1   2026-10-21 17:30:00 UTC by lab via cli\r\nlab@r1> "
        return "\r\nsyntax error, expecting <command>." + EDIT
    return reply


def ios_cli(line):
    """An IOS CLI at `Router#`."""
    if line == "configure terminal":
        return "\r\nRouter(config)#"
    if line == "end":
        return "\r\nRouter#"
    return "\r\nRouter(config)#"


class ShellClient(ExitClient):
    """ExitClient with a shell: invoke_shell() opens the scripted CLI."""
    banner = ""
    reply = None
    shells = None      # every shell this class opened, for the wire

    def invoke_shell(self, **kw):
        shell = FakeShell(type(self).banner, type(self).reply)
        shell.terminal = kw
        type(self).shells.append(shell)
        return shell


@pytest.fixture
def shell(monkeypatch):
    """Install a client whose shell plays the scripted CLI; returns the list its shells land in."""
    def install(banner, reply):
        shells = []
        cls = type("Client", (ShellClient,), {"banner": banner, "reply": staticmethod(reply), "shells": shells})
        monkeypatch.setattr(ssh, "paramiko", FakeParamiko(cls))
        return shells
    return install


class NeverConnects:
    def __init__(self, *a, **k):
        raise AssertionError("connected although the request was refused before any device I/O")


@pytest.fixture
def no_connection(monkeypatch):
    monkeypatch.setattr(ssh, "paramiko", FakeParamiko(NeverConnects))


def test_a_junos_edit_over_ssh_commits_through_the_cli_engine_on_a_shell(shell):
    shells = shell(JUNOS_BANNER, junos_cli())
    result = ssh.edit("10.0.0.1", "lab", "p", "set system host-name test\n", 5, 10, vendor_hint="junos@ssh")
    assert isinstance(result, R.EditResult) and result.status == "committed"
    assert "+  host-name test;" in result.diff and result.startswith("COMMIT OK\n\nDIFF:\n")
    (sh,) = shells
    assert sh.typed == ["configure exclusive", "set system host-name test", "show | compare", "commit", "exit"]
    assert sh.terminal == {"term": "vt100", "width": 511, "height": 1000}
    assert sh.closed


def test_a_junos_dry_run_over_ssh_shows_the_diff_and_rolls_the_candidate_back(shell):
    shells = shell(JUNOS_BANNER, junos_cli())
    result = ssh.edit("10.0.0.1", "lab", "p", "set system host-name test\n", 5, 10,
                          vendor_hint="junos@ssh", dry_run=True)
    assert result.status == "dry-run" and "+  host-name test;" in result.diff
    assert shells[0].typed[-2:] == ["rollback 0", "exit"] and "commit" not in shells[0].typed


def test_a_junos_commit_confirmed_over_ssh_arms_the_timer(shell):
    shells = shell(JUNOS_BANNER, junos_cli())
    result = ssh.edit("10.0.0.1", "lab", "p", "set system host-name test\n", 5, 10,
                          vendor_hint="junos@ssh", commit_confirmed=5)
    assert result.status == "confirmed" and result.minutes == 5 and result.pending
    assert "commit confirmed 5" in shells[0].typed


def test_a_refused_lock_is_not_applied_and_nothing_more_is_sent(shell):
    shells = shell(JUNOS_BANNER, junos_cli(lock=LOCKED))
    with pytest.raises(NotAppliedError, match="Failed to lock config: error: configuration database locked"):
        ssh.edit("10.0.0.1", "lab", "p", "set system host-name test\n", 5, 10, vendor_hint="junos@ssh")
    assert shells[0].typed == ["configure exclusive"] and shells[0].closed


def test_a_refused_commit_is_failed_and_the_candidate_discarded(shell):
    shells = shell(JUNOS_BANNER, junos_cli(commit="\r\nerror: configuration check-out failed" + EDIT))
    with pytest.raises(RuntimeError, match="Commit failed: error: configuration check-out failed"):
        ssh.edit("10.0.0.1", "lab", "p", "set system host-name test\n", 5, 10, vendor_hint="junos@ssh")
    assert shells[0].typed[-3:] == ["commit", "rollback 0", "exit"]


def test_a_commit_line_in_a_junos_payload_is_refused_before_connecting(no_connection):
    with pytest.raises(ValueError, match="'commit' is not configuration"):
        ssh.edit("10.0.0.1", "lab", "p", "set system host-name test\ncommit\n", 5, 10, vendor_hint="junos@ssh")


def test_a_commit_line_ending_in_a_semicolon_is_refused_before_connecting(no_connection):
    """#139: `commit;` went past the commit rail, which for a library
    caller is the only one, and was typed in configure mode, a dry run
    too."""
    for payload in ("commit;\n", "set system host-name test\ncommit;\n"):
        with pytest.raises(ValueError, match="'commit' is not configuration"):
            ssh.edit("10.0.0.1", "lab", "p", payload, 5, 10, vendor_hint="junos@ssh", dry_run=True)


def test_an_abbreviated_commit_line_is_refused_before_connecting(no_connection):
    """#139 review: `ssh.edit(payload='set a b\\ncom\\n', vendor_hint='junos@ssh')`
    passed the commit rail and typed `com` in configure mode, which a Junos
    CLI completes to `commit`, a dry run too. Refused before connecting."""
    for payload in ("set system host-name test\ncom\n", "comm;\n", "commi confirmed 1\n"):
        with pytest.raises(ValueError, match="is 'commit' to a Junos CLI, and 'commit' is not configuration"):
            ssh.edit("10.0.0.1", "lab", "p", payload, 5, 10, vendor_hint="junos@ssh", dry_run=True)


# ^C, ^U and DEL, which the Junos line editor acts on as they arrive, a Tab, which completes the word, and
# an ESC or a C1 CSI, which starts a key sequence (#139)
KEYS = ["set system host-name x\x03commit comment y\n", "set a\x15commit\n", "set " + "\x7f" * 4 + "commit\n",
        "\tset system host-name x\n", "set a\x1b[2Kcommit\n", "set a\x9b2Kcommit\n"]


def test_a_payload_the_cli_engine_would_take_as_keys_is_refused_before_connecting(no_connection):
    """#139: a ^C inside a set line, then `commit comment ...`: the device
    dropped the line at the ^C and ran the rest, a commit for good, while a
    dry run said DRY-RUN. Every dialect typed at a shell refuses it, and a
    confirm comment that would type more than the comment, before
    connecting; the plain ssh driver runs no shell."""
    for payload in KEYS:
        with pytest.raises(ValueError, match="which a CLI takes as a key, not as text; nothing was sent to the device"):
            ssh.edit("10.0.0.1", "lab", "p", payload, 5, 10, vendor_hint="junos@ssh", dry_run=True)
        with pytest.raises(ValueError, match="nothing was sent to the device"):
            ssh.edit("10.0.0.1", "lab", "p", payload, 5, 10, vendor_hint="ios@ssh")
    for comment in ('x"\nrollback 1\ncommit', 'x"', "x\ty"):
        with pytest.raises(ValueError, match="the comment .* nothing was sent to the device"):
            ssh.confirm("10.0.0.1", "lab", "p", 5, 10, vendor_hint="junos@ssh", comment=comment)


def test_the_runner_hands_a_library_caller_the_same_refusal(no_connection, tmp_path):
    """#139: run_for_target (and edit() called directly) has no CLI in front
    of it to read a payload first: the transport's own refusal is the one
    it gets, a FAIL with nothing sent, for an -eC payload and a -eB file."""
    broadcast = tmp_path / "all.set"
    broadcast.write_text("set system host-name a\x03commit comment via-runner\n")
    for mode, edit_cmd in (("edit-cmd", "set system host-name a\x03commit comment via-runner"),
                           ("edit-broadcast", None)):
        name, ok, out, _ = runner.run_for_target(
            t=Target("R1", "10.0.0.1", "junos@ssh"), transport="junos@ssh", mode=mode,
            show_cmd=None, edit_cmd=edit_cmd, config_dir=None, broadcast_file=str(broadcast),
            user="lab", passwd="p", session_timeout=5, command_timeout=30,
            dry_run=True, commit_confirmed=None, save_dir=None, quiet=True, max_attempts=1)
        assert ok is False and "has a control character '\\x03'" in out and "nothing was sent to the device" in out


def test_confirm_over_ssh_commits_the_pending_commit_confirmed(shell):
    shells = shell(JUNOS_BANNER, junos_cli())
    result = ssh.confirm("10.0.0.1", "lab", "p", 5, 10, vendor_hint="junos@ssh")
    assert isinstance(result, R.EditResult) and result.status == "confirmed-ok"
    assert shells[0].typed == ["show system commit", "configure exclusive", "commit", "exit"]
    ssh.confirm("10.0.0.1", "lab", "p", 5, 10, vendor_hint="junos@ssh", comment="ok")
    assert shells[1].typed[2] == 'commit comment "ok"'


def test_confirm_with_nothing_pending_sends_only_the_history_read(shell):
    shells = shell(JUNOS_BANNER, junos_cli(history=CLEAN))
    with pytest.raises(NothingToConfirmError, match="nothing to confirm"):
        ssh.confirm("10.0.0.1", "lab", "p", 5, 10, vendor_hint="junos@ssh")
    assert shells[0].typed == ["show system commit"]


def test_confirm_is_only_for_a_junos_dialect(no_connection):
    with pytest.raises(ValueError, match="confirm is only for a Junos dialect, not ios@ssh; nothing was sent"):
        ssh.confirm("10.0.0.1", "u", "p", 5, 10, vendor_hint="ios@ssh")
    with pytest.raises(ValueError, match="not ssh; nothing was sent"):
        ssh.confirm("10.0.0.1", "u", "p", 5, 10, vendor_hint="ssh")


@pytest.mark.parametrize("hint", ["ios@ssh", "nxos@ssh", "eos@ssh"])
def test_an_ios_shaped_edit_over_ssh_types_the_lines_in_config_mode(shell, hint):
    shells = shell("\r\nRouter#", ios_cli)
    result = ssh.edit("10.0.0.1", "u", "p", "hostname x\n", 5, 10, vendor_hint=hint)
    assert result == "(config applied)" and result.status == "applied"
    assert shells[0].typed == ["configure terminal", "hostname x", "end"]


@pytest.mark.parametrize("hint", ["ios@ssh", "nxos@ssh", "eos@ssh"])
def test_an_ios_shaped_edit_over_ssh_stops_at_the_first_refused_line(shell, hint):
    """#142: the lines after a refused line were typed in whatever mode the
    device was in: `shutdown` after a refused `interface Gi0/9` shut the
    interface before it. The edit stops there and types `end`."""
    def no_gi09(line):
        if line == "interface Gi0/9":
            return "\r\n" + " " * 17 + "^\r\n% Invalid input detected at '^' marker.\r\n\r\nRouter(config-if)#"
        return ios_cli(line)
    shells = shell("\r\nRouter#", no_gi09)
    with pytest.raises(RuntimeError, match=r"^'interface Gi0/9': % Invalid input detected at '\^' marker\.; "
                                           r"applied before it: 'interface Gi0/1'; not sent: 'shutdown'$"):
        ssh.edit("10.0.0.1", "u", "p", "interface Gi0/1\ninterface Gi0/9\n shutdown\n", 5, 10, vendor_hint=hint)
    assert shells[0].typed == ["configure terminal", "interface Gi0/1", "interface Gi0/9", "end"] and shells[0].closed


def test_an_edit_with_nothing_to_apply_is_refused_before_connecting(no_connection):
    """#142: an edit of `!` lines on ios@ssh logged in, typed `configure
    terminal` and `end` and said APPLIED, and one of whitespace on the plain
    ssh driver logged in, sent nothing and said ok. Nothing but blank lines
    and comments (the dialect's: '#', and '!' for an IOS-shaped one) is
    refused before connecting, on every dialect without a candidate."""
    for hint, payload, kinds in (("ios@ssh", "! a\n\n  ! b\n# c\n", "'#' or '!'"), ("nxos@ssh", "! x", "'#' or '!'"),
                                 ("eos@ssh", "\n", "'#' or '!'"), ("ssh", "  \n ", "'#'"), (None, "# x\n", "'#'")):
        with pytest.raises(ValueError) as refused:
            ssh.edit("10.0.0.1", "u", "p", payload, 5, 10, vendor_hint=hint)
        assert str(refused.value) == (f"the payload has nothing but blank lines and {kinds} comments in it; "
                                      "nothing was sent to the device"), hint


def test_an_ios_shaped_dialect_refuses_a_dry_run_before_connecting(no_connection):
    with pytest.raises(ValueError, match="not supported by ios@ssh; nothing was sent"):
        ssh.edit("10.0.0.1", "u", "p", "hostname x\n", 5, 10, vendor_hint="ios@ssh", dry_run=True)
    with pytest.raises(ValueError, match="not supported by nxos@ssh"):
        ssh.edit("10.0.0.1", "u", "p", "hostname x\n", 5, 10, vendor_hint="nxos@ssh", commit_confirmed=5)


def test_eos_show_structured_asks_the_exec_channel_for_json(exits_with):
    exits_with(0, stdout=b'{"modelName": "DCS-7050SX3", "sent": "%s"}\n')
    data = ssh.show_structured("10.0.0.1", "u", "p", "show version", 5, 10, vendor_hint="eos@ssh")
    assert data == {"modelName": "DCS-7050SX3", "sent": "show version | json"}
    exits_with(0, stdout=b"Arista DCS-7050SX3\n(%s)\n")
    with pytest.raises(RuntimeError, match=r"'show version \| json' did not return JSON: 'Arista DCS-7050SX3'"):
        ssh.show_structured("10.0.0.1", "u", "p", "show version", 5, 10, vendor_hint="eos@ssh")
    exits_with(0, stdout=b"%% Invalid input (%s)\n")
    with pytest.raises(RuntimeError, match="was refused by the device: % Invalid input"):
        ssh.show_structured("10.0.0.1", "u", "p", "show version", 5, 10, vendor_hint="eos@ssh")


def test_show_structured_is_refused_on_any_other_dialect(no_connection):
    with pytest.raises(ValueError, match="--structured is not supported by junos@ssh; nothing was sent"):
        ssh.show_structured("10.0.0.1", "u", "p", "show version", 5, 10, vendor_hint="junos@ssh")
    with pytest.raises(ValueError, match="--structured is not supported by ssh; nothing was sent"):
        ssh.show_structured("10.0.0.1", "u", "p", "show version", 5, 10)


def test_a_show_is_refused_by_the_dialects_own_rule(exits_with):
    """The Junos CLI says "syntax error, expecting <command>" with no "error:"
    in front: a refusal for junos@ssh, output for the none dialect, which
    knows only "error:" and "% "."""
    exits_with(0, stdout=b"syntax error, expecting <command>: %s\n")
    with pytest.raises(RuntimeError, match="'show versionx' was refused by the device: syntax error, expecting"):
        ssh.show("10.0.0.1", "u", "p", "show versionx", 5, 10, vendor_hint="junos@ssh")
    assert "syntax error" in ssh.show("10.0.0.1", "u", "p", "show versionx", 5, 10, vendor_hint="ssh")
    assert ssh.show_batch("10.0.0.1", "u", "p", ["show versionx"], 5, 10, vendor_hint="junos@ssh")[0]["ok"] is False
    assert ssh.show_batch("10.0.0.1", "u", "p", ["show versionx"], 5, 10)[0]["ok"] is True


def test_the_none_dialect_refuses_a_dry_run_and_a_diff_check(no_connection):
    with pytest.raises(ValueError, match="not supported by ssh; nothing was sent to the device"):
        ssh.edit("10.0.0.1", "u", "p", "hostname x\n", 5, 10, vendor_hint="ssh", dry_run=True)
    with pytest.raises(ValueError, match="not supported by ssh; nothing was sent to the device"):
        ssh.edit("10.0.0.1", "u", "p", "hostname x\n", 5, 10, expected_diff="+ x")
    with pytest.raises(ValueError, match="commit_confirmed is not supported by the 'ssh' transport"):
        ssh.edit("10.0.0.1", "u", "p", "hostname x\n", 5, 10, commit_confirmed=5, dry_run=True)


def test_the_runner_reaches_a_junos_dry_run_over_ssh_through_the_registry(shell):
    shells = shell(JUNOS_BANNER, junos_cli())
    name, ok, out, _ = runner.run_for_target(
        t=Target("R1", "10.0.0.1", "junos@ssh"), transport="junos@ssh", mode="edit-cmd",
        show_cmd=None, edit_cmd="set system host-name test", config_dir=None, broadcast_file=None,
        user="lab", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=True, commit_confirmed=None, save_dir=None, quiet=True, max_attempts=1)
    assert ok is True and "DRY-RUN" in out and "+  host-name test;" in out
    assert shells[0].typed[-2:] == ["rollback 0", "exit"]


def test_the_pin_files_are_parsed_once_per_process_not_per_connection(home, monkeypatch):
    """A 250-device fleet re-parsed its 250-line pin file for every
    connection, under the lock: 250 × 13 ms in a row, growing with the
    square of the fleet. The files are parsed once and shared until they
    change; a pin this process adds is in the shared copy already."""
    from hssh.transports import ssh as T
    pins = pin_file(home)
    pins.parent.mkdir(mode=0o700, exist_ok=True)
    key = paramiko.ECDSAKey.generate()
    seed = paramiko.HostKeys()
    seed.add("10.0.0.1", key.get_name(), key)
    seed.save(str(pins))
    parses = []
    real_parse = T._parse
    monkeypatch.setattr(T, "_parse", lambda text, path, system: parses.append(path) or real_parse(text, path, system))
    T._PINS.clear()

    clients = [paramiko.SSHClient() for _ in range(5)]
    for c in clients:
        T._load_pins(c, str(pins))
    assert parses == [str(pins)]                                           # once, not five times (no ~/.ssh/known_hosts here)
    assert all(c.get_host_keys().lookup("10.0.0.1") for c in clients)      # and every client has the pins

    key2 = paramiko.ECDSAKey.generate()
    T._PinPolicy(str(pins)).missing_host_key(clients[0], "10.0.0.2", key2)  # pins under the lock, from the shared parse
    seen = len(parses)
    late = paramiko.SSHClient()
    T._load_pins(late, str(pins))
    assert len(parses) == seen and late.get_host_keys().lookup("10.0.0.2")   # the shared copy already has it

    other = paramiko.HostKeys()                                             # another process pins 10.0.0.3
    other.load(str(pins))
    key3 = paramiko.ECDSAKey.generate()
    other.add("10.0.0.3", key3.get_name(), key3)
    other.save(str(pins))
    os.utime(pins, ns=(1, 1))                                               # whatever the clock says, the file changed
    seen = len(parses)
    fresh = paramiko.SSHClient()
    T._load_pins(fresh, str(pins))
    assert len(parses) == seen + 1 and fresh.get_host_keys().lookup("10.0.0.3")


# --- #114: the pin file read and written whole, OpenSSH's markers, damaged lines named ---

import base64
import fcntl
import re


def _key_line(host, key):
    return f"{host} {key.get_name()} {key.get_base64()}"


def _pins_with(home, *lines):
    pins = pin_file(home)
    pins.parent.mkdir(mode=0o700, exist_ok=True)
    pins.write_text("".join(line + "\n" for line in lines))
    return pins


def _another_run_pins(pins, host, key, held, goes_on=False):
    """Another run's pin, its lock held on `held`: a new file with the line
    added, renamed over the old one, and the old one's lock let go. One
    that goes on to its next pin at once has the new file locked before it
    lands, and gets it back."""
    new = pins.with_name("known_hosts.new")
    f = open(new, "w")
    if goes_on:
        fcntl.flock(f, fcntl.LOCK_EX)
    f.write(pins.read_text() + _key_line(host, key) + "\n")
    f.flush()
    os.replace(new, pins)
    fcntl.flock(held, fcntl.LOCK_UN)
    held.close()
    if goes_on:
        return f
    f.close()


def test_a_reader_waits_for_a_save_in_progress_and_sees_the_whole_file(home):
    """G1: the pin file was read under the thread lock only, while a save
    truncates it and writes it again under the file lock: a run that read in
    between saw no pins, and under accept-new pinned whatever a re-keyed
    host presented. The read takes the file lock as well."""
    key = paramiko.ECDSAKey.generate()
    pins = _pins_with(home, _key_line("10.0.0.1", key))
    ssh._PINS.clear()
    seen = {}

    def read():
        client = paramiko.SSHClient()
        ssh._load_pins(client, str(pins))
        seen["keys"] = client.get_host_keys()
    with open(pins, "r+") as saving:                  # another run, half-way through a save
        fcntl.flock(saving, fcntl.LOCK_EX)
        saving.truncate(0)
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        reader.join(0.5)
        assert reader.is_alive()                      # waiting for the save, not reading an empty file
        saving.write(_key_line("10.0.0.1", key) + "\n")
        saving.flush()
        fcntl.flock(saving, fcntl.LOCK_UN)
    reader.join(5)
    assert seen["keys"].lookup("10.0.0.1")["ecdsa-sha2-nistp256"] == key


def test_a_pin_that_waited_on_a_file_another_run_replaced_lands_in_the_new_one(home):
    """G1: a pin waits for the lock on the file it opened, while the run
    holding that lock renames a new file over it. Pinning into the old file
    would save over the other run's pin, and the next contact would pin
    that host again on trust. The lock is taken again on the new file."""
    key = paramiko.ECDSAKey.generate()
    pins = _pins_with(home, _key_line("10.0.0.1", key))
    ssh._PINS.clear()
    with open(pins, "r+") as old:                     # another run, half-way through a pin
        fcntl.flock(old, fcntl.LOCK_EX)
        pinning = threading.Thread(daemon=True, target=lambda: ssh._PinPolicy(str(pins)).missing_host_key(
            paramiko.SSHClient(), "10.0.0.3", key))
        pinning.start()
        pinning.join(0.5)
        assert pinning.is_alive()                     # waiting for the lock
        new = pins.with_name("known_hosts.new")
        new.write_text(_key_line("10.0.0.1", key) + "\n" + _key_line("10.0.0.2", key) + "\n")
        os.replace(new, pins)                         # its pin lands
        fcntl.flock(old, fcntl.LOCK_UN)
    pinning.join(5)
    assert [line.split()[0] for line in pins.read_text().splitlines()] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_a_pin_file_another_run_keeps_locked_fails_the_connection_within_the_session_timeout(offline, home):
    """A run stopped with Ctrl-Z in the middle of a pin keeps the pin file
    locked. Another run waited for it with no end, holding this process's
    pin lock while it did, so every one of its workers hung. Reading the
    pins and pinning wait the session timeout at most, and then fail once,
    in words, with nothing sent."""
    pins = _pins_with(home)
    ssh._PINS.clear()

    def connect():
        """(seconds, what ssh.show raised), or None while it is still waiting."""
        done = []

        def run():
            started = _time.monotonic()
            try:
                ssh.show("10.0.0.1", "admin", "s3cret", "show version", 1, 10)
            except Exception as e:
                done.append((_time.monotonic() - started, e))
        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(5)
        return done[0] if done else None
    for held in (fcntl.LOCK_EX, fcntl.LOCK_SH):       # the read waits on the first, the pin on the second
        with open(pins) as other:
            fcntl.flock(other, held)
            failed = connect()
        assert failed is not None, "still waiting for the other run's lock"
        took, error = failed
        assert str(error) == f"{pins} is locked by another h-ssh run (one stopped with Ctrl-Z while it pinned?); resume or end it"
        assert 1 <= took < 3 and runner.is_permanent_failure(error)
    assert offline.auth_calls == [] and pins.read_text() == ""


def test_the_time_queued_behind_this_runs_own_pins_is_not_counted_against_another_runs_lock(home):
    """The session timeout for another run's lock ran from before the
    thread lock: a worker queued behind its own run's pins for longer than
    that failed at its first sight of another run's lock, for good, with
    the message that blames a stopped run. 4 runs of 50 workers pinning at
    once at --session-timeout 1 lost 200 of 800 devices that way. The wait
    starts when the worker holds the thread lock; reading the pins and
    pinning alike."""
    key = paramiko.ECDSAKey.generate()
    pins = _pins_with(home, _key_line("10.0.0.1", key))
    ssh._PINS.clear()
    calls = (lambda: ssh._load_pins(paramiko.SSHClient(), str(pins), 1.0),
             lambda: ssh._PinPolicy(str(pins), 1.0).missing_host_key(paramiko.SSHClient(), "10.0.0.9", key))
    for theirs, call in zip(("10.0.0.2", "10.0.0.3"), calls):
        failed = []

        def run(call):
            try:
                call()
            except Exception as e:
                failed.append(e)
        worker = threading.Thread(target=run, args=(call,), daemon=True)
        with ssh._PIN_LOCK:                           # this run's other workers, pinning for 1.3 s
            worker.start()
            _time.sleep(1.3)
            other = open(pins, "r+")
            fcntl.flock(other, fcntl.LOCK_EX)         # and another run starts a pin
        _time.sleep(0.2)
        _another_run_pins(pins, theirs, key, other)
        worker.join(5)
        assert failed == [] and not worker.is_alive()
    assert [line.split()[0] for line in pins.read_text().splitlines()] == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9"]


def test_a_run_that_keeps_pinning_is_waited_for_past_the_session_timeout(home):
    """Every pin another run makes changes the file, so a lock held through
    a string of them is a run at work, not one stopped with Ctrl-Z. The wait
    gave up a session timeout after it began, however busy the other run
    was, and the device failed for good. It goes on while the file keeps
    changing."""
    key = paramiko.ECDSAKey.generate()
    pins = _pins_with(home, _key_line("10.0.0.1", key))
    ssh._PINS.clear()
    failed = []

    def pin():
        try:
            ssh._PinPolicy(str(pins), 1.0).missing_host_key(paramiko.SSHClient(), "10.0.0.9", key)
        except Exception as e:
            failed.append(e)
    held = open(pins, "r+")
    fcntl.flock(held, fcntl.LOCK_EX)
    worker = threading.Thread(target=pin, daemon=True)
    worker.start()
    theirs = ["10.0.0.2", "10.0.0.3", "10.0.0.4"]
    for host in theirs:                               # 1.5 s of pins, the lock never let go
        _time.sleep(0.5)
        held = _another_run_pins(pins, host, key, held, goes_on=True)
    fcntl.flock(held, fcntl.LOCK_UN)
    held.close()
    worker.join(5)
    assert failed == [] and not worker.is_alive()
    assert [line.split()[0] for line in pins.read_text().splitlines()] == ["10.0.0.1", *theirs, "10.0.0.9"]


def test_the_workers_queued_behind_a_stopped_run_give_up_with_the_first_not_one_timeout_each(home):
    """The wait for another run's lock starts when a worker holds the
    thread lock, so the workers queued there behind a run stopped with
    Ctrl-Z would wait a session timeout each, in turn: 8 workers, 8 s at
    --session-timeout 1. Once one has waited it out on an unchanged file,
    the rest give up at once. Once the run lets go, the next connection
    reads the pins at once, and another run's pin is waited for again."""
    key = paramiko.ECDSAKey.generate()
    pins = _pins_with(home, _key_line("10.0.0.1", key))
    ssh._PINS.clear()
    failed = []

    def connect(i):
        started = _time.monotonic()
        try:
            if i % 2:
                ssh._PinPolicy(str(pins), 1.0).missing_host_key(paramiko.SSHClient(), f"10.0.1.{i}", key)
            else:
                ssh._load_pins(paramiko.SSHClient(), str(pins), 1.0)
        except RuntimeError as e:
            failed.append((_time.monotonic() - started, str(e)))
    workers = [threading.Thread(target=connect, args=(i,), daemon=True) for i in range(8)]
    with open(pins, "r+") as stopped:
        fcntl.flock(stopped, fcntl.LOCK_EX)
        for w in workers:
            w.start()
        for w in workers:
            w.join(10)
    stuck = f"{pins} is locked by another h-ssh run (one stopped with Ctrl-Z while it pinned?); resume or end it"
    assert [error for _, error in failed] == [stuck] * 8
    assert max(took for took, _ in failed) < 2.5, sorted(round(took, 2) for took, _ in failed)
    client = paramiko.SSHClient()
    ssh._load_pins(client, str(pins), 1.0)                                    # resumed: read at once
    other = open(pins, "r+")
    fcntl.flock(other, fcntl.LOCK_EX)                                         # a pin of another run's, the file as it was
    theirs = threading.Timer(0.3, _another_run_pins, (pins, "10.0.0.3", key, other))
    theirs.start()
    ssh._PinPolicy(str(pins), 1.0).missing_host_key(client, "10.0.0.2", key)  # waited for, not given up on
    theirs.join(5)
    assert [line.split()[0] for line in pins.read_text().splitlines()] == ["10.0.0.1", "10.0.0.3", "10.0.0.2"]


def test_a_pin_file_another_run_keeps_locked_starts_no_cooldown(offline, home, tmp_path):
    """The lock is this machine's problem, not the device's: under
    --safety-file it failed the device with a 120 s cooldown, kept in the
    safety file, so the rerun the message asks for was refused too."""
    from hssh.safety import SafetyGate
    pins = _pins_with(home, _key_line("10.0.0.1", offline.server_key))       # pinned already: only a read
    ssh._PINS.clear()
    safety = tmp_path / "safety.json"

    def run():
        return runner.run_for_target(
            t=Target("R1", "10.0.0.1", "ssh"), transport="ssh", mode="show", show_cmd="show version",
            edit_cmd=None, config_dir=None, broadcast_file=None, user="u", passwd="p",
            session_timeout=1, command_timeout=30, dry_run=False, commit_confirmed=None,
            save_dir=None, quiet=True, max_attempts=3, safety_gate=SafetyGate(safety_file=str(safety)))
    with open(pins, "r+") as stopped:
        fcntl.flock(stopped, fcntl.LOCK_EX)                                   # a run stopped with Ctrl-Z mid-pin
        _, ok, out, _ = run()
    assert ok is False and "is locked by another h-ssh run" in out
    _, ok, out, _ = run()                                                     # the stopped run ended: run again
    assert ok, out


def test_a_give_up_does_not_fail_waits_once_the_stopped_run_has_resumed_and_pinned(home):
    """The memo of a given-up wait is the file as it was then: once the
    stopped run resumes and pins (the file changes) and goes straight on to
    its next pin, a wait that meets that lock waits for it, not fails."""
    key = paramiko.ECDSAKey.generate()
    pins = _pins_with(home, _key_line("10.0.0.1", key))
    ssh._PINS.clear()
    stopped = open(pins, "r+")
    fcntl.flock(stopped, fcntl.LOCK_EX)
    with pytest.raises(RuntimeError, match="locked by another h-ssh run"):
        ssh._PinPolicy(str(pins), 0.5).missing_host_key(paramiko.SSHClient(), "10.0.0.8", key)
    held = _another_run_pins(pins, "10.0.0.2", key, stopped, goes_on=True)   # resumed: pins, then its next pin
    out = []

    def pin():
        try:
            ssh._PinPolicy(str(pins), 0.5).missing_host_key(paramiko.SSHClient(), "10.0.0.9", key)
            out.append(None)
        except Exception as e:
            out.append(str(e))
    waiter = threading.Thread(target=pin, daemon=True)
    waiter.start()
    _time.sleep(0.3)
    fcntl.flock(held, fcntl.LOCK_UN)
    held.close()
    waiter.join(5)
    assert out == [None]


def test_a_run_that_pinned_and_then_stopped_is_given_up_on_a_session_timeout_after_its_pin(home):
    """The wait starts again at each change of the file; a holder that
    pinned and then stopped in its next pin is given up on a session
    timeout after that change, not waited for without end."""
    key = paramiko.ECDSAKey.generate()
    pins = _pins_with(home, _key_line("10.0.0.1", key))
    ssh._PINS.clear()
    held = open(pins, "r+")
    fcntl.flock(held, fcntl.LOCK_EX)
    out = []

    def pin():
        started = _time.monotonic()
        try:
            ssh._PinPolicy(str(pins), 1.0).missing_host_key(paramiko.SSHClient(), "10.0.0.9", key)
            out.append((_time.monotonic() - started, None))
        except Exception as e:
            out.append((_time.monotonic() - started, str(e)))
    waiter = threading.Thread(target=pin, daemon=True)
    waiter.start()
    _time.sleep(0.3)
    held = _another_run_pins(pins, "10.0.0.2", key, held, goes_on=True)      # pins, then stops in its next pin
    try:
        waiter.join(5)
        assert out, "still waiting 5 s after the holder stopped"
        took, error = out[0]
        assert error and "locked by another h-ssh run" in error and 1.1 < took < 3.0, out
    finally:
        held.close()


def test_a_host_another_run_pins_during_this_handshake_is_checked_against_that_pin(offline, home, monkeypatch):
    """G1: the pin policy merged the file and then add()ed the key this
    server presented, over a pin another run had written since this one
    read the file: a torn or stale read re-pinned a changed key. The host
    is looked up again under the lock, and a pin found there is checked."""
    theirs = paramiko.ECDSAKey.generate()

    class Racing(FakeTransport):
        def start_client(self, timeout=None):
            # another run pins this host, with the key it was shown, meanwhile
            ssh._PinPolicy(str(pin_file(home))).missing_host_key(paramiko.SSHClient(), "10.0.0.1", theirs)
    monkeypatch.setattr(offline, "transport", Racing)
    with pytest.raises(RuntimeError, match="Host key verification failed for 10.0.0.1: the key is not the one pinned"):
        ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert offline.auth_calls == []
    assert pin_file(home).read_text() == _key_line("10.0.0.1", theirs) + "\n"


def test_a_pin_is_saved_by_replacing_the_file_whole(offline, home, tmp_path):
    """G1: paramiko's save truncated the pin file and wrote it again in
    place. A pin is written to a new file renamed over the old one: a reader
    has the old file or the new one, never a part of either. A pin file
    that is a symlink stays one."""
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    before = pin_file(home).read_text()
    with open(pin_file(home)) as held:                # opened before the next pin, read after it
        ssh.show("10.0.0.2", "admin", "s3cret", "show version", 5, 10)
        assert held.read() == before
    lines = pin_file(home).read_text().splitlines()
    assert lines[0] == before.strip() and lines[1].startswith("10.0.0.2 ecdsa-sha2-nistp256 ")
    assert stat.S_IMODE(pin_file(home).stat().st_mode) == 0o600
    assert [p.name for p in pin_file(home).parent.iterdir()] == ["known_hosts"]     # nothing left behind

    shared = tmp_path / "shared-pins"
    os.replace(pin_file(home), shared)
    pin_file(home).symlink_to(shared)
    ssh.show("10.0.0.3", "admin", "s3cret", "show version", 5, 10)
    assert pin_file(home).is_symlink() and shared.read_text().splitlines()[2].startswith("10.0.0.3 ")


def test_a_pin_keeps_the_files_mode_and_every_byte_of_the_other_lines(offline, home):
    """A pin wrote the text it had read, a byte that is not UTF-8 replaced,
    into a new 0600 file: a pin file shared 0640 lost its group's read, and
    a Latin-1 comment came back changed. The new file has the old one's
    mode, and every line but the new one as it was."""
    key = paramiko.ECDSAKey.generate()
    pins = _pins_with(home)
    before = b"# caf\xe9: the lab's pins\n" + _key_line("10.0.0.9", key).encode() + b"\n"
    pins.write_bytes(before)
    pins.chmod(0o640)
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    after = pins.read_bytes()
    assert after.startswith(before) and after[len(before):].startswith(b"10.0.0.1 ecdsa-sha2-nistp256 ")
    assert stat.S_IMODE(pins.stat().st_mode) == 0o640


def test_a_pin_keeps_the_files_group(offline, home):
    """A pin file shared through its group went to the pinning user's own
    group at the first pin. The new file has the old one's group: another
    of this user's groups, or, as root (CI's containers), any other."""
    pins = _pins_with(home)
    mine = pins.stat().st_gid
    others = [g for g in os.getgroups() if g != mine] or ([65534 if mine != 65534 else 1] if os.geteuid() == 0 else [])
    if not others:
        pytest.skip("this user has no other group to give the pin file")
    os.chown(pins, -1, others[0])
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert pins.read_text().startswith("10.0.0.1 ") and pins.stat().st_gid == others[0]


def test_a_pin_parses_the_pin_file_only_when_another_run_changed_it(home, monkeypatch):
    """Every pin parsed the whole pin file again, one key object a line,
    holding the thread lock and the file lock, even when this process held
    the parse of that very file: 60-100 ms a pin at 3000 pins, one after
    another. A pin starts from the parse this process holds, and parses
    again a file another run changed."""
    key = paramiko.ECDSAKey.generate()
    pins = _pins_with(home, *(_key_line(f"192.168.0.{i}", key) for i in range(20)))
    ssh._PINS.clear()
    parses = []
    real_parse = ssh._parse
    monkeypatch.setattr(ssh, "_parse", lambda text, path, system: parses.append(path) or real_parse(text, path, system))
    ssh._load_pins(paramiko.SSHClient(), str(pins))
    for host in ("10.0.0.1", "10.0.0.2"):
        ssh._PinPolicy(str(pins)).missing_host_key(paramiko.SSHClient(), host, key)
    assert parses == [str(pins)]                                              # the first read's, no more
    with open(pins, "a") as other:                                            # another run pins, in place
        other.write(_key_line("10.0.0.3", key) + "\n")
    ssh._PinPolicy(str(pins)).missing_host_key(paramiko.SSHClient(), "10.0.0.4", key)
    assert parses == [str(pins)] * 2
    client = paramiko.SSHClient()
    ssh._load_pins(client, str(pins))
    assert parses == [str(pins)] * 2
    assert all(client.get_host_keys().lookup(h) for h in ("192.168.0.19", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"))


def test_a_cert_authority_line_in_the_system_file_is_passed_over_and_the_rest_still_counts(offline, home):
    """G2: an @cert-authority line, which an SSH CA puts in every user's
    ~/.ssh/known_hosts, refused every connection as malformed. paramiko
    cannot check a host certificate: the line is passed over, a host known
    only through the CA is pinned on first contact, and the file's own pins
    still count. So does a line of a key type paramiko does not know."""
    ca = paramiko.ECDSAKey.generate()
    dss = base64.b64encode(b"\x00\x00\x00\x07ssh-dss" + bytes(40)).decode()
    system = home / ".ssh" / "known_hosts"
    system.parent.mkdir(mode=0o700)
    system.write_text(f"@cert-authority *.example.net {ca.get_name()} {ca.get_base64()}\n"
                      f"10.0.0.8 ssh-dss {dss}\n"
                      + _key_line("10.0.0.9", offline.server_key) + "\n")
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert pin_file(home).read_text().startswith("10.0.0.1 ecdsa-sha2-nistp256 ")
    ssh.show("10.0.0.9", "admin", "s3cret", "show version", 5, 10)       # known from ~/.ssh/known_hosts
    assert "10.0.0.9" not in pin_file(home).read_text()
    offline.server_key = paramiko.ECDSAKey.generate()
    with pytest.raises(RuntimeError, match="Host key verification failed for 10.0.0.9"):
        ssh.show("10.0.0.9", "admin", "s3cret", "show version", 5, 10)


def test_a_line_of_the_system_file_that_holds_no_key_is_passed_over_as_openssh_does(offline, home):
    """~/.ssh/known_hosts is OpenSSH's, and OpenSSH passes over a line it
    cannot read: one damaged line, for any host, refused every connection
    here while ssh itself and the openssh transport worked. The file's
    other lines still count, and a line with a marker OpenSSH does not have
    is passed over as OpenSSH passes it over. An @revoked line that cannot
    be read is still refused: a revocation is never dropped."""
    key = paramiko.ECDSAKey.generate()
    system = home / ".ssh" / "known_hosts"
    system.parent.mkdir(mode=0o700)
    system.write_text("oldbox ssh-ed25519\n"                                   # too few fields
                      "oldbox ssh-ed25519 AAAA!!!!\n"                          # not base64
                      "oldbox ssh-ed25519 aGVsbG8sIG5vdCBhIGtleQ==\n"          # not a key
                      f"|1|AAAA|{base64.b64encode(b'h' * 20).decode()} {key.get_name()} {key.get_base64()}\n"
                      + _key_line("10.0.0.9", offline.server_key) + "\n")
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert pin_file(home).read_text().startswith("10.0.0.1 ecdsa-sha2-nistp256 ")
    ssh.show("10.0.0.9", "admin", "s3cret", "show version", 5, 10)       # known from ~/.ssh/known_hosts
    assert "10.0.0.9" not in pin_file(home).read_text()
    offline.server_key = paramiko.ECDSAKey.generate()
    with pytest.raises(RuntimeError, match="Host key verification failed for 10.0.0.9"):
        ssh.show("10.0.0.9", "admin", "s3cret", "show version", 5, 10)
    unreadable = f"@revoked * {key.get_name()}"
    system.write_text(unreadable + "\n")
    with pytest.raises(ValueError) as refused:
        ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert str(refused.value) == (f"{system}: malformed known_hosts line 1: {unreadable!r} "
                                  "(expected host, key type and key); fix or remove it")
    system.write_text(f"@revokd * {offline.server_key.get_name()} {offline.server_key.get_base64()}\n")
    ssh.show("10.0.0.2", "admin", "s3cret", "show version", 5, 10)       # no marker of OpenSSH's: passed over
    assert "10.0.0.2 ecdsa-sha2-nistp256 " in pin_file(home).read_text()


def _a_line_lands_during_the_next_read(monkeypatch, path, line, before_the_read=False):
    """The ssh transport's next read of `path`, with `line` appended to the
    file meanwhile by a writer that takes no lock (OpenSSH, a hand edit):
    just after the read, or just before it once it has begun. Returns a
    list that holds True once it has landed."""
    real_open, landed = open, []

    def land():
        with real_open(path, "a") as writer:
            writer.write(line + "\n")
        landed.append(True)

    class Reading:
        def __init__(self, f):
            self.f = f

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.f.close()

        def read(self):
            if before_the_read:
                land()
            data = self.f.read()
            if not before_the_read:
                land()
            return data

    def opening(file, mode="r", *args, **kw):
        f = real_open(file, mode, *args, **kw)
        if mode == "rb" and isinstance(file, int) and not landed and os.fstat(file).st_ino == path.stat().st_ino:
            return Reading(f)
        return f
    monkeypatch.setattr(ssh, "open", opening, raising=False)
    return landed


def test_a_line_openssh_adds_while_the_file_is_read_is_seen_by_the_next_connection(offline, home, monkeypatch):
    """The parse of ~/.ssh/known_hosts was stamped after the read: a line
    OpenSSH appended in between was in the stamp but not in the parse, so
    that host stayed unknown here for the rest of the process (pinned
    again under accept-new, refused under yes; a Fleet lives long). The
    stamp is taken before the read, and a file that changed during it is
    read again by the next connection."""
    system = home / ".ssh" / "known_hosts"
    system.parent.mkdir(mode=0o700)
    system.write_text(_key_line("10.0.0.1", offline.server_key) + "\n")
    landed = _a_line_lands_during_the_next_read(monkeypatch, system, _key_line("10.0.0.2", offline.server_key))
    monkeypatch.setenv("HSSH_HOST_KEY_POLICY", "yes")
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)       # reads the file; OpenSSH appends meanwhile
    ssh.show("10.0.0.2", "admin", "s3cret", "show version", 5, 10)       # known: the line is read
    assert landed and pin_file(home).read_text() == ""


def test_a_pin_parses_a_file_that_changed_while_it_read_it_not_the_copy_it_holds(home, monkeypatch):
    """A pin starts from the parse this process holds when the file is the
    one parsed. A line added by hand, with no lock, as the pin reads the
    file is in the text the pin saves; had the read been taken for the
    file the parse came from, this process's copy would lack it, and that
    host would be pinned here again on trust. A read during which the file
    changed is parsed."""
    key = paramiko.ECDSAKey.generate()
    pins = _pins_with(home, _key_line("10.0.0.1", key))
    ssh._PINS.clear()
    ssh._load_pins(paramiko.SSHClient(), str(pins))
    landed = _a_line_lands_during_the_next_read(monkeypatch, pins, _key_line("10.0.0.2", key), before_the_read=True)
    ssh._PinPolicy(str(pins)).missing_host_key(paramiko.SSHClient(), "10.0.0.3", key)
    client = paramiko.SSHClient()
    ssh._load_pins(client, str(pins))
    assert landed and client.get_host_keys().lookup("10.0.0.2") is not None
    assert [line.split()[0] for line in pins.read_text().splitlines()] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


class _Sshd(paramiko.ServerInterface):
    """Lets anyone in with a password, and notes who tried."""

    def __init__(self, logins):
        self.logins = logins

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.logins.append(username)
        return paramiko.AUTH_SUCCESSFUL


@pytest.fixture
def sshd():
    """paramiko as an SSH server on 127.0.0.1: (port, its host key, the logins it saw)."""
    key = paramiko.ECDSAKey.generate()
    logins, transports = [], []
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(key)
            transports.append(t)
            try:
                t.start_server(server=_Sshd(logins))
            except (paramiko.SSHException, EOFError, OSError):
                pass
    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1], key, logins
    srv.close()
    for t in transports:
        t.close()


def test_a_key_the_system_file_marks_revoked_is_refused_before_any_credential(sshd, home, monkeypatch):
    """G2: an @revoked line refused every connection as malformed. Passed
    over, it would let a key the operator revoked be pinned on first
    contact, or still match an old pin. It is refused whenever a server
    presents it, pinned or not, under every policy, before any password."""
    port, key, logins = sshd
    system = home / ".ssh" / "known_hosts"
    system.parent.mkdir(mode=0o700)
    revoked = f"@revoked * {key.get_name()} {key.get_base64()}\n"
    refused = r"^Host key verification failed for 127\.0\.0\.1: its key is marked @revoked in ~/\.ssh/known_hosts\.$"
    system.write_text(revoked)
    with pytest.raises(RuntimeError, match=refused):
        ssh._connect("127.0.0.1", "u", "p", 5, port)
    assert logins == [] and pin_file(home).read_text() == ""
    system.write_text("")
    ssh._connect("127.0.0.1", "u", "p", 5, port).close()                  # not revoked: in, and pinned
    assert logins == ["u"] and pin_file(home).read_text().startswith(f"[127.0.0.1]:{port} ")
    system.write_text(revoked)
    for policy in ("accept-new", "yes", "no"):
        monkeypatch.setenv("HSSH_HOST_KEY_POLICY", policy)
        with pytest.raises(RuntimeError, match=refused):
            ssh._connect("127.0.0.1", "u", "p", 5, port)
    assert logins == ["u"]


def test_netconf_pins_the_router_on_first_contact_and_refuses_another_key(sshd, home, monkeypatch):
    """#150: the NETCONF session verifies the router's key by default, on
    the store the ssh transport keeps. First contact pins `[host]:port` in
    ~/.h-ssh/known_hosts and logs in; a router whose key is not the one
    pinned is refused before the password goes, and so is one the two
    files disagree on; HSSH_NETCONF_HOSTKEY=no is the opt-out."""
    pytest.importorskip("jnpr.junos")
    from hssh.transports import netconf
    port, key, logins = sshd
    monkeypatch.delenv("HSSH_NETCONF_HOSTKEY", raising=False)
    with pytest.raises(NotAppliedError):            # in; then refused the NETCONF subsystem, being no router
        netconf._open("127.0.0.1", "u", "p", 5, 30, port)
    assert logins == ["u"]
    pinned = pin_file(home).read_text()
    assert pinned == _key_line(f"[127.0.0.1]:{port}", key) + "\n"
    with pytest.raises(NotAppliedError):            # pinned: in again
        netconf._open("127.0.0.1", "u", "p", 5, 30, port)
    assert logins == ["u", "u"] and pin_file(home).read_text() == pinned
    other = paramiko.ECDSAKey.generate()
    pin_file(home).write_text(_key_line(f"[127.0.0.1]:{port}", other) + "\n")        # the router re-keyed
    with pytest.raises(NotAppliedError, match=rf"^NETCONF connect failed: host key verification failed for "
                                              rf"127\.0\.0\.1:{port}: its key is not the one pinned in "
                                              rf"{re.escape(str(pin_file(home)))} \(or ~/\.ssh/known_hosts\); "
                                              rf"if the router was re-keyed, remove its line; nothing was sent$"):
        netconf._open("127.0.0.1", "u", "p", 5, 30, port)
    assert logins == ["u", "u"]
    pin_file(home).write_text(pinned)
    system = home / ".ssh" / "known_hosts"
    system.parent.mkdir(mode=0o700)
    system.write_text(_key_line(f"[127.0.0.1]:{port}", other) + "\n")                # the files disagree
    with pytest.raises(NotAppliedError, match=r"hold different keys for it"):
        netconf._open("127.0.0.1", "u", "p", 5, 30, port)
    assert logins == ["u", "u"]
    monkeypatch.setenv("HSSH_NETCONF_HOSTKEY", "no")                                   # the opt-out: not checked
    with pytest.raises(NotAppliedError):
        netconf._open("127.0.0.1", "u", "p", 5, 30, port)
    assert logins == ["u", "u", "u"]


def test_netconf_host_key_verification_reads_the_system_file_the_same_way(sshd, home, monkeypatch):
    """G2 on the junos transport: with HSSH_NETCONF_HOSTKEY=yes ncclient read
    ~/.ssh/known_hosts with paramiko's load(), and an @cert-authority or
    @revoked line refused every session, `ConnectError for HOST:PORT:
    ('@cert-authority ...', Error(...))`. It is read as the ssh transport
    reads it: the CA line passed over, the file's own lines checked, a key
    it marks @revoked refused before any password."""
    pytest.importorskip("jnpr.junos")
    from hssh.transports import netconf
    port, key, logins = sshd
    monkeypatch.setenv("HSSH_NETCONF_HOSTKEY", "yes")
    ca = paramiko.ECDSAKey.generate()
    system = home / ".ssh" / "known_hosts"
    system.parent.mkdir(mode=0o700)
    lines = f"@cert-authority *.example.net {ca.get_name()} {ca.get_base64()}\n"
    system.write_text(lines)
    with pytest.raises(NotAppliedError, match=rf"^NETCONF connect failed: host key verification failed for "
                                              rf"127\.0\.0\.1:{port}: not pinned in ~/\.h-ssh/known_hosts or "
                                              rf"~/\.ssh/known_hosts \(HSSH_NETCONF_HOSTKEY=yes\); nothing was sent$"):
        netconf._open("127.0.0.1", "u", "p", 5, 30, port)
    assert logins == []
    lines += _key_line(f"[127.0.0.1]:{port}", key) + "\n"
    system.write_text(lines)
    with pytest.raises(NotAppliedError):            # in; then refused the NETCONF subsystem, being no router
        netconf._open("127.0.0.1", "u", "p", 5, 30, port)
    assert logins == ["u"]
    system.write_text(lines + f"@revoked * {key.get_name()} {key.get_base64()}\n")
    with pytest.raises(NotAppliedError, match=rf"^NETCONF connect failed: host key verification failed for "
                                              rf"127\.0\.0\.1:{port}: its key is marked @revoked in "
                                              rf"{re.escape(str(system))}; nothing was sent$"):
        netconf._open("127.0.0.1", "u", "p", 5, 30, port)
    assert logins == ["u"]


@pytest.mark.parametrize("damaged, why", [
    ("10.0.0.1 ecdsa-sha2-nistp256", "expected host, key type and key"),
    ("10.0.0.1 ssh-foo {blob}", "unknown key type ssh-foo"),
    ("10.0.0.1 ssh-ed25519 aGVsbG8sIG5vdCBhIGtleQ==", "the key does not decode as ssh-ed25519"),
    ("10.0.0.1 ssh-ed25519 AAAA!!!!", "the key is not base64"),
    ("|1|AAAA|{hash} ecdsa-sha2-nistp256 {blob}", "a hashed host name that is not |1|salt|hash"),
    ("@revoked 10.0.0.1 ecdsa-sha2-nistp256 {blob}", "markers are read from ~/.ssh/known_hosts only"),
])
def test_a_damaged_pin_line_is_refused_by_name_not_dropped_and_pinned_over(offline, home, damaged, why):
    """G3: paramiko's load dropped such a line without a word: the host
    counted as unknown, was pinned again on trust, and the next save deleted
    the line (another host's too); a hashed name with a bad salt was an
    empty AssertionError, retried. The run is refused with the line, nothing
    sent and nothing rewritten."""
    key = paramiko.ECDSAKey.generate()
    damaged = damaged.format(blob=key.get_base64(), hash=base64.b64encode(b"h" * 20).decode())
    pins = _pins_with(home, _key_line("10.0.0.9", key), damaged)
    before = pins.read_text()
    with pytest.raises(ValueError) as refused:
        ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert str(refused.value) == f"{pins}: malformed known_hosts line 2: {damaged!r} ({why}); fix or remove it"
    assert runner.is_permanent_failure(refused.value)
    assert offline.auth_calls == [] and pins.read_text() == before


def test_a_bad_salt_fails_the_device_once_and_says_which_line(offline, home, capsys):
    """G3: it was `RETRY 1/2 in 1s ()`, `RETRY 2/2 in 3s ()`, then `ERROR: `
    with nothing after it."""
    key = paramiko.ECDSAKey.generate()
    _pins_with(home, f"|1|AAAA|{base64.b64encode(b'h' * 20).decode()} {key.get_name()} {key.get_base64()}")
    name, ok, out, _ = runner.run_for_target(
        t=Target("R1", "10.0.0.1", "ssh"), transport="ssh", mode="show",
        show_cmd="show version", edit_cmd=None, config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=False, commit_confirmed=None, save_dir=None, quiet=False, max_attempts=3)
    assert ok is False
    assert f"ERROR: {pin_file(home)}: malformed known_hosts line 1: '|1|AAAA|" in out
    assert "RETRY" not in capsys.readouterr().out


def test_a_form_feed_in_a_comment_does_not_end_the_line(offline, home):
    """The pin file was split with splitlines(), which also ends a line at
    a form feed (and \\x1c-\\x1e, \\x85, U+2028 and U+2029): a comment with
    one in it refused every connection over a 'damaged' line made of its
    second half, and every line after it was named with the wrong number.
    A line ends at a newline only, as OpenSSH reads it."""
    pins = _pins_with(home, "# lab pins\x0cpage 2", _key_line("10.0.0.1", offline.server_key))
    ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)       # known: nothing refused, nothing pinned
    assert pins.read_text().count("10.0.0.1 ") == 1
    pins.write_text(pins.read_text() + "10.0.0.2 ssh-ed25519\n")
    with pytest.raises(ValueError) as refused:
        ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert str(refused.value) == (f"{pins}: malformed known_hosts line 3: '10.0.0.2 ssh-ed25519' "
                                  "(expected host, key type and key); fix or remove it")


def test_the_key_exchange_has_the_session_timeout_too_not_paramikos_fixed_15_s(monkeypatch):
    """G4: connect() takes no handshake timeout and paramiko's Transport
    gives the key exchange 15 s after the banner: a session timeout above
    that failed at 15 s with an empty EOFError. The transport _connect
    builds has the session timeout there as well."""
    seen = {}

    class Recording(paramiko.SSHClient):
        def connect(self, **kw):
            seen.update(kw)

        def exec_command(self, cmd, timeout=None, **kw):
            return exec_result(b"ok")
    monkeypatch.setattr(ssh, "paramiko", FakeParamiko(Recording))
    ssh.show("10.0.0.1", "u", "p", "show version", 40, 10)
    a, b = socket.socketpair()
    try:
        assert seen["transport_factory"](a).handshake_timeout == 40.0
    finally:
        a.close()
        b.close()


# --- #141: the shell's login types no credentials, whatever the banner says ---

import asyncio
import json
import sqlite3

from hssh import cli


class _ShellSshd(_Sshd):
    """_Sshd with a shell on a pty: `play(channel)` is the device."""

    def __init__(self, logins, play):
        super().__init__(logins)
        self.play = play

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self.play, args=(channel,), daemon=True).start()
        return True


@pytest.fixture
def shell_sshd():
    """shell_sshd(play) -> the port of a paramiko SSH server on 127.0.0.1
    that lets anyone in with a password and plays `play(channel)` on the
    shell it opens."""
    key = paramiko.ECDSAKey.generate()
    opened = []

    def make(play):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        opened.append(srv)

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                t = paramiko.Transport(conn)
                t.add_server_key(key)
                opened.append(t)
                try:
                    t.start_server(server=_ShellSshd([], play))
                except (paramiko.SSHException, EOFError, OSError):
                    pass
        threading.Thread(target=serve, daemon=True).start()
        return srv.getsockname()[1]
    yield make
    for each in opened:
        each.close()


PASSWORD_BANNER = "\r\n--- JUNOS 23.2R1.13 built 2023-06-21\r\nAsk the NOC for the Password: "


def junos_pty(received, banner=PASSWORD_BANNER, pause=0.7):
    """A Junos CLI behind an SSH shell: the banner, `pause` seconds of
    nothing, then its prompt, and what was typed ahead is read once the
    prompt is out. Each line typed is kept in `received`, echoed as a pty
    does and answered; a line the CLI does not know gets `unknown
    command`."""
    def play(channel):
        cfg, candidate = [False], []

        def prompt():
            return "\r\n\r\n[edit]\r\nlab@r1# " if cfg[0] else "\r\n\r\nlab@r1> "

        def answer(line):
            if line == "configure exclusive" and not cfg[0]:
                cfg[0] = True
                return "\r\nEntering configuration mode" + prompt()
            if cfg[0] and line.startswith("set "):
                candidate.append(" ".join(line.split()[2:]))
                return prompt()
            if cfg[0] and line == "show | compare":
                return "".join(f"\r\n[edit system]\r\n+  {stmt};" for stmt in candidate) + prompt()
            if cfg[0] and line == "rollback 0":
                candidate.clear()
                return "\r\nload complete" + prompt()
            if cfg[0] and line == "exit":
                cfg[0] = False
                return "\r\nExiting configuration mode" + prompt()
            return "\r\n          ^\r\nunknown command." + prompt()
        try:
            channel.sendall(banner.encode())
            _time.sleep(pause)
            channel.sendall(prompt().encode())
            _time.sleep(0.1)
            pending = b""
            while True:
                data = channel.recv(4096)
                if not data:
                    return
                pending += data
                while b"\n" in pending:
                    raw, pending = pending.split(b"\n", 1)
                    line = raw.decode(errors="replace").rstrip("\r")
                    received.append(line)
                    channel.sendall((line + answer(line)).encode())
        except (OSError, EOFError):
            pass
    return play


def ios_pty(received, tail, lag=0.2):
    """An IOS CLI behind an SSH shell: a banner whose last line ends in
    `NOC-DESK>`, half a second of nothing, then `tail`, the rest of it and
    the prompt. What was typed ahead is read once that is out; each line
    is kept in `received`, and echoed and answered `lag` seconds after it
    comes, as over a slow link. A line it does not know is refused."""
    def play(channel):
        def answer(line):
            if line == "configure terminal":
                return "\r\nEnter configuration commands, one per line.  End with CNTL/Z.\r\nR1(config)#"
            if line.startswith("interface "):
                return "\r\nR1(config-if)#"
            if line == "end":
                return "\r\nR1#"
            return "\r\n               ^\r\n% Invalid input detected at '^' marker.\r\n\r\nR1(config-if)#"
        try:
            channel.sendall(b"\r\nAuthorized users only - report misuse to NOC-DESK>")
            _time.sleep(0.5)
            channel.sendall(tail.encode())
            pending = b""
            while True:
                data = channel.recv(4096)
                if not data:
                    return
                pending += data
                while b"\n" in pending:
                    raw, pending = pending.split(b"\n", 1)
                    line = raw.decode(errors="replace").rstrip("\r")
                    received.append(line)
                    _time.sleep(lag)
                    channel.sendall((line + answer(line)).encode())
        except (OSError, EOFError):
            pass
    return play


def test_a_banner_that_ends_like_a_prompt_does_not_shift_the_replies(shell_sshd):
    """#141 review: on ios@ssh a banner whose last line ends in `NOC-DESK>`,
    the device pausing half a second before its line break, ended the
    login there, and the rest of the banner was the reply to `configure
    terminal`. With the device answering each line 0.2 s after it, every
    later reply was the one before: the `% Invalid input` for a refused
    line was read as the reply to `end`, and the edit said APPLIED. The
    shell echoes what is typed, so the first reply is read through its
    echo: the refused line fails the edit."""
    received = []
    port = shell_sshd(ios_pty(received, "\r\nChange window 22:00-02:00 only\r\n\r\nR1>"))
    with pytest.raises(RuntimeError, match=r"^'ip addres 10\.0\.0\.1 255\.255\.255\.0': % Invalid input detected"):
        ssh.edit("127.0.0.1", "lab", "pw", "interface Gi0/1\nip addres 10.0.0.1 255.255.255.0\n", 5, 10, port=port,
                 vendor_hint="ios@ssh")
    assert received == ["configure terminal", "interface Gi0/1", "ip addres 10.0.0.1 255.255.255.0", "end"]


def test_a_shell_banner_that_asks_for_a_password_gets_nothing_typed(shell_sshd):
    """#141: login() answered `Password:` on the shell too. A banner ending
    in `Password: `, the prompt 0.7 s later, got the SSH password typed into
    the device CLI on junos@ssh, a dry run too, three times with retries;
    its echo came back as the reply to `configure exclusive` (`Failed to
    lock config: <password>`), and with a CLI that answers the stray line
    with nothing every later reply was the one before. SSH has logged in:
    nothing is typed at the banner, the first line the device gets is
    `configure exclusive`, and the dry run's diff is the compare's."""
    received = []
    port = shell_sshd(junos_pty(received))
    result = ssh.edit("127.0.0.1", "lab", "Pa55-NOC-only", "set system host-name x\n", 5, 10, port=port,
                      vendor_hint="junos@ssh", dry_run=True)
    assert result.status == R.DRY_RUN and result.diff == "[edit system]\n+  host-name x;"
    assert received == ["configure exclusive", "set system host-name x", "show | compare", "rollback 0", "exit"]


def test_the_ssh_password_never_reaches_the_runs_records(shell_sshd, tmp_path, monkeypatch, capsys):
    """#141: the password typed at such a banner came back in the reply,
    so it was the run's error, and the screen, --log, the audit log and the
    store all kept it. Nothing is typed, so no reply can hold it: a dry run
    on junos@ssh behind that banner, every record written, the password in
    none."""
    secret = "Pa55-NOC-only"
    port = shell_sshd(junos_pty([]))
    log, audit, store = tmp_path / "run.jsonl", tmp_path / "audit.jsonl", tmp_path / "runs.db"
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER", "HSSH_STORE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", secret)
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "lab",
                                      "--target", f"R1:127.0.0.1:junos@ssh:{port}",
                                      "-eC", "set system host-name x", "--dry-run",
                                      "--log", str(log), "--audit-log", str(audit), "--store", str(store)])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 0 and "DRY-RUN" in out and "+  host-name x;" in out
    assert json.loads(log.read_text().splitlines()[0])["ok"] is True
    db = sqlite3.connect(str(store))
    try:
        kept = "\n".join(repr(row) for table in ("runs", "results") for row in db.execute(f"SELECT * FROM {table}"))
    finally:
        db.close()
    for where, text in (("stdout", out), ("stderr", err), ("--log", log.read_text()),
                        ("the audit log", audit.read_text()), ("the store", kept)):
        assert text and secret not in text, where


# --- #143: a session lost before the reply ended is not a reply ----------------

class _ExecSshd(_Sshd):
    """_Sshd that answers an exec: `reply(channel, command)` is the device,
    in a thread of its own; `sent` keeps every command it was given."""

    def __init__(self, logins, reply, sent):
        super().__init__(logins)
        self.reply, self.sent = reply, sent

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        self.sent.append(command.decode())
        threading.Thread(target=self.reply, args=(channel, command.decode()), daemon=True).start()
        return True


@pytest.fixture
def exec_sshd():
    """exec_sshd(reply) -> (port, sent): a paramiko SSH server on 127.0.0.1
    that lets anyone in with a password and answers every exec with
    `reply(channel, command)`; `sent` is the commands it got, in order."""
    key = paramiko.ECDSAKey.generate()
    opened = []

    def make(reply):
        sent = []
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        opened.append(srv)

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                t = paramiko.Transport(conn)
                t.add_server_key(key)
                opened.append(t)
                try:
                    t.start_server(server=_ExecSshd([], reply, sent))
                except (paramiko.SSHException, EOFError, OSError):
                    pass
        threading.Thread(target=serve, daemon=True).start()
        return srv.getsockname()[1], sent
    yield make
    for each in opened:
        each.close()


def lost_after(*lines):
    """A device that says `lines`, then loses the session: the connection
    closes with no exit status, no EOF and no channel close before it."""
    def reply(channel, command):
        for line in lines:
            channel.sendall(line.encode() + b"\n")
        _time.sleep(0.2)
        channel.get_transport().close()
    return reply


def no_status(channel, command):
    """A device that ends its output (EOF), closes the channel and never sends an exit status."""
    channel.sendall(b"output-for: " + command.encode() + b"\n")
    channel.shutdown_write()
    _time.sleep(0.1)
    channel.close()


def test_a_session_lost_before_the_command_finished_is_not_its_reply(exec_sshd):
    """paramiko's -1 after the transport died was read as "no status":
    a session lost 0.2 s after the exec was an OK show with empty output,
    and one lost after two lines returned them as the whole reply. The EOF
    is what tells it from a device that ends its output and never sends a
    status (some network OSes): that one gave its whole reply."""
    lost = "connection to 127.0.0.1 lost before 'show interfaces terse' finished"
    for lines in ((), ("xe-0/0/0 up up", "xe-0/0/1 up up")):
        port, sent = exec_sshd(lost_after(*lines))
        with pytest.raises(ConnectionError) as failed:
            ssh.show("127.0.0.1", "u", "p", "show interfaces terse", 5, 5, port=port)
        assert str(failed.value) == lost and not runner.is_permanent_failure(failed.value)
        (entry,) = ssh.show_batch("127.0.0.1", "u", "p", ["show interfaces terse"], 5, 5, port=port)
        assert entry == {"command": "show interfaces terse", "ok": False, "error": lost}
        assert sent == ["show interfaces terse"] * 2
    port, _ = exec_sshd(no_status)
    assert ssh.show("127.0.0.1", "u", "p", "show version", 5, 5, port=port) == (
        "$ show version\noutput-for: show version\n")


def test_a_lost_session_is_tried_again_for_a_read_and_fails_an_edit_once(exec_sshd, monkeypatch):
    """A reset after connecting is retried for a read (README, Failure
    handling); a none-dialect edit line whose session was lost came back
    APPLIED. Its outcome is unknown: FAILED, and never sent again."""
    monkeypatch.setattr(runner, "_backoff", lambda attempt, steps=None: 0)
    port, sent = exec_sshd(lost_after("partial"))

    def run(**kw):
        args = dict(t=Target("R1", "127.0.0.1", "ssh", port), transport="ssh", mode="show",
                    show_cmd=None, edit_cmd=None, config_dir=None, broadcast_file=None, user="u", passwd="p",
                    session_timeout=5, command_timeout=5, dry_run=False, commit_confirmed=None, save_dir=None,
                    quiet=True, max_attempts=3)
        args.update(kw)
        return runner.run_for_target(**args)
    read = run(show_cmd="show version")
    assert not read.ok and read.error == "connection to 127.0.0.1 lost before 'show version' finished"
    assert sent == ["show version"] * 3
    del sent[:]
    edit = run(mode="edit-cmd", edit_cmd="set system host-name r1")
    assert not edit.ok and edit.error == "connection to 127.0.0.1 lost before 'set system host-name r1' finished"
    assert edit.result is None and "APPLIED" not in edit.text
    assert sent == ["set system host-name r1"]


def status_then_lost(*lines):
    """A device whose exit status goes out ahead of the rest of its output,
    as OpenSSH's sshd sends it the moment the command exits, and whose
    session is lost before the rest and the EOF."""
    def reply(channel, command):
        for line in lines:
            channel.sendall(line.encode() + b"\n")
        channel.send_exit_status(0)
        _time.sleep(0.2)
        channel.get_transport().close()
    return reply


def closed_without_eof(channel, command):
    """A device that ends the command by closing its channel, with no EOF
    before the close (SSH allows it) and no exit status, on a session that
    stays up."""
    channel.sendall(b"output-for: " + command.encode() + b"\n")
    _time.sleep(0.1)
    channel.eof_sent = True             # paramiko's close() sends an EOF first unless one went out
    channel.close()


def test_a_session_lost_after_the_exit_status_came_is_not_its_reply(exec_sshd, monkeypatch):
    """Only paramiko's -1 counted as a lost session, and OpenSSH's sshd
    (Junos's too) sends the status as soon as the command exits, with up to
    a window of its output still to go: a session lost in the tail of a big
    reply was status 0 and a complete reply, `show configuration | display
    set` cut to two lines and stored as the baseline. No EOF and the
    transport gone is a lost session whatever status came, and a read is
    tried again; a channel the device closed with no EOF on a session that
    stays up, which was called lost, is the device's answer."""
    monkeypatch.setattr(runner, "_backoff", lambda attempt, steps=None: 0)
    cmd = "show configuration | display set"
    lost = f"connection to 127.0.0.1 lost before '{cmd}' finished"
    port, sent = exec_sshd(status_then_lost("set system host-name r1", "set system services ssh"))
    with pytest.raises(ConnectionError) as failed:
        ssh.show("127.0.0.1", "u", "p", cmd, 5, 5, port=port)
    assert str(failed.value) == lost and not runner.is_permanent_failure(failed.value)
    assert list(ssh.show_batch("127.0.0.1", "u", "p", [cmd], 5, 5, port=port)) == [
        {"command": cmd, "ok": False, "error": lost}]
    del sent[:]
    read = runner.run_for_target(
        t=Target("R1", "127.0.0.1", "ssh", port), transport="ssh", mode="show", show_cmd=cmd,
        edit_cmd=None, config_dir=None, broadcast_file=None, user="u", passwd="p", session_timeout=5,
        command_timeout=5, dry_run=False, commit_confirmed=None, save_dir=None, quiet=True, max_attempts=3)
    assert not read.ok and read.error == lost and sent == [cmd] * 3
    port, _ = exec_sshd(closed_without_eof)
    assert ssh.show("127.0.0.1", "u", "p", "show version", 5, 5, port=port) == (
        "$ show version\noutput-for: show version\n")


def test_a_refusal_on_stdout_fails_the_show_whatever_stderr_says(exits_with):
    """#143: a device that wrote anything to stderr (a warning) had its
    refusal of the show on stdout at exit 0 taken for the show's output."""
    exits_with(0, stderr=b"warning: y\n", stdout=b"error: syntax error, expecting <command>: %s\n")
    refused = "'show foo' was refused by the device: error: syntax error, expecting <command>: show foo"
    with pytest.raises(RuntimeError) as failed:
        ssh.show("10.0.0.1", "u", "p", "show foo", 5, 10)
    assert str(failed.value) == refused
    assert list(ssh.show_batch("10.0.0.1", "u", "p", ["show foo"], 5, 10)) == [
        {"command": "show foo", "ok": False, "error": refused}]
