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
    the credentials it was handed instead of sending them anywhere.
    """
    server_key = None
    auth_calls = []

    def connect(self, hostname, port=22, **kw):
        return super().connect(hostname, port=port, sock=FakeSock(type(self).server_key),
                               transport_factory=FakeTransport, **kw)

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


def test_unknown_policy_is_refused(offline, monkeypatch):
    monkeypatch.setenv("HSSH_HOST_KEY_POLICY", "maybe")
    with pytest.raises(RuntimeError, match="invalid HSSH_HOST_KEY_POLICY"):
        ssh.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)


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


def test_every_phase_of_the_connect_has_the_session_timeout_the_channel_open_too(monkeypatch):
    """paramiko gives connect, banner, auth and the channel open each their
    own clock; the last one defaults to an hour. A device that authenticates
    and then never answers the shell's channel open held a worker that long."""
    seen = {}

    class Recording(paramiko.SSHClient):
        def connect(self, **kw):
            seen.update(kw)

        def exec_command(self, cmd, timeout=None, **kw):
            return exec_result(b"ok")
    monkeypatch.setattr(ssh, "paramiko", FakeParamiko(Recording))
    ssh.show("10.0.0.1", "u", "p", "show version", 7, 10)
    assert (seen["timeout"], seen["banner_timeout"], seen["auth_timeout"], seen["channel_timeout"]) == (7.0, 7.0, 7.0, 7.0)

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
    assert fcntl.LOCK_EX in locks and fcntl.LOCK_UN in locks
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
    real_load = paramiko.HostKeys.load
    monkeypatch.setattr(paramiko.HostKeys, "load", lambda self, path: parses.append(path) or real_load(self, path))
    T._PINS.clear()

    clients = [paramiko.SSHClient() for _ in range(5)]
    for c in clients:
        T._load_pins(c, str(pins))
    assert parses == [str(pins)]                                           # once, not five times (no ~/.ssh/known_hosts here)
    assert all(c.get_host_keys().lookup("10.0.0.1") for c in clients)      # and every client has the pins

    key2 = paramiko.ECDSAKey.generate()
    T._PinPolicy(str(pins)).missing_host_key(clients[0], "10.0.0.2", key2)  # pins under the lock: one merge parse
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
