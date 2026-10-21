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
from hssh.vendors import generic


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
    monkeypatch.setattr(generic, "paramiko", FakeParamiko(OfflineSSHClient))
    monkeypatch.setattr(OfflineSSHClient, "auth_calls", [])
    monkeypatch.setattr(OfflineSSHClient, "server_key", paramiko.ECDSAKey.generate())
    return OfflineSSHClient


def test_first_contact_pins_the_key(offline, home):
    out = generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert "output-for: show version" in out
    lines = pin_file(home).read_text().splitlines()
    assert len(lines) == 1 and lines[0].startswith("10.0.0.1 ecdsa-sha2-nistp256 ")
    assert stat.S_IMODE(pin_file(home).stat().st_mode) == 0o600
    assert offline.auth_calls == [("admin", "s3cret")]


def test_a_changed_key_is_refused_before_any_credential_is_sent(offline, home):
    """Regression: WarningPolicy let an impostor on a known address have the password."""
    generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    pinned = pin_file(home).read_text()
    offline.auth_calls.clear()
    offline.server_key = paramiko.ECDSAKey.generate()
    with pytest.raises(RuntimeError, match="Host key verification failed for 10.0.0.1"):
        generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert offline.auth_calls == []
    assert pin_file(home).read_text() == pinned


def test_a_pinned_key_is_accepted_again(offline, home):
    generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert len(pin_file(home).read_text().splitlines()) == 1
    assert len(offline.auth_calls) == 2


def test_strict_policy_refuses_an_unknown_host(offline, home, monkeypatch):
    monkeypatch.setenv("HSSH_HOST_KEY_POLICY", "yes")
    with pytest.raises(RuntimeError, match="Host key verification failed for 10.0.0.1"):
        generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert offline.auth_calls == []
    assert pin_file(home).read_text() == ""


def test_strict_policy_accepts_a_pinned_host(offline, home, monkeypatch):
    generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    monkeypatch.setenv("HSSH_HOST_KEY_POLICY", "yes")
    out = generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert "output-for: show version" in out


def test_no_policy_warns_and_pins_nothing(offline, home, monkeypatch):
    monkeypatch.setenv("HSSH_HOST_KEY_POLICY", "no")
    with pytest.warns(UserWarning, match="Unknown ecdsa-sha2-nistp256 host key for 10.0.0.1"):
        generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert pin_file(home).read_text() == ""


def test_unknown_policy_is_refused(offline, monkeypatch):
    monkeypatch.setenv("HSSH_HOST_KEY_POLICY", "maybe")
    with pytest.raises(RuntimeError, match="invalid HSSH_HOST_KEY_POLICY"):
        generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)


def test_another_port_is_pinned_under_its_own_name(offline, home):
    generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10, port=2222)
    assert pin_file(home).read_text().startswith("[10.0.0.1]:2222 ecdsa-sha2-nistp256 ")


def test_parallel_first_contacts_are_all_pinned(offline, home):
    """Workers of one run pin at the same time; the file must end up with every host."""
    hosts = ["10.0.0.%d" % i for i in range(1, 9)]
    errors = []

    def contact(host):
        try:
            generic.show(host, "admin", "s3cret", "show version", 5, 10)
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
        monkeypatch.setattr(generic, "paramiko", FakeParamiko(client_cls))
    return install


def test_edit_raises_on_a_non_zero_exit(exits_with):
    """Regression: a failed config line came back as output and the runner printed OK."""
    exits_with(127, stderr=b"sh: 1: configure: not found\n")
    with pytest.raises(RuntimeError, match="exit 127 from 'configure terminal': sh: 1: configure: not found"):
        generic.edit("10.0.0.1", "u", "p", "configure terminal\nhostname NEW\n", 5, 10)


def test_batch_marks_a_non_zero_exit_per_command(exits_with):
    exits_with(1, stderr=b"error: syntax error\n")
    results = generic.show_batch("10.0.0.1", "u", "p", ["show foo"], 5, 10)
    assert results[0]["ok"] is False
    assert "exit 1" in results[0]["error"] and "syntax error" in results[0]["error"]


def test_exit_zero_returns_the_output_block(exits_with):
    exits_with(0)
    assert generic.show("10.0.0.1", "u", "p", "show version", 5, 10) == (
        "$ show version\noutput-for: show version\n")
    results = generic.show_batch("10.0.0.1", "u", "p", ["show version"], 5, 10)
    assert results == [{"command": "show version", "ok": True,
                        "output": "$ show version\noutput-for: show version"}]


def test_no_exit_status_from_the_server_is_not_a_failure(exits_with):
    exits_with(-1)
    assert "output-for: show version" in generic.show("10.0.0.1", "u", "p", "show version", 5, 10)


def test_failure_detail_falls_back_to_stdout(exits_with):
    """Network OSes tend to print their errors on stdout."""
    exits_with(1, stdout=b"error: unknown command: %s\n")
    with pytest.raises(RuntimeError, match="exit 1 from 'show foo': error: unknown command: show foo"):
        generic.show("10.0.0.1", "u", "p", "show foo", 5, 10)


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
    monkeypatch.setattr(generic, "paramiko", FakeParamiko(NoClient))
    with pytest.raises(ValueError, match="not supported by the 'ssh' transport; nothing was sent"):
        generic.edit("10.0.0.1", "u", "p", "hostname NEW\n", 5, 10, commit_confirmed=5)

def test_a_failed_connect_closes_the_client(monkeypatch):
    """A refused login left paramiko's Transport thread and socket behind (#43)."""
    closes = []

    class Refusing(paramiko.SSHClient):
        def connect(self, **kw):
            raise paramiko.AuthenticationException("Authentication failed.")

        def close(self):
            closes.append(1)
            super().close()
    monkeypatch.setattr(generic, "paramiko", FakeParamiko(Refusing))
    with pytest.raises(paramiko.AuthenticationException):
        generic.show("10.0.0.1", "u", "wrong", "show version", 5, 10)
    assert closes == [1]

# --- #45: every wait in exec is bounded ----------------------------------------

import threading
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
    """generic.show(command_timeout=3) was still blocked after 20 s in
    recv_exit_status; Ctrl-C could not end the run."""
    monkeypatch.setattr(generic, "paramiko", FakeParamiko(_stuck_client(status_set=False)))
    t0 = _time.monotonic()
    with pytest.raises(TimeoutError, match="no exit status within 1s"):
        generic.show("10.0.0.1", "u", "p", "show version", 5, 1)
    assert _time.monotonic() - t0 < 3


def test_a_status_that_does_arrive_is_read_as_before(monkeypatch):
    monkeypatch.setattr(generic, "paramiko", FakeParamiko(_stuck_client(status_set=True)))
    assert "partial output" in generic.show("10.0.0.1", "u", "p", "show version", 5, 1)


def test_a_device_that_never_stops_sending_hits_the_deadline(monkeypatch):
    class Endless(io.RawIOBase):
        channel = FakeChannel(0)

        def read(self, n=-1):
            _time.sleep(0.05)
            return b"x" * 1024

    class Client(ExitClient):
        def exec_command(self, cmd, timeout=None):
            return FakeStream(b"", 0), Endless(), FakeStream(b"", 0)
    monkeypatch.setattr(generic, "paramiko", FakeParamiko(Client))
    t0 = _time.monotonic()
    with pytest.raises(TimeoutError, match="still sending"):
        generic.show("10.0.0.1", "u", "p", "show version", 5, 1)
    assert _time.monotonic() - t0 < 3

def test_pinning_takes_a_file_lock_so_two_processes_keep_each_others_pins(offline, home, monkeypatch):
    """The pin file was rewritten whole under a per-process lock (#47)."""
    import fcntl
    locks = []
    real = fcntl.flock

    def recording(fd, op):
        locks.append(op)
        return real(fd, op)
    monkeypatch.setattr(generic.fcntl, "flock", recording)
    generic.show("10.0.0.1", "admin", "s3cret", "show version", 5, 10)
    assert fcntl.LOCK_EX in locks and fcntl.LOCK_UN in locks
    assert pin_file(home).read_text().startswith("10.0.0.1 ")
