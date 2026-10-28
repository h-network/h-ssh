"""OpenSSH transport tests — a fake `ssh` binary on PATH, no live devices needed."""
import json
import os
import stat
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import drivers
from hssh.transports import openssh


@pytest.fixture
def fake_ssh(tmp_path, monkeypatch):
    """Put a stub `ssh` on PATH that echoes its command back, or fails on demand."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "ssh"
    script.write_text(
        "#!/bin/sh\n"
        'if [ -n "$FAKE_SSH_STDERR" ]; then echo "$FAKE_SSH_STDERR" >&2; fi\n'
        'if [ "$FAKE_SSH_RC" != "" ] && [ "$FAKE_SSH_RC" != "0" ]; then exit "$FAKE_SSH_RC"; fi\n'
        'for arg in "$@"; do last="$arg"; done\n'
        'echo "output-for: $last"\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(openssh, "AVAILABLE", True)
    return script


def test_available_reflects_ssh_on_path(fake_ssh, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    import shutil
    assert shutil.which("ssh") is None


def test_show_returns_command_output(fake_ssh):
    out = openssh.show("10.0.1.1", "admin", None, "show version", 5, 10)
    assert "$ show version" in out
    assert "output-for: show version" in out


def test_show_maps_auth_failure(fake_ssh, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_RC", "255")
    monkeypatch.setenv("FAKE_SSH_STDERR", "Permission denied (publickey,password).")
    with pytest.raises(RuntimeError, match="Authentication failed."):
        openssh.show("10.0.1.1", "admin", None, "show version", 5, 10)


def test_show_maps_host_key_failure(fake_ssh, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_RC", "255")
    monkeypatch.setenv("FAKE_SSH_STDERR", "Host key verification failed.")
    with pytest.raises(RuntimeError, match="not the one pinned") as exc:
        openssh.show("10.0.1.1", "admin", None, "show version", 5, 10)
    assert "HSSH_HOST_KEY_POLICY=no" not in str(exc.value)      # no coaching to skip the check (#47)


def test_show_reports_unmapped_stderr_verbatim(fake_ssh, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_RC", "255")
    monkeypatch.setenv("FAKE_SSH_STDERR", "kex_exchange_identification: banner line")
    with pytest.raises(RuntimeError, match="banner line"):
        openssh.show("10.0.1.1", "admin", None, "show version", 5, 10)


def test_batch_returns_one_entry_per_command(fake_ssh):
    cmds = ["show version", "show chassis hardware", "show interfaces terse"]
    results = openssh.show_batch("10.0.1.1", "admin", None, cmds, 5, 10)
    assert [r["command"] for r in results] == cmds
    assert all(r["ok"] for r in results)
    # Alignment is the point: multiplexing must not merge the streams.
    assert "output-for: show chassis hardware" in results[1]["output"]


def test_batch_records_per_command_failure(fake_ssh, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_RC", "255")
    monkeypatch.setenv("FAKE_SSH_STDERR", "Connection refused")
    results = openssh.show_batch("10.0.1.1", "admin", None, ["show version"], 5, 10)
    assert results[0]["ok"] is False
    assert "Connection refused" in results[0]["error"]


def test_edit_runs_each_payload_line(fake_ssh):
    out = openssh.edit("10.0.1.1", "admin", None,
                       "set system host-name r1\nset system domain-name lab\n", 5, 10)
    assert "output-for: set system host-name r1" in out
    assert "output-for: set system domain-name lab" in out


def test_edit_refuses_commit_confirmed(fake_ssh):
    with pytest.raises(RuntimeError, match="not supported by the 'openssh' transport"):
        openssh.edit("10.0.1.1", "admin", None, "set a b", 5, 10, commit_confirmed=5)


def test_batchmode_set_only_without_password():
    keyed = openssh._base_opts(8, None, None, have_password=False)
    passworded = openssh._base_opts(8, None, None, have_password=True)
    assert "BatchMode=yes" in keyed
    assert "BatchMode=yes" not in passworded


def test_control_options_only_when_multiplexing():
    plain = openssh._base_opts(8, None, None, False)
    muxed = openssh._base_opts(8, None, "/tmp/x/cm", False)
    assert not any("ControlMaster" in o for o in plain)
    assert "ControlMaster=auto" in muxed
    assert "ControlPath=/tmp/x/cm" in muxed


def test_port_is_passed_through():
    assert "-p" in openssh._base_opts(8, 2222, None, False)
    assert "2222" in openssh._base_opts(8, 2222, None, False)


def test_ssh_never_inherits_local_stdin(fake_ssh):
    """-n plus DEVNULL stdin: nothing local can reach the remote command."""
    import subprocess
    seen = {}
    real = subprocess.Popen

    def spy(argv, **kwargs):
        seen["argv"] = argv
        seen["stdin"] = kwargs.get("stdin")
        return real(argv, **kwargs)

    subprocess.Popen = spy
    try:
        openssh.show("10.0.1.1", "admin", None, "show version", 5, 10)
    finally:
        subprocess.Popen = real
    assert "-n" in seen["argv"]
    assert seen["stdin"] == subprocess.DEVNULL


def test_host_follows_an_end_of_options_marker(fake_ssh, tmp_path):
    """A host like -oProxyCommand=... must reach ssh as the host, never as an
    option. The CLI always sends user@host; a library caller may send no user."""
    import subprocess
    seen = []
    real_run, real_popen = subprocess.run, subprocess.Popen

    def spy_run(argv, **kwargs):
        seen.append(argv)
        return real_run(argv, **kwargs)

    def spy_popen(argv, **kwargs):
        seen.append(argv)
        return real_popen(argv, **kwargs)

    mux = tmp_path / "mux"
    mux.mkdir()
    (mux / "cm").write_text("")
    subprocess.run, subprocess.Popen = spy_run, spy_popen
    try:
        openssh.show("-oProxyCommand=x", None, None, "uptime", 5, 10)     # Popen
        openssh._close_master("-oProxyCommand=x", None, str(mux / "cm"), str(mux), 5, None)   # run
    finally:
        subprocess.run, subprocess.Popen = real_run, real_popen
    login, command, close = seen[:3]        # (subprocess.run's own Popen comes after)
    assert login[-2:] == ["--", "-oProxyCommand=x"] and "-N" in login
    assert command[-3:] == ["--", "-oProxyCommand=x", "uptime"]
    assert close[-2:] == ["--", "-oProxyCommand=x"]
    line = openssh.ssh_command_line("-oProxyCommand=x", None, "uptime")
    assert line.endswith(" -- -oProxyCommand=x uptime")


def test_registered_as_a_vendor():
    from hssh import cli
    driver = drivers.get("openssh")
    assert driver.name == "none@openssh" and driver.aliases == ("openssh",)
    assert drivers.module_of(driver) is openssh
    assert driver.transport.install == "the OpenSSH client ('ssh' on PATH)"
    assert cli.drivers is drivers      # one registry; the CLI and its probe read the same one


@pytest.fixture
def askpass_ssh(tmp_path, monkeypatch):
    """A stub ssh that authenticates only via SSH_ASKPASS and records session input.

    It also emits device output whose tail looks exactly like a password prompt,
    which is the shape that made the old PTY implementation type the password
    into the live session.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "ssh"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import os, subprocess, sys, select\n"
        "helper = os.environ.get('SSH_ASKPASS')\n"
        "if not helper or os.environ.get('SSH_ASKPASS_REQUIRE') != 'force':\n"
        "    sys.stderr.write('no askpass configured\\n'); sys.exit(255)\n"
        "got = subprocess.run([helper, 'p'], capture_output=True, text=True).stdout.strip()\n"
        "if got != 'hunter2':\n"
        "    sys.stderr.write('Permission denied (password).\\n'); sys.exit(255)\n"
        "print('authentication-order password:')\n"
        "print('radius-server 10.0.0.1;')\n"
        "r, _, _ = select.select([sys.stdin], [], [], 0.3)\n"
        "if r:\n"
        "    data = sys.stdin.read()\n"
        "    if data.strip():\n"
        "        print('SESSION-RECEIVED:' + data.strip())\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(openssh, "AVAILABLE", True)
    return script


def test_password_auth_goes_through_askpass(askpass_ssh):
    out = openssh.show("10.0.1.1", "admin", "hunter2", "show configuration", 5, 10)
    assert "radius-server 10.0.0.1;" in out


def test_wrong_password_fails_cleanly(askpass_ssh):
    with pytest.raises(RuntimeError, match="Authentication failed."):
        openssh.show("10.0.1.1", "admin", "wrong", "show configuration", 5, 10)


def test_password_never_reaches_the_session(askpass_ssh):
    """Regression: device output ending in '...password:' once matched the prompt
    pattern on the PTY, and the password was typed into the live session."""
    out = openssh.show("10.0.1.1", "admin", "hunter2", "show configuration", 5, 10)
    assert "SESSION-RECEIVED" not in out


def test_password_never_appears_in_output(askpass_ssh):
    out = openssh.show("10.0.1.1", "admin", "hunter2", "show configuration", 5, 10)
    assert "hunter2" not in out


def test_device_output_is_never_rewritten(askpass_ssh):
    """Regression: scrubbing prompt-shaped lines deleted real config from output."""
    out = openssh.show("10.0.1.1", "admin", "hunter2", "show configuration", 5, 10)
    assert "authentication-order password:" in out


def test_the_helper_holds_no_secret_and_the_secret_file_beside_it_is_0600(askpass_ssh, tmp_path):
    """The helper is a script; the password is a 0600 file beside it in the
    helper's 0700 directory, for the login alone (#151: it travelled in the
    ssh process's environment before)."""
    captured = {}
    real = openssh._AskPass.__enter__

    def spy(self):
        result = real(self)
        if self.path:
            captured["helper"] = open(self.path).read()
            captured["mode"] = stat.S_IMODE(os.stat(self.path).st_mode)
            captured["dir_mode"] = stat.S_IMODE(os.stat(self.dir).st_mode)
            captured["secret"] = open(self.secret).read()
            captured["secret_mode"] = stat.S_IMODE(os.stat(self.secret).st_mode)
        return result

    openssh._AskPass.__enter__ = spy
    try:
        openssh.show("10.0.1.1", "admin", "hunter2", "show configuration", 5, 10)
    finally:
        openssh._AskPass.__enter__ = real
    assert "hunter2" not in captured["helper"]
    assert captured["mode"] == 0o700 and captured["dir_mode"] == 0o700
    assert captured["secret"] == "hunter2\n" and captured["secret_mode"] == 0o600


def test_askpass_helper_is_removed_afterwards(askpass_ssh):
    seen = {}
    real = openssh._AskPass.__enter__

    def spy(self):
        result = real(self)
        seen["path"] = self.path
        seen["secret"] = self.secret
        seen["dir"] = self.dir
        return result

    openssh._AskPass.__enter__ = spy
    try:
        openssh.show("10.0.1.1", "admin", "hunter2", "show configuration", 5, 10)
    finally:
        openssh._AskPass.__enter__ = real
    assert not os.path.exists(seen["path"])
    assert not os.path.exists(seen["secret"])
    assert not os.path.exists(seen["dir"])


def test_no_askpass_configured_without_a_password(fake_ssh):
    with openssh._AskPass(None) as ap:
        assert "SSH_ASKPASS" not in ap.env
        assert ap.path is None


def test_old_openssh_is_refused_for_password_auth(monkeypatch):
    monkeypatch.setattr(openssh, "_openssh_version", lambda: (8, 3))
    with pytest.raises(RuntimeError, match="OpenSSH >= 8.4"):
        with openssh._AskPass("hunter2"):
            pass


def test_version_is_parsed_from_the_banner():
    version = openssh._openssh_version()
    assert version == () or (isinstance(version, tuple) and len(version) == 2)


def test_command_line_is_reproducible():
    line = openssh.ssh_command_line("10.0.1.1", "admin", "show version | match Junos")
    assert line.startswith("ssh -n ")
    assert "admin@10.0.1.1" in line
    assert "'show version | match Junos'" in line


def test_the_child_environment_does_not_carry_hssh_password(monkeypatch):
    """HSSH_PASSWORD was inherited by ssh, the ControlMaster daemon and any
    ProxyCommand helper (#42); the askpass channel is the only carrier."""
    from hssh.transports.openssh import _AskPass
    monkeypatch.setenv("HSSH_PASSWORD", "Pa55w0rd-FROM-ENV")
    with _AskPass("Pa55w0rd-FROM-ENV") as ap:
        env = ap.env
        assert "HSSH_PASSWORD" not in env and env["SSH_ASKPASS"] == ap.path
        assert "Pa55w0rd-FROM-ENV" not in env.values()           # #151: nor in HSSH_ASKPASS_SECRET, as it was
        assert open(ap.secret).read() == "Pa55w0rd-FROM-ENV\n"   # the helper reads it from here
    with _AskPass(None) as ap:
        assert "HSSH_PASSWORD" not in ap.env


@pytest.fixture
def recording_ssh(askpass_ssh):
    """askpass_ssh, recording every invocation's arguments and environment
    in FAKE_SSH_ENV_LOG, answering `ssh -V` as OpenSSH 9.6, making the
    ControlPath on the login (`-N`) and removing it on `-O exit`, as ssh
    does, so every child a call runs is seen."""
    askpass_ssh.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, subprocess, sys\n"
        "with open(os.environ['FAKE_SSH_ENV_LOG'], 'a') as f:\n"
        "    f.write(json.dumps({'argv': sys.argv[1:], 'env': dict(os.environ)}) + '\\n')\n"
        "if '-V' in sys.argv:\n"
        "    sys.stderr.write('OpenSSH_9.6p1\\n'); sys.exit(0)\n"
        "cp = next((a.split('=', 1)[1] for a in sys.argv if a.startswith('ControlPath=')), None)\n"
        "if '-O' in sys.argv:\n"
        "    if 'exit' in sys.argv and cp and os.path.exists(cp):\n"
        "        os.unlink(cp)\n"
        "    sys.exit(0)\n"
        "helper = os.environ.get('SSH_ASKPASS')\n"
        "if not helper or os.environ.get('SSH_ASKPASS_REQUIRE') != 'force':\n"
        "    sys.stderr.write('no askpass configured\\n'); sys.exit(255)\n"
        "got = subprocess.run([helper, 'p'], capture_output=True, text=True).stdout.strip()\n"
        "if got != 'hunter2':\n"
        "    sys.stderr.write('Permission denied (password).\\n'); sys.exit(255)\n"
        "if '-N' in sys.argv and cp:\n"
        "    open(cp, 'w').close()\n"
        "print('radius-server 10.0.0.1;')\n"
    )
    return askpass_ssh


def test_no_ssh_child_carries_the_password_in_its_environment(recording_ssh, tmp_path, monkeypatch):
    """#151: the password rode in HSSH_ASKPASS_SECRET in the environment of
    every ssh (the login, each command, the -tt edit session), which a
    same-user process reads from /proc/<pid>/environ and a ProxyCommand
    inherits; `ssh -V` and `ssh -O exit` ran with HSSH_PASSWORD. The helper
    reads the secret from the 0600 file beside it, and the children that
    need no credential get no HSSH_PASSWORD either."""
    log = tmp_path / "ssh-env.jsonl"
    monkeypatch.setenv("FAKE_SSH_ENV_LOG", str(log))
    monkeypatch.setenv("HSSH_PASSWORD", "hunter2")
    out = openssh.show("10.0.1.1", "admin", "hunter2", "show configuration", 5, 10)
    assert "radius-server 10.0.0.1;" in out                                 # authenticated, through the helper
    calls = [json.loads(ln) for ln in log.read_text().splitlines()]
    kinds = [("-V" if "-V" in c["argv"] else "-O" if "-O" in c["argv"] else "-N" if "-N" in c["argv"] else "command")
             for c in calls]
    assert sorted(kinds) == ["-N", "-O", "-V", "command"], kinds             # the version, the login, the command, the master's exit
    for c in calls:
        assert "hunter2" not in json.dumps(c["env"]), c["argv"]
        assert "HSSH_PASSWORD" not in c["env"] and "HSSH_ASKPASS_SECRET" not in c["env"], c["argv"]


# --- #143: the server's login banner is not a command's stderr ----------------------

import shlex
import shutil
import socket
import threading
import time


@pytest.fixture
def real_ssh(tmp_path, monkeypatch):
    """The OpenSSH client on PATH, behind a wrapper that keeps the user's
    ~/.ssh/config out of it, with a private HOME; skipped where there is
    none, or one too old for a password through askpass."""
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
    if openssh._openssh_version() < (8, 4):
        pytest.skip("password auth needs OpenSSH 8.4")


def _device(channel, command):
    """A device's answer to an exec: Junos's refusal of `show foo` on
    stdout at exit 0, a `Permission denied` of its own on stderr at exit 1,
    a warning of its own on stderr beside its output, an exit 255 of its
    own, a session lost under `show log auth` after a line of its reply and
    under `set system services ssh` (sshd restarting), and anything else's
    output."""
    rc = 0
    if command in ("show log auth", "set system services ssh"):
        if command == "show log auth":
            channel.sendall(b"Oct 28 r1 sshd[1]: Failed password for root: Permission denied\n")
        time.sleep(0.2)
        channel.get_transport().close()
        return
    if command == "show foo":
        channel.sendall(b"error: syntax error, expecting <command>\n")
    elif command == "cat /etc/shadow":
        channel.sendall_stderr(b"cat: /etc/shadow: Permission denied\n")
        rc = 1
    elif command == "request support information":
        channel.sendall_stderr(b"error: another request is running\n")
        rc = 255
    else:
        channel.sendall(b"output-for: " + command.encode() + b"\n")
        if command == "show log messages":
            channel.sendall_stderr(b"warning: log file rotated\n")
    channel.send_exit_status(rc)
    channel.close()


@pytest.fixture
def banner_sshd():
    """banner_sshd(banner) -> (port, logins): a paramiko SSH server on
    127.0.0.1 that sends `banner` as its login message (SSH's userauth
    banner, the Junos `system login message`), lets user lab in with
    password hunter2 and answers each exec as _device does; `logins` is
    every login that got in."""
    paramiko = pytest.importorskip("paramiko")
    key = paramiko.ECDSAKey.generate()
    opened = []

    class Sshd(paramiko.ServerInterface):
        def __init__(self, banner, logins):
            self.banner, self.logins = banner, logins

        def get_banner(self):
            return self.banner, "en-US"

        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, password):
            if (username, password) != ("lab", "hunter2"):
                return paramiko.AUTH_FAILED
            self.logins.append(username)
            return paramiko.AUTH_SUCCESSFUL

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_channel_exec_request(self, channel, command):
            threading.Thread(target=_device, args=(channel, command.decode()), daemon=True).start()
            return True

    def make(banner):
        logins = []
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
                    t.start_server(server=Sshd(banner, logins))
                except (paramiko.SSHException, EOFError, OSError):
                    pass
        threading.Thread(target=serve, daemon=True).start()
        return srv.getsockname()[1], logins
    yield make
    for each in opened:
        each.close()


def device(port, call, *args, **kw):
    """openssh.<call>("127.0.0.1", "lab", "hunter2", *args, 10, 10, port=port, **kw)"""
    return getattr(openssh, call)("127.0.0.1", "lab", kw.pop("passwd", "hunter2"), *args, 10, 10, port=port, **kw)


def test_the_login_banner_is_kept_out_of_every_commands_stderr(banner_sshd, real_ssh):
    """`-v` put ssh's log level over `-o LogLevel=ERROR`, so OpenSSH printed
    the server's login message into the command's stderr: a STDERR block
    on every output and store row, and on junos@openssh a refusal on stdout
    hidden behind it, `show foo` an OK show and the refusal its output.
    Each call logs in once, on a ControlMaster whose stderr is its own; the
    device's stderr is still the device's."""
    port, logins = banner_sshd("Welcome to r1\n")
    assert device(port, "show", "show version") == "$ show version\noutput-for: show version\n"
    assert device(port, "show_batch", ["show version", "show chassis hardware"]) == [
        {"command": "show version", "ok": True, "output": "$ show version\noutput-for: show version"},
        {"command": "show chassis hardware", "ok": True,
         "output": "$ show chassis hardware\noutput-for: show chassis hardware"}]
    assert device(port, "show", "show log messages") == (
        "$ show log messages\noutput-for: show log messages\nSTDERR:\nwarning: log file rotated\n")
    with pytest.raises(RuntimeError, match=r"^'show foo' was refused by the device: error: syntax error, "
                                           r"expecting <command>$"):
        device(port, "show", "show foo", vendor_hint="junos@openssh")
    assert logins == ["lab"] * 4                       # one login a call, the batch's too


def test_a_login_message_that_starts_with_error_fails_no_show(banner_sshd, real_ssh):
    """A cRPD with `system login message "error: in maintenance window"`
    failed every show over openssh as refused by the device, while ssh
    was OK; a show the device refuses still fails."""
    port, _ = banner_sshd("error: in maintenance window\n")
    assert device(port, "show", "show version", vendor_hint="junos@openssh") == (
        "$ show version\noutput-for: show version\n")
    results = device(port, "show_batch", ["show version", "show foo"], vendor_hint="junos@openssh")
    assert [r["ok"] for r in results] == [True, False]
    assert results[1]["error"] == "'show foo' was refused by the device: error: syntax error, expecting <command>"


def test_a_devices_permission_denied_is_its_failure_not_a_failed_login(banner_sshd, real_ssh):
    """What a command says on its stderr is the device's, not ssh's: a
    command the device answered `Permission denied` at exit 1 was
    "Authentication failed.", which a failed login still is."""
    port, logins = banner_sshd("Welcome to r1\n")
    said = "exit 1 from 'cat /etc/shadow': cat: /etc/shadow: Permission denied"
    with pytest.raises(RuntimeError) as failed:
        device(port, "show", "cat /etc/shadow")
    assert str(failed.value) == said
    (entry,) = device(port, "show_batch", ["cat /etc/shadow"])
    assert entry == {"command": "cat /etc/shadow", "ok": False, "error": said}
    with pytest.raises(RuntimeError, match=r"^Authentication failed\.$"):
        device(port, "show", "show version", passwd="wrong")
    assert logins == ["lab"] * 2


def test_a_session_lost_under_a_command_is_lost_not_the_devices_words(banner_sshd, real_ssh, monkeypatch):
    """Every command runs through the login's ControlMaster, and a session
    lost under one takes the master with it: ssh exits 255 with nothing of
    its own in its log, and that was read as the device's failure, in the
    first line of the reply cut short. A line with `Permission denied` in
    it made a lost read a permanent failure, sent once; in a batch the next
    command logged in by itself, its banner in its stderr. The master gone
    (`ssh -O check`) is a lost session, as on the ssh transport: a read is
    tried again, an edit line FAILED once, never APPLIED, and the next
    command of a batch logs in again."""
    from hssh import runner
    from hssh.core import Target
    monkeypatch.setattr(runner, "_backoff", lambda attempt, steps=None: 0)
    port, logins = banner_sshd("Welcome to r1\n")
    lost = "connection to 127.0.0.1 lost before 'show log auth' finished"
    with pytest.raises(ConnectionError) as failed:
        device(port, "show", "show log auth")
    assert str(failed.value) == lost and not runner.is_permanent_failure(failed.value)
    assert device(port, "show_batch", ["show log auth", "show version"]) == [
        {"command": "show log auth", "ok": False, "error": lost},
        {"command": "show version", "ok": True, "output": "$ show version\noutput-for: show version"}]
    with pytest.raises(RuntimeError) as failed:          # the device's own 255, the master still up
        device(port, "show", "request support information")
    assert str(failed.value) == "exit 255 from 'request support information': error: another request is running"

    def run(**kw):
        args = dict(t=Target("R1", "127.0.0.1", "openssh", port), transport="openssh", mode="show",
                    show_cmd=None, edit_cmd=None, config_dir=None, broadcast_file=None, user="lab",
                    passwd="hunter2", session_timeout=10, command_timeout=10, dry_run=False,
                    commit_confirmed=None, save_dir=None, quiet=True, max_attempts=3)
        args.update(kw)
        return runner.run_for_target(**args)
    del logins[:]
    read = run(show_cmd="show log auth")
    assert not read.ok and read.error == lost and logins == ["lab"] * 3      # one login an attempt
    del logins[:]
    edit = run(mode="edit-cmd", edit_cmd="set system services ssh")
    assert not edit.ok and edit.error == "connection to 127.0.0.1 lost before 'set system services ssh' finished"
    assert edit.result is None and "APPLIED" not in edit.text and logins == ["lab"]
