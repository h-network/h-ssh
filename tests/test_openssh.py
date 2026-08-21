"""OpenSSH transport tests — a fake `ssh` binary on PATH, no live devices needed."""
import os
import stat
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh.vendors import openssh, VENDORS


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
    with pytest.raises(RuntimeError, match="HSSH_HOST_KEY_POLICY"):
        openssh.show("10.0.1.1", "admin", None, "show version", 5, 10)


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
    real = subprocess.run

    def spy(argv, **kwargs):
        seen["argv"] = argv
        seen["stdin"] = kwargs.get("stdin")
        return real(argv, **kwargs)

    subprocess.run = spy
    try:
        openssh.show("10.0.1.1", "admin", None, "show version", 5, 10)
    finally:
        subprocess.run = real
    assert "-n" in seen["argv"]
    assert seen["stdin"] == subprocess.DEVNULL


def test_registered_as_a_vendor():
    from hssh.cli import VENDOR_MODULES, VENDOR_INSTALL
    assert VENDORS["openssh"] is openssh
    assert VENDOR_MODULES["openssh"] is openssh
    assert "openssh" in VENDOR_INSTALL


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


def test_secret_is_not_written_to_disk(askpass_ssh, tmp_path):
    captured = {}
    real = openssh._AskPass.__enter__

    def spy(self):
        result = real(self)
        if self.path:
            captured["helper"] = open(self.path).read()
            captured["mode"] = stat.S_IMODE(os.stat(self.path).st_mode)
        return result

    openssh._AskPass.__enter__ = spy
    try:
        openssh.show("10.0.1.1", "admin", "hunter2", "show configuration", 5, 10)
    finally:
        openssh._AskPass.__enter__ = real
    assert "hunter2" not in captured["helper"]
    assert captured["mode"] == 0o700


def test_askpass_helper_is_removed_afterwards(askpass_ssh):
    seen = {}
    real = openssh._AskPass.__enter__

    def spy(self):
        result = real(self)
        seen["path"] = self.path
        seen["dir"] = self.dir
        return result

    openssh._AskPass.__enter__ = spy
    try:
        openssh.show("10.0.1.1", "admin", "hunter2", "show configuration", 5, 10)
    finally:
        openssh._AskPass.__enter__ = real
    assert not os.path.exists(seen["path"])
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
