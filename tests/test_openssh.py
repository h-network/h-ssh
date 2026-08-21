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


def test_secret_is_erased_after_use():
    secret = openssh._secret("hunter2")
    assert bytes(secret) == b"hunter2"
    openssh._burn(secret)
    assert len(secret) == 0


def test_registered_as_a_vendor():
    from hssh.cli import VENDOR_MODULES, VENDOR_INSTALL
    assert VENDORS["openssh"] is openssh
    assert VENDOR_MODULES["openssh"] is openssh
    assert "openssh" in VENDOR_INSTALL


@pytest.fixture
def prompting_ssh(tmp_path):
    """A stub that demands a password on its controlling terminal, as OpenSSH does."""
    script = tmp_path / "ssh-ask"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "fd = os.open('/dev/tty', os.O_RDWR)\n"
        "os.write(fd, b\"admin@host's password: \")\n"
        "secret = b''\n"
        "while not secret.endswith(b'\\n'):\n"
        "    secret += os.read(fd, 1)\n"
        "if secret.strip() != b'hunter2':\n"
        "    os.write(fd, b'\\nPermission denied, please try again.\\n')\n"
        "    sys.exit(255)\n"
        "os.write(fd, b'\\nauthenticated: ' + sys.argv[-1].encode() + b'\\n')\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


@pytest.mark.skipif(not openssh._PTY, reason="no pty on this platform")
def test_pty_answers_the_password_prompt(prompting_ssh):
    result = openssh._pty_run([prompting_ssh, "show version"], bytearray(b"hunter2"), 10)
    assert result.returncode == 0
    assert "authenticated: show version" in result.stdout


@pytest.mark.skipif(not openssh._PTY, reason="no pty on this platform")
def test_pty_never_returns_the_secret(prompting_ssh):
    """A PTY echoes by default; the transcript reaches logs and --save-output."""
    result = openssh._pty_run([prompting_ssh, "show version"], bytearray(b"hunter2"), 10)
    assert "hunter2" not in result.stdout
    assert "password" not in result.stdout.lower()


@pytest.mark.skipif(not openssh._PTY, reason="no pty on this platform")
def test_pty_reports_a_rejected_password(prompting_ssh):
    result = openssh._pty_run([prompting_ssh, "show version"], bytearray(b"wrong"), 10)
    assert result.returncode == 255


@pytest.mark.skipif(not openssh._PTY, reason="no pty on this platform")
def test_pty_times_out_on_a_hung_process(tmp_path):
    script = tmp_path / "ssh-hang"
    script.write_text("#!/bin/sh\nsleep 30\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    import subprocess
    with pytest.raises(subprocess.TimeoutExpired):
        openssh._pty_run([str(script)], bytearray(b"x"), 1)


def test_command_line_is_reproducible():
    line = openssh.ssh_command_line("10.0.1.1", "admin", "show version | match Junos")
    assert line.startswith("ssh -n ")
    assert "admin@10.0.1.1" in line
    assert "'show version | match Junos'" in line
