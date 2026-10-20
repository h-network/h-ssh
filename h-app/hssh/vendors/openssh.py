"""Dependency-free SSH transport that drives the OpenSSH client binary.

Exists for hosts where third-party packages cannot be installed: jump hosts
with no package index, no ensurepip, and no root. Everything here is stdlib
plus the `ssh` binary, which is already present wherever operators log in.

Key auth needs nothing but subprocess. Password auth goes through SSH_ASKPASS:
OpenSSH refuses to read a password from a pipe, so the password is handed to a
helper that OpenSSH execs on its own, over a channel the session never touches.

The obvious alternative — running ssh on a PTY and answering whatever looks
like a prompt — is unsafe and was removed. Auth prompts and device output share
one stream there, so output that happens to end in "...password:" matches the
prompt pattern and the password gets typed into the live session, echoed back,
and recorded in the device's command accounting. There is no pattern that
reliably separates the two, which is why the channel has to be separate.

Multiple commands reuse one TCP connection and one authentication via OpenSSH
connection multiplexing (ControlMaster), so batch mode keeps per-command
output cleanly separated instead of parsing one merged stream.
"""

import os
import shlex
import shutil
import stat
import subprocess
import tempfile
from typing import List, Optional

AVAILABLE = shutil.which("ssh") is not None

# accept-new trusts a host the first time and pins it after, matching the
# WarningPolicy the paramiko transport uses. Override for stricter sites.
_HOST_KEY_POLICY = os.environ.get("HSSH_HOST_KEY_POLICY", "accept-new")

# SSH_ASKPASS_REQUIRE=force is what lets askpass work with no TTY and no
# DISPLAY. It landed in OpenSSH 8.4; older clients would silently ignore it
# and fall back to prompting on the terminal, so refuse rather than guess.
_MIN_OPENSSH = (8, 4)

# The helper carries no secret. OpenSSH passes its own environment to it, so
# the password travels in the environment of the ssh process, readable only by
# this user. Nothing is written to disk except this three-line script.
_ASKPASS_HELPER = """#!/bin/sh
printf '%s\\n' "$HSSH_ASKPASS_SECRET"
"""


def _openssh_version() -> tuple:
    """(major, minor) of the ssh on PATH, or () if it cannot be determined."""
    try:
        proc = subprocess.run(["ssh", "-V"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return ()
    banner = (proc.stderr or "") + (proc.stdout or "")
    import re
    m = re.search(r"OpenSSH_(\d+)\.(\d+)", banner)
    return (int(m.group(1)), int(m.group(2))) if m else ()


class _AskPass:
    """A short-lived SSH_ASKPASS helper, and the environment that points ssh at it.

    The password reaches OpenSSH through the helper's environment, never through
    the session, so no amount of device output can be mistaken for a prompt.
    """

    def __init__(self, passwd: Optional[str]):
        self.passwd = passwd
        self.dir = None
        self.path = None

    def __enter__(self):
        if not self.passwd:
            return self
        version = _openssh_version()
        if version and version < _MIN_OPENSSH:
            raise RuntimeError(
                "password authentication needs OpenSSH >= %d.%d for "
                "SSH_ASKPASS_REQUIRE (found %d.%d); use key authentication"
                % (_MIN_OPENSSH + version))
        self.dir = tempfile.mkdtemp(prefix="hssh-ap-")
        os.chmod(self.dir, stat.S_IRWXU)
        self.path = os.path.join(self.dir, "askpass")
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(fd, "w") as fh:
            fh.write(_ASKPASS_HELPER)
        return self

    @property
    def env(self) -> dict:
        env = os.environ.copy()
        if not self.passwd:
            return env
        env["SSH_ASKPASS"] = self.path
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["HSSH_ASKPASS_SECRET"] = self.passwd
        # DISPLAY is irrelevant under REQUIRE=force and only invites an X11
        # askpass dialog on a desktop, which would hang a batch run.
        env.pop("DISPLAY", None)
        return env

    def __exit__(self, *_exc):
        if self.path:
            try:
                os.unlink(self.path)
            except OSError:
                pass
        if self.dir:
            try:
                os.rmdir(self.dir)
            except OSError:
                pass
        return False


def _base_opts(session_timeout: int, port: Optional[int],
               control_path: Optional[str], have_password: bool) -> List[str]:
    known_hosts = os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")
    opts = [
        "-o", "StrictHostKeyChecking=%s" % _HOST_KEY_POLICY,
        "-o", "UserKnownHostsFile=%s" % known_hosts,
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=%d" % int(session_timeout),
        "-o", "NumberOfPasswordPrompts=1",
    ]
    if not have_password:
        # No secret to offer, so never let OpenSSH sit on an interactive prompt.
        opts += ["-o", "BatchMode=yes"]
    if port:
        opts += ["-p", str(port)]
    if control_path:
        opts += [
            "-o", "ControlMaster=auto",
            "-o", "ControlPath=%s" % control_path,
            "-o", "ControlPersist=30s",
        ]
    return opts


def _exec(host: str, user: str, askpass, cmd: str,
          session_timeout: int, command_timeout: int, port: Optional[int],
          control_path: Optional[str]):
    argv = (["ssh", "-n"]
            + _base_opts(session_timeout, port, control_path, askpass.passwd is not None)
            + ["%s@%s" % (user, host) if user else host, cmd])
    timeout = float(session_timeout + command_timeout)
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, env=askpass.env,
                          stdin=subprocess.DEVNULL)


def _describe_failure(host: str, proc) -> str:
    """OpenSSH reports the real reason on stderr; surface it instead of an exit code."""
    detail = (proc.stderr or "").strip() or (proc.stdout or "").strip()
    first = detail.splitlines()[0] if detail else ""
    if "Permission denied" in detail or "Authentication failed" in detail:
        return "Authentication failed."
    if "Connection refused" in detail:
        return "Connection refused by %s." % host
    if "Host key verification failed" in detail:
        return ("Host key verification failed for %s. Set HSSH_HOST_KEY_POLICY=no "
                "to skip the check, or fix ~/.ssh/known_hosts." % host)
    if "Could not resolve" in detail or "Name or service not known" in detail:
        return "Cannot resolve %s." % host
    if first:
        return "ssh exit %d: %s" % (proc.returncode, first)
    return "ssh exit %d with no diagnostic output." % proc.returncode


def _format(cmd: str, proc) -> str:
    block = ["$ %s" % cmd]
    out = (proc.stdout or "").rstrip()
    err = (proc.stderr or "").rstrip()
    if out.strip():
        block.append(out)
    if err.strip():
        block.append("STDERR:")
        block.append(err)
    return "\n".join(block)


def _run_commands(host: str, user: str, passwd: Optional[str], commands: List[str],
                  session_timeout: int, command_timeout: int,
                  port: Optional[int] = None) -> str:
    if not AVAILABLE:
        raise RuntimeError("no 'ssh' binary found on PATH.")

    tmpdir = tempfile.mkdtemp(prefix="hssh-") if len(commands) > 1 else None
    # Unix socket paths cap near 104 bytes, so keep the name short.
    control_path = os.path.join(tmpdir, "cm") if tmpdir else None
    try:
        with _AskPass(passwd) as askpass:
            outputs = []
            for cmd in commands:
                try:
                    proc = _exec(host, user, askpass, cmd, session_timeout,
                                 command_timeout, port, control_path)
                except subprocess.TimeoutExpired:
                    raise RuntimeError("Command timed out after %ds: %s"
                                       % (session_timeout + command_timeout, cmd))
                except OSError as exc:
                    raise RuntimeError("SSH transport failed: %s" % exc)
                if proc.returncode != 0:
                    raise RuntimeError(_describe_failure(host, proc))
                outputs.append(_format(cmd, proc))
            return "\n\n".join(outputs).strip() + "\n"
    finally:
        _close_master(host, user, control_path, tmpdir, session_timeout, port)


def _close_master(host: str, user: str, control_path: Optional[str],
                  tmpdir: Optional[str], session_timeout: int,
                  port: Optional[int]) -> None:
    """Drop the multiplexed connection now rather than waiting out ControlPersist."""
    if not control_path:
        return
    try:
        if os.path.exists(control_path):
            subprocess.run(
                ["ssh", "-O", "exit", "-o", "ControlPath=%s" % control_path]
                + (["-p", str(port)] if port else [])
                + ["%s@%s" % (user, host) if user else host],
                capture_output=True, text=True, timeout=float(session_timeout))
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        os.rmdir(tmpdir)
    except OSError:
        pass


def show(host: str, user: str, passwd: str, cmd: str, session_timeout: int,
         command_timeout: int, port: int = None, vendor_hint: str = None) -> str:
    """Execute a show command via the OpenSSH client."""
    return _run_commands(host, user, passwd, [cmd], session_timeout,
                         command_timeout, port=port)


def edit(host: str, user: str, passwd: str, payload: str, session_timeout: int,
         command_timeout: int, commit_confirmed: int = None, port: int = None,
         vendor_hint: str = None) -> str:
    """Execute configuration commands via the OpenSSH client."""
    if commit_confirmed:
        # Junos gets this from NETCONF, where the rollback timer is part of the
        # commit RPC. There is no vendor-neutral equivalent over a raw exec
        # channel, and pretending otherwise would remove the safety net.
        raise RuntimeError(
            "--commit-confirmed is not supported by the 'openssh' transport; "
            "use the 'junos' transport for confirmed commits")
    commands = [ln.strip() for ln in payload.strip().splitlines() if ln.strip()]
    return _run_commands(host, user, passwd, commands, session_timeout,
                         command_timeout, port=port)


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = None) -> List[dict]:
    """Execute multiple commands over one multiplexed SSH connection."""
    if not AVAILABLE:
        raise RuntimeError("no 'ssh' binary found on PATH.")

    tmpdir = tempfile.mkdtemp(prefix="hssh-")
    control_path = os.path.join(tmpdir, "cm")
    try:
        with _AskPass(passwd) as askpass:
            results = []
            for cmd in cmds:
                try:
                    proc = _exec(host, user, askpass, cmd, session_timeout,
                                 command_timeout, port, control_path)
                    if proc.returncode != 0:
                        results.append({"command": cmd, "ok": False,
                                        "error": _describe_failure(host, proc)})
                    else:
                        results.append({"command": cmd, "ok": True,
                                        "output": _format(cmd, proc)})
                except Exception as exc:
                    results.append({"command": cmd, "ok": False, "error": str(exc)})
            return results
    finally:
        _close_master(host, user, control_path, tmpdir, session_timeout, port)


def ssh_command_line(host: str, user: str, cmd: str, session_timeout: int = 8,
                     port: int = None) -> str:
    """The exact command line this module would run, for logs and bug reports."""
    argv = (["ssh", "-n"] + _base_opts(session_timeout, port, None, False)
            + ["%s@%s" % (user, host) if user else host, cmd])
    return " ".join(shlex.quote(part) for part in argv)
