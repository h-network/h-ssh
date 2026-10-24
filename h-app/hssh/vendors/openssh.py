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
import time
from typing import List, Optional

from ..core import refusal_line, refused_reply

AVAILABLE = shutil.which("ssh") is not None

# accept-new trusts a host the first time and pins it after. The paramiko
# transport reads the same variable and pins in ~/.h-ssh/known_hosts; this
# one leaves pinning to ssh and ~/.ssh/known_hosts. Override for stricter sites.
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
        # The password reaches ssh through the askpass channel only; the
        # variable the operator set is not for ssh, the ControlMaster daemon
        # (which outlives the run) or any ProxyCommand helper to inherit.
        env.pop("HSSH_PASSWORD", None)
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
    if have_password:
        # The password is the credential, as on the junos and ssh transports:
        # no ~/.ssh/id_* and no agent key is offered first, so a wrong
        # password is a failed login and not an OK by way of a key (M5).
        opts += ["-o", "PubkeyAuthentication=no", "-o", "IdentitiesOnly=yes"]
    else:
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


# ssh's own log, written with -v to the -E file, says when the session is up:
# the first connection prints "Authenticated to HOST" and "Entering interactive
# session", a command riding the ControlMaster prints "master session id".
_SESSION_UP = ("Authenticated to ", "Entering interactive session", "master session id")
# Lines of that log that are chatter, not a diagnostic.
_CHATTER = ("debug", "OpenSSH_", "Authenticated to ", "Transferred: ", "Bytes per second: ",
            "Warning: Permanently added ")
_POLL = 0.2


class _Result:
    """What _exec hands back: the command's own stdout and stderr, and ssh's
    diagnostics (its non-debug log lines) apart from them."""

    def __init__(self, args, returncode, stdout, stderr, diag, log=""):
        self.args, self.returncode, self.stdout, self.stderr, self.diag = args, returncode, stdout, stderr, diag
        self.log = log      # ssh's whole -v log, for the phase a failure happened in


def _own_lines(log: str) -> str:
    return "\n".join(ln for ln in log.splitlines() if ln.strip() and not ln.startswith(_CHATTER))


def _phase(log: str) -> str:
    """How far the session got, from ssh's log."""
    if "Connection established" not in log:
        return "no TCP connection"
    if "Remote protocol version" not in log:
        return "connected, but no SSH banner came"
    return "the banner came, but key exchange or authentication did not finish"


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _exec(host: str, user: str, askpass, cmd: str,
          session_timeout: int, command_timeout: int, port: Optional[int],
          control_path: Optional[str]) -> _Result:
    """Run one command through ssh. ConnectTimeout bounds the TCP connect and
    the banner, nothing in OpenSSH bounds the key exchange after it (L9), so
    the session has --session-timeout from the start to be up, judged by ssh's
    own -v log, and the command has --command-timeout from that moment."""
    # "--" ends the options: a host that starts with "-" is still the host,
    # which matters for a library caller that passes no user.
    fd, log_path = tempfile.mkstemp(prefix="hssh-ssh-", suffix=".log")
    os.close(fd)
    argv = (["ssh", "-n", "-v", "-E", log_path]
            + _base_opts(session_timeout, port, control_path, askpass.passwd is not None)
            + ["--", "%s@%s" % (user, host) if user else host, cmd])
    try:
        with tempfile.TemporaryFile() as outf, tempfile.TemporaryFile() as errf:
            proc = subprocess.Popen(argv, stdout=outf, stderr=errf, env=askpass.env,
                                    stdin=subprocess.DEVNULL)
            try:
                _wait(proc, host, cmd, log_path, session_timeout, command_timeout)
            except BaseException:
                proc.kill()
                proc.wait()
                raise
            outf.seek(0)
            errf.seek(0)
            log = _read(log_path)
            return _Result(argv, proc.returncode,
                           outf.read().decode("utf-8", "replace"),
                           errf.read().decode("utf-8", "replace"),
                           _own_lines(log), log)
    finally:
        try:
            os.unlink(log_path)
        except OSError:
            pass


def _wait(proc, host: str, cmd: str, log_path: str, session_timeout: int, command_timeout: int) -> None:
    deadline = time.monotonic() + session_timeout
    session_up = False
    while True:
        try:
            proc.wait(timeout=min(_POLL, max(0.0, deadline - time.monotonic())))
            return
        except subprocess.TimeoutExpired:
            pass
        if not session_up:
            log = _read(log_path)
            if any(marker in log for marker in _SESSION_UP):
                session_up = True
                deadline = time.monotonic() + command_timeout
                continue
        if time.monotonic() >= deadline:
            if not session_up:
                raise RuntimeError("no SSH session to %s within %ds: %s"
                                   % (host, session_timeout, _phase(_read(log_path))))
            raise RuntimeError("Command timed out after %ds: %s" % (command_timeout, cmd))


def _describe_failure(host: str, proc) -> str:
    """OpenSSH reports the real reason in its own log; surface it instead of an exit code."""
    detail = ((getattr(proc, "diag", "") or "").strip() or (proc.stderr or "").strip()
              or (proc.stdout or "").strip())
    first = detail.splitlines()[0] if detail else ""
    if "Permission denied" in detail or "Authentication failed" in detail:
        return "Authentication failed."
    if "Connection closed by" in detail and _password_offered(getattr(proc, "log", "")):
        # Junos sshd (cRPD too) drops the connection after a refused password
        # instead of answering "Permission denied".
        return ("Authentication failed: %s closed the connection after the password was offered "
                "(wrong password, or password login is off on the server)." % host)
    if "Connection refused" in detail:
        return "Connection refused by %s." % host
    if "Host key verification failed" in detail:
        return ("Host key verification failed for %s: the key is not the one pinned. "
                "If the device was re-keyed, remove its line from ~/.ssh/known_hosts." % host)
    if "Could not resolve" in detail or "Name or service not known" in detail:
        return "Cannot resolve %s." % host
    if first:
        return "ssh exit %d: %s" % (proc.returncode, first)
    return "ssh exit %d with no diagnostic output." % proc.returncode


def _password_offered(log: str) -> bool:
    """ssh's -v log says when a password went out: the askpass helper was
    asked, or password was the authentication method being tried."""
    return ("requested to askpass" in log or "Next authentication method: password" in log
            or "Next authentication method: keyboard-interactive" in log)


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
                  port: Optional[int] = None, edit: bool = False) -> str:
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
                except OSError as exc:
                    raise RuntimeError("SSH transport failed: %s" % exc)
                if proc.returncode != 0:
                    raise RuntimeError(_describe_failure(host, proc))
                # The reply counts as well as the exit status: a CLI that
                # answers "error: ..." or "% ..." and exits 0 has refused the
                # line (M6); a show whose reply opens that way got no answer.
                refused = (refusal_line(proc.stderr, proc.stdout) if edit
                           else refused_reply(proc.stderr, proc.stdout))
                if refused:
                    raise RuntimeError("'%s' was refused by the device: %s" % (cmd, refused))
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
                + ["--", "%s@%s" % (user, host) if user else host],
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
                         command_timeout, port=port, edit=True)


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
                    refused = refused_reply(proc.stderr, proc.stdout) if proc.returncode == 0 else None
                    if proc.returncode != 0:
                        results.append({"command": cmd, "ok": False,
                                        "error": _describe_failure(host, proc)})
                    elif refused:
                        results.append({"command": cmd, "ok": False,
                                        "error": "'%s' was refused by the device: %s" % (cmd, refused)})
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
            + ["--", "%s@%s" % (user, host) if user else host, cmd])
    return " ".join(shlex.quote(part) for part in argv)
