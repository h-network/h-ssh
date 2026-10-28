"""Dependency-free SSH transport that drives the OpenSSH client binary, in the
dialect the vendor_hint names (none for the plain `openssh` driver).

Exists for hosts where third-party packages cannot be installed: jump hosts
with no package index, no ensurepip, and no root. Everything here is stdlib
plus the `ssh` binary, which is already present wherever operators log in.

Shows, and the none dialect's edits, run on an exec: one `ssh host cmd` per
command, its exit status and its reply checked (a non-zero status is a
failure, not output, and so is a reply the dialect's CLI opens with a
refusal). Multiple commands reuse one TCP connection and one authentication
via OpenSSH connection multiplexing (ControlMaster), so batch mode keeps
per-command output cleanly separated instead of parsing one merged stream.
A dialect's edits and confirms (junos@openssh, ios@openssh, nxos@openssh,
eos@openssh) go through the CLI engine (hssh.transports.cli) on a pty shell:
`ssh -tt host` with its stdin and stdout piped, because a candidate
configuration, its lock, a diff and a rollback timer need one session that
stays in configuration mode. eos@openssh's structured reads ask the exec for
`<cmd> | json`.

Key auth needs nothing but subprocess. Password auth goes through SSH_ASKPASS:
OpenSSH refuses to read a password from a pipe, so the password is handed to a
helper that OpenSSH execs on its own, over a channel the session never touches.
That holds on the pty shell too: ssh has authenticated through askpass before
the engine reads its first byte.

The obvious alternative — running ssh on a local PTY and answering whatever
looks like a password prompt — is unsafe and was removed. Auth prompts and
device output share one stream there, so output that happens to end in
"...password:" matches the prompt pattern and the password gets typed into the
live session, echoed back, and recorded in the device's command accounting.
There is no pattern that reliably separates the two, which is why the channel
has to be separate.
"""

import json
import math
import os
import re
import select
import shlex
import shutil
import stat
import subprocess
import tempfile
import time
from typing import List, Optional

from .. import drivers
from ..core import refusal_line, refused_reply
from ..dialects.base import Dialect
from ..drivers import results as R
from ..errors import ConnectTimeoutError, NotAppliedError
from .cli import Cli, edit_policy, refuse_comment, refuse_commit_lines, refuse_control_characters
from .connect import (DEFAULT as DEFAULT_CONNECT_TIMEOUT, after_applied, budget, no_banner, tcp_timed_out,
                      where)

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


def _dialect(vendor_hint: Optional[str]) -> Dialect:
    """The dialect behind a vendor_hint: junos@openssh is junos, ios@openssh
    is ios, plain openssh (and None, and a name the registry does not know)
    is none. The hint is a driver's name, alias or canonical."""
    try:
        return drivers.get(vendor_hint or "openssh").dialect
    except ValueError:
        return drivers.NONE


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


def _base_opts(connect_timeout, port: Optional[int],
               control_path: Optional[str], have_password: bool) -> List[str]:
    """ssh's options. `connect_timeout` is the connect phase's seconds:
    OpenSSH's ConnectTimeout bounds the TCP connect and the banner exchange
    together, as --connect-timeout does (#126)."""
    known_hosts = os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")
    opts = [
        "-o", "StrictHostKeyChecking=%s" % _HOST_KEY_POLICY,
        "-o", "UserKnownHostsFile=%s" % known_hosts,
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=%d" % max(1, math.ceil(connect_timeout)),
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
# ...and how far the connect phase got: the TCP connect, or a proxy command
# standing in for it (ProxyJump too), then the device's banner.
_CONNECTED = ("Connection established", "Executing proxy")
_BANNER = "Remote protocol version"
_CONNECTING = re.compile(r"Connecting to \S+(?: \[[^\]]*\])? port (\d+)\.")
# OpenSSH's words when its own ConnectTimeout runs out before this module's clock.
_SSH_NO_BANNER = "timed out during banner exchange"
_SSH_TCP_TIMEOUT = re.compile(r"connect to host \S+ port \d+: Connection timed out")
# Lines of that log that are chatter, not a diagnostic.
_CHATTER = ("debug", "OpenSSH_", "Authenticated to ", "Transferred: ", "Bytes per second: ",
            "Warning: Permanently added ")
_POLL = 0.2
# How long ssh on a pty gets to end on its own once its stdin is closed or
# SIGTERM is sent, and how long an EOF on its stdout gets to become an exit
# status with a reason in the log.
_EXIT_GRACE = 2.0


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
    if _BANNER not in log:
        return "connected, but no SSH banner came"
    return "the banner came, but key exchange or authentication did not finish"


def _where(host: str, port: Optional[int], log: str) -> str:
    """HOST:PORT for a message: the port ssh says it connected to (the
    ~/.ssh/config may set one), else the one given, else 22."""
    m = _CONNECTING.search(log)
    return where(host, m.group(1) if m else (port or 22))


def _past_banner(log: str) -> bool:
    """The device's banner is in ssh's log, or a session is: the connect phase is over."""
    return _BANNER in log or any(marker in log for marker in _SESSION_UP)


def _ran_out(host: str, port: Optional[int], log: str, seconds) -> ConnectTimeoutError:
    """The connect phase ran out on this module's clock: no TCP connection
    by then (nothing in the log says one was made), or a connection and no
    banner."""
    at = _where(host, port, log)
    if any(marker in log for marker in _CONNECTED):
        return ConnectTimeoutError(no_banner(at, seconds))
    return ConnectTimeoutError(tcp_timed_out(at, seconds))


def _ssh_ran_out(host: str, port: Optional[int], log: str, seconds) -> Optional[ConnectTimeoutError]:
    """The same, when ssh's own ConnectTimeout fired first and ssh ended
    the session itself; None for any other end."""
    if any(marker in log for marker in _SESSION_UP):
        return None
    if _SSH_NO_BANNER in log:
        return ConnectTimeoutError(no_banner(_where(host, port, log), seconds))
    if _SSH_TCP_TIMEOUT.search(log):
        return ConnectTimeoutError(tcp_timed_out(_where(host, port, log), seconds))
    return None


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _exec(host: str, user: str, askpass, cmd: str,
          session_timeout: int, command_timeout: int, port: Optional[int],
          control_path: Optional[str], connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> _Result:
    """Run one command through ssh. ConnectTimeout bounds the TCP connect and
    the banner, nothing in OpenSSH bounds the key exchange after it (L9), so
    the session has --session-timeout from the start to be up, judged by ssh's
    own -v log, and the command has --command-timeout from that moment. The
    connect phase has --connect-timeout from the start (#126), on the same
    clock: a ConnectTimeoutError when it runs out, whichever clock fires."""
    connect_s = budget(connect_timeout, session_timeout)
    # "--" ends the options: a host that starts with "-" is still the host,
    # which matters for a library caller that passes no user.
    fd, log_path = tempfile.mkstemp(prefix="hssh-ssh-", suffix=".log")
    os.close(fd)
    argv = (["ssh", "-n", "-v", "-E", log_path]
            + _base_opts(connect_s, port, control_path, askpass.passwd is not None)
            + ["--", "%s@%s" % (user, host) if user else host, cmd])
    try:
        with tempfile.TemporaryFile() as outf, tempfile.TemporaryFile() as errf:
            proc = subprocess.Popen(argv, stdout=outf, stderr=errf, env=askpass.env,
                                    stdin=subprocess.DEVNULL)
            try:
                _wait(proc, host, cmd, log_path, session_timeout, command_timeout, connect_s, port)
            except BaseException:
                proc.kill()
                proc.wait()
                raise
            outf.seek(0)
            errf.seek(0)
            log = _read(log_path)
            if proc.returncode != 0:
                late = _ssh_ran_out(host, port, log, connect_s)
                if late is not None:
                    raise late
            return _Result(argv, proc.returncode,
                           outf.read().decode("utf-8", "replace"),
                           errf.read().decode("utf-8", "replace"),
                           _own_lines(log), log)
    finally:
        try:
            os.unlink(log_path)
        except OSError:
            pass


def _wait(proc, host: str, cmd: str, log_path: str, session_timeout: int, command_timeout: int,
          connect_timeout=None, port: Optional[int] = None) -> None:
    started = time.monotonic()
    deadline = started + session_timeout
    connect_by = None if connect_timeout is None else started + connect_timeout
    session_up = False
    while True:
        until = deadline if connect_by is None else min(deadline, connect_by)
        try:
            proc.wait(timeout=min(_POLL, max(0.0, until - time.monotonic())))
            return
        except subprocess.TimeoutExpired:
            pass
        if not session_up:
            log = _read(log_path)
            if any(marker in log for marker in _SESSION_UP):
                session_up = True
                connect_by = None
                deadline = time.monotonic() + command_timeout
                continue
            if connect_by is not None:
                if _past_banner(log):
                    connect_by = None
                elif time.monotonic() >= connect_by:
                    raise _ran_out(host, port, log, connect_timeout)
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


class ProcessChannel:
    """The ssh binary on a forced remote pty (`ssh -tt`) as the CLI engine's
    Channel. recv(n, timeout) raises TimeoutError when nothing arrived in
    time and ConnectionError when the link failed; an empty read is the peer
    closing, which the engine reports. When ssh itself ended the session,
    its own account of why, from the -E log (a refused password, a rejected
    key, a host key that changed), is the error, not a bare "connection
    closed"."""

    def __init__(self, proc, host: str, log_path: str, argv: List[str], port: Optional[int] = None,
                 connect_timeout=None):
        self.proc = proc
        self.host = host
        self.log_path = log_path
        self.argv = argv
        self.closed = False
        self._log = None          # the log as it stood when the channel was closed
        # The connect phase (#126): the device's banner is due in ssh's log
        # by connect_by; None once it is there, or with no clock at all.
        self.port = port
        self.connect_timeout = connect_timeout
        self.connect_by = None if connect_timeout is None else time.monotonic() + connect_timeout
        self.ran_out: Optional[ConnectTimeoutError] = None     # why the connect phase failed, if it did

    @classmethod
    def open(cls, host: str, user: str, askpass, session_timeout: int,
             port: Optional[int], connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> "ProcessChannel":
        """Start `ssh -tt` to the device with stdin and stdout piped. ssh
        authenticates before the engine reads a byte, through askpass with a
        password; -v to the -E log says how far it got. The terminal is
        vt100, as the paramiko shell asks for, so the device dresses its
        output the same way on both transports. The escape character is
        off (-e none): with a forced tty ssh reads a ~ at the start of a typed
        line as a command to itself (~R, ~B, ~.), keeps it from the device
        and types the rest, so `~Rcommit` would reach it as `commit` (#139)."""
        connect_s = budget(connect_timeout, session_timeout)
        fd, log_path = tempfile.mkstemp(prefix="hssh-ssh-", suffix=".log")
        os.close(fd)
        argv = (["ssh", "-tt", "-e", "none", "-v", "-E", log_path]
                + _base_opts(connect_s, port, None, askpass.passwd is not None)
                + ["--", "%s@%s" % (user, host) if user else host])
        env = askpass.env
        env["TERM"] = "vt100"
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=env, bufsize=0)
        except OSError as exc:
            _unlink(log_path)
            raise RuntimeError("SSH transport failed: %s" % exc) from exc
        return cls(proc, host, log_path, argv, port=port, connect_timeout=connect_s)

    def recv(self, n: int, timeout: float) -> bytes:
        end = time.monotonic() + max(0.0, timeout)
        while True:
            wait = end - time.monotonic()
            if self.connect_by is not None:
                wait = min(wait, self.connect_by - time.monotonic())
            try:
                ready, _, _ = select.select([self.proc.stdout], [], [], max(0.0, wait))
            except (OSError, ValueError) as e:            # the pipe is closed
                raise ConnectionError(f"connection lost: {e}") from e
            if ready:
                break
            if self.connect_by is not None and time.monotonic() >= self.connect_by:
                self._connect_phase_over()
                continue
            raise TimeoutError(f"nothing from {self.host} within {timeout:.1f}s")
        self.connect_by = None                        # something came: the phase is over either way
        try:
            data = os.read(self.proc.stdout.fileno(), n)
        except OSError as e:
            raise ConnectionError(f"connection lost: {e}") from e
        if data:
            return data
        why = self._ended()
        if why:
            raise ConnectionError(why)
        return b""

    def _connect_phase_over(self) -> None:
        """The connect phase's clock ran out: fine when ssh's log has the
        device's banner (or a session) by now, else the session is abandoned
        here, as the exec's is. The engine sees a lost connection; `ran_out`
        keeps the reason for the caller."""
        log = _read(self.log_path)
        if _past_banner(log):
            self.connect_by = None
            return
        self.ran_out = _ran_out(self.host, self.port, log, self.connect_timeout)
        raise ConnectionError(str(self.ran_out))

    def _ended(self) -> Optional[str]:
        """Why ssh's stdout closed, in OpenSSH's words, when ssh exited other
        than cleanly; None for a clean exit, which is the device ending the
        session, and for a process that has not exited yet."""
        try:
            self.proc.wait(timeout=_EXIT_GRACE)
        except subprocess.TimeoutExpired:
            return None
        if self.proc.returncode == 0:
            return None
        log = _read(self.log_path)
        if self.connect_timeout is not None:
            self.ran_out = _ssh_ran_out(self.host, self.port, log, self.connect_timeout)
            if self.ran_out is not None:
                return str(self.ran_out)
        return _describe_failure(self.host, _Result(self.argv, self.proc.returncode, "", "",
                                                    _own_lines(log), log))

    def send(self, data: bytes) -> None:
        view = memoryview(data)
        try:
            while view:
                view = view[self.proc.stdin.write(view):]
            self.proc.stdin.flush()
        except (OSError, ValueError) as e:            # BrokenPipeError: ssh is gone
            raise ConnectionError(f"connection lost: {e}") from e

    def log(self) -> str:
        """ssh's -v log: the file while the session lives, what it held when
        the channel was closed."""
        return _read(self.log_path) if self._log is None else self._log

    def close(self) -> None:
        """End the session. With stdin closed ssh sends EOF and ends with the
        remote shell; one that is still there gets SIGTERM, and SIGKILL after
        a short grace. The log file goes with it."""
        if self.closed:
            return
        self.closed = True
        proc = self.proc
        try:
            proc.stdin.close()
        except OSError:
            pass
        if proc.poll() is None:
            try:
                proc.wait(timeout=_EXIT_GRACE / 4)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=_EXIT_GRACE)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        try:
            proc.stdout.close()
        except OSError:
            pass
        self._log = _read(self.log_path)
        _unlink(self.log_path)


def _shell_session(host: str, user: str, passwd: Optional[str], session_timeout: int,
                   port: Optional[int], dialect: Dialect, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT):
    """(channel, session): a CLI session at the device's own prompt on the
    pty of a fresh `ssh -tt`; the caller closes both (closing the channel
    ends the process). The askpass helper lives only until the prompt is
    seen: ssh has authenticated by then, and login() is handed no
    credentials to type at a banner that asks for one (#141). The remote
    pty echoes every line typed, which the engine is told: the first reply
    is read through its echo, never taken from the rest of a banner.
    login() has session_timeout for the connect, the authentication and the
    banner together, of which the TCP connect and the banner have
    connect_timeout (the channel's clock, #126); when either runs out
    before ssh got a session the error says how far ssh came, as the exec
    path's does, and otherwise which line the device stopped at."""
    if not AVAILABLE:
        raise RuntimeError("no 'ssh' binary found on PATH.")
    with _AskPass(passwd) as askpass:
        channel = ProcessChannel.open(host, user, askpass, session_timeout, port, connect_timeout)
        session = Cli(channel, dialect, session_timeout, echoes=True)
        try:
            session.login()
        except BaseException as exc:
            log = channel.log()
            channel.close()
            if channel.ran_out is not None:
                raise channel.ran_out from exc
            if isinstance(exc, NotAppliedError) and not any(marker in log for marker in _SESSION_UP):
                raise RuntimeError("no SSH session to %s within %ds: %s"
                                   % (host, session_timeout, _phase(log))) from exc
            raise
    return channel, session


def _run_commands(host: str, user: str, passwd: Optional[str], commands: List[str],
                  session_timeout: int, command_timeout: int,
                  port: Optional[int] = None, edit: bool = False,
                  dialect: Optional[Dialect] = None, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> str:
    """One exec per command. The reply counts as well as the exit status: a
    CLI that answers "error: ..." or "% ..." (or whatever the dialect's
    `refused` says) and exits 0 has refused the line (M6), and the edit stops
    there; a show whose reply opens that way got no answer."""
    if not AVAILABLE:
        raise RuntimeError("no 'ssh' binary found on PATH.")

    tmpdir = tempfile.mkdtemp(prefix="hssh-") if len(commands) > 1 else None
    # Unix socket paths cap near 104 bytes, so keep the name short.
    control_path = os.path.join(tmpdir, "cm") if tmpdir else None
    try:
        with _AskPass(passwd) as askpass:
            outputs = []
            for i, cmd in enumerate(commands):
                try:
                    proc = _exec(host, user, askpass, cmd, session_timeout,
                                 command_timeout, port, control_path, connect_timeout)
                except ConnectTimeoutError as exc:
                    if edit and i:
                        # The lines before it were applied: no longer
                        # nothing-was-sent, so the edit is not tried again,
                        # and after Ctrl-C it is not "interrupted while
                        # connecting" either.
                        raise RuntimeError(after_applied(exc, i)) from exc
                    raise
                except OSError as exc:
                    raise RuntimeError("SSH transport failed: %s" % exc)
                if proc.returncode != 0:
                    raise RuntimeError(_describe_failure(host, proc))
                refused = (refusal_line(proc.stderr, proc.stdout, dialect=dialect) if edit
                           else refused_reply(proc.stderr, proc.stdout, dialect=dialect))
                if refused:
                    raise RuntimeError("'%s' was refused by the device: %s" % (cmd, refused))
                outputs.append(_format(cmd, proc))
            text = "\n\n".join(outputs).strip() + "\n"
            return R.EditResult(R.APPLIED, message=text) if edit else text
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
         command_timeout: int, port: int = None, vendor_hint: str = None,
         connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> str:
    """One show command on an exec; a reply the dialect's CLI opens with a
    refusal is a failure, not output. `connect_timeout` bounds the TCP
    connect and the SSH banner, never more than `session_timeout` (every
    function here that connects takes it)."""
    return _run_commands(host, user, passwd, [cmd], session_timeout,
                         command_timeout, port=port, dialect=_dialect(vendor_hint),
                         connect_timeout=connect_timeout)


def edit(host: str, user: str, passwd: str, payload: str, session_timeout: int,
         command_timeout: int, commit_confirmed: int = None, port: int = None,
         vendor_hint: str = None, dry_run: bool = False,
         expected_diff: Optional[str] = None, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> R.EditResult:
    """Push configuration.

    The none dialect (the plain `openssh` driver) runs each line as its own
    exec and applies what it is given: a rollback timer has no equivalent
    there, so asking for one is refused, not dropped, and so are a dry run
    and a diff check. A dialect's edit goes through the CLI engine on a pty
    shell: Junos gets configure exclusive, the lines, show | compare and a
    commit (confirmed with a timer, or rollback 0 for a dry run, or only if
    the diff is still what the dry run showed); an IOS-shaped dialect gets
    configure terminal, the lines, end, and refuses dry_run, commit_confirmed
    and expected_diff before anything is sent. A payload the CLI engine would
    type with a control character or a Tab in it is refused before connecting:
    the CLI takes either as a key (cli.refuse_control_characters).
    """
    d = _dialect(vendor_hint)
    if d is drivers.NONE:
        if commit_confirmed:
            # Junos gets this from NETCONF, where the rollback timer is part of the
            # commit RPC. There is no vendor-neutral equivalent over a raw exec
            # channel, and pretending otherwise would remove the safety net.
            raise RuntimeError(
                "--commit-confirmed is not supported by the 'openssh' transport; "
                "use the 'junos' transport for confirmed commits")
        edit_policy(d, vendor_hint or "openssh", dry_run, None, expected_diff)
        commands = [ln.strip() for ln in payload.strip().splitlines() if ln.strip()]
        return _run_commands(host, user, passwd, commands, session_timeout,
                             command_timeout, port=port, edit=True, dialect=d,
                             connect_timeout=connect_timeout)
    if d.cli is None:
        raise ValueError(f"{vendor_hint}: the {d.title} dialect has no CLI to type at; "
                         "nothing was sent to the device")
    edit_policy(d, vendor_hint, dry_run, commit_confirmed, expected_diff)
    refuse_control_characters(payload)
    if d.cli.has_candidate:
        refuse_commit_lines(payload)
    channel, session = _shell_session(host, user, passwd, session_timeout, port, d, connect_timeout)
    try:
        if d.cli.has_candidate:
            return session.edit_candidate(payload, dry_run=dry_run, confirmed_minutes=commit_confirmed or 0,
                                          expected_diff=expected_diff)
        return session.edit_lines(payload)
    finally:
        session.close()
        channel.close()


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = None,
               connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> List[dict]:
    """Execute multiple commands over one multiplexed SSH connection. A
    connect phase that runs out before any command ran ends the batch as
    one failure, as on the other transports, where a batch has one
    connection: each command after it would cost another connect timeout
    for the same silence (#126). Once a command has its result, the results
    stand: a connect that runs out after that is that command's failure,
    and the batch goes on."""
    if not AVAILABLE:
        raise RuntimeError("no 'ssh' binary found on PATH.")

    d = _dialect(vendor_hint)
    tmpdir = tempfile.mkdtemp(prefix="hssh-")
    control_path = os.path.join(tmpdir, "cm")
    try:
        with _AskPass(passwd) as askpass:
            results = []
            for cmd in cmds:
                try:
                    proc = _exec(host, user, askpass, cmd, session_timeout,
                                 command_timeout, port, control_path, connect_timeout)
                    refused = refused_reply(proc.stderr, proc.stdout, dialect=d) if proc.returncode == 0 else None
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
                    if isinstance(exc, ConnectTimeoutError) and not results:
                        raise           # nothing ran: one failure, which may be tried again
                    results.append({"command": cmd, "ok": False, "error": str(exc)})
            return R.BatchResult(results)
    finally:
        _close_master(host, user, control_path, tmpdir, session_timeout, port)


def confirm(host: str, user: str, passwd: str, session_timeout: int, command_timeout: int,
            port: int = None, vendor_hint: str = "junos@openssh",
            comment: Optional[str] = None, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> R.EditResult:
    """Confirm a pending commit-confirmed on a Junos device through the
    OpenSSH client: `show system commit` must show one waiting, then
    configure exclusive, a bare `commit` (`commit comment "…"` with a
    comment), exit. Only a dialect with a candidate and a commit history has
    anything to confirm. A comment with a control character, a Tab or a
    double quote in it is refused before connecting (cli.refuse_comment)."""
    d = _dialect(vendor_hint)
    if d.cli is None or not d.cli.has_candidate or d.commit_pending is None:
        raise ValueError(f"confirm is only for a Junos dialect, not {vendor_hint}; nothing was sent")
    refuse_comment(comment)
    channel, session = _shell_session(host, user, passwd, session_timeout, port, d, connect_timeout)
    try:
        return session.confirm(command_timeout, comment)
    finally:
        session.close()
        channel.close()


def show_structured(host: str, user: str, passwd: str, cmd: str,
                    session_timeout: int, command_timeout: int,
                    port: int = None, vendor_hint: str = None,
                    binding: Optional[dict] = None, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT):
    """A command's own JSON, for a dialect whose CLI renders one: EOS answers
    `<cmd> | json` with the data its text would show, so an exec runs that
    and the reply is parsed. `binding` is the field map the NETCONF driver
    needs and EOS does not: accepted for the shared signature, ignored. Any
    other dialect refuses before anything is sent."""
    d = _dialect(vendor_hint)
    if d is not drivers.EOS:
        raise ValueError(f"--structured is not supported by {vendor_hint or 'openssh'}; "
                         "nothing was sent to the device")
    if not AVAILABLE:
        raise RuntimeError("no 'ssh' binary found on PATH.")
    full = f"{cmd} | json"
    with _AskPass(passwd) as askpass:
        try:
            proc = _exec(host, user, askpass, full, session_timeout, command_timeout, port, None, connect_timeout)
        except OSError as exc:
            raise RuntimeError("SSH transport failed: %s" % exc)
    if proc.returncode != 0:
        raise RuntimeError(_describe_failure(host, proc))
    refused = refused_reply(proc.stderr, proc.stdout, dialect=d)
    if refused:
        raise RuntimeError("'%s' was refused by the device: %s" % (full, refused))
    try:
        return json.loads(proc.stdout)
    except ValueError:
        first = next((ln.strip() for ln in proc.stdout.splitlines() if ln.strip()), "")
        raise RuntimeError(f"'{full}' did not return JSON: {first!r}") from None


def ssh_command_line(host: str, user: str, cmd: str, session_timeout: int = 8,
                     port: int = None, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> str:
    """The exact command line this module would run, for logs and bug reports."""
    argv = (["ssh", "-n"] + _base_opts(budget(connect_timeout, session_timeout), port, None, False)
            + ["--", "%s@%s" % (user, host) if user else host, cmd])
    return " ".join(shlex.quote(part) for part in argv)
