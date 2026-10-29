"""Dependency-free SSH transport that drives the OpenSSH client binary, in the
dialect the vendor_hint names (none for the plain `openssh` driver).

Exists for hosts where third-party packages cannot be installed: jump hosts
with no package index, no ensurepip, and no root. Everything here is stdlib
plus the `ssh` binary, which is already present wherever operators log in.

Shows, and the none dialect's edits, run on an exec: one `ssh host cmd` per
command, its exit status and its reply checked (a non-zero status is a
failure, not output, and so is a reply the dialect's CLI opens with a
refusal). Each call logs in once, on a ControlMaster (`ssh -N`, which goes
to the background once the session is up), and every command, a lone
show's too, runs through it as an ssh of its own: per-command output stays
cleanly separated instead of parsed out of one merged stream, and OpenSSH's
print of the server's login banner, which goes to the stderr of the ssh
that logs in, never lands in a command's.
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
from .cli import (Cli, edit_policy, refuse_comment, refuse_commit_lines, refuse_control_characters,
                  refuse_empty_edit)
from .connect import (DEFAULT as DEFAULT_CONNECT_TIMEOUT, after_applied, budget, no_banner, tcp_timed_out,
                      where)
from . import ssh as _ssh
from .ssh import host_key_policy, _known_hosts as _pin_file

AVAILABLE = shutil.which("ssh") is not None

# The host-key policy and the pin store are the ssh transport's (#150): one
# HSSH_HOST_KEY_POLICY, read per call and refused unless it is one of the
# three, and one ~/.h-ssh/known_hosts, where OpenSSH pins what it trusts
# (host_key_policy and _pin_file, imported above).

# SSH_ASKPASS_REQUIRE=force is what lets askpass work with no TTY and no
# DISPLAY. It landed in OpenSSH 8.4; older clients would silently ignore it
# and fall back to prompting on the terminal, so refuse rather than guess.
_MIN_OPENSSH = (8, 4)

# The helper carries no secret: it prints the 0600 file beside it, which
# holds the password in the helper's 0700 directory for the call alone (the
# login and the commands on its session; a `-tt` session until its prompt)
# and goes with it. The password used to ride in the ssh process's environment,
# which any process of this user reads from /proc/<pid>/environ and a
# ProxyCommand inherits (#151).
_ASKPASS_HELPER = """#!/bin/sh
cat "${0%/*}/secret"
"""


def _without_password() -> dict:
    """The environment for an ssh that needs no credential (`-V`, `-O check`,
    `-O exit`): HSSH_PASSWORD is the operator's, not its to inherit (#151)."""
    return {k: v for k, v in os.environ.items() if k != "HSSH_PASSWORD"}


def _openssh_version() -> tuple:
    """(major, minor) of the ssh on PATH, or () if it cannot be determined."""
    try:
        proc = subprocess.run(["ssh", "-V"], capture_output=True, text=True, timeout=10, env=_without_password())
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

    The password reaches OpenSSH through the helper, which reads it from the
    file beside it, never through the session, so no amount of device output
    can be mistaken for a prompt.
    """

    def __init__(self, passwd: Optional[str]):
        self.passwd = passwd
        self.dir = None
        self.path = None
        self.secret = None

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
        try:
            os.chmod(self.dir, stat.S_IRWXU)
            self.path = os.path.join(self.dir, "askpass")
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
            with os.fdopen(fd, "w") as fh:
                fh.write(_ASKPASS_HELPER)
            self.secret = os.path.join(self.dir, "secret")
            fd = os.open(self.secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(self.passwd + "\n")
        except BaseException:
            # A `with` that failed to enter is never exited: what was made
            # (the directory, the helper, part of the secret) goes here.
            self.__exit__(None, None, None)
            raise
        return self

    @property
    def env(self) -> dict:
        env = os.environ.copy()
        # The password reaches ssh through the askpass channel only; the
        # variable the operator set is not for ssh, the ControlMaster daemon
        # (which outlives the run) or any ProxyCommand helper to inherit, and
        # neither is the password itself: the helper reads it from its file.
        env.pop("HSSH_PASSWORD", None)
        if not self.passwd:
            return env
        env["SSH_ASKPASS"] = self.path
        env["SSH_ASKPASS_REQUIRE"] = "force"
        # DISPLAY is irrelevant under REQUIRE=force and only invites an X11
        # askpass dialog on a desktop, which would hang a batch run.
        env.pop("DISPLAY", None)
        return env

    def __exit__(self, *_exc):
        for made in (self.secret, self.path):
            if made:
                try:
                    os.unlink(made)
                except OSError:
                    pass
        if self.dir:
            try:
                os.rmdir(self.dir)
            except OSError:
                pass
        return False


def _quoted(path: str) -> str:
    """A path as one word of an ssh option that takes several."""
    return '"%s"' % path if any(c.isspace() for c in path) else path


def _system_file() -> str:
    return os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")


def _refuse_disagreement(host: str, user: str, port: Optional[int]) -> None:
    """Before the ssh that logs in runs (once a session, not once a
    command): a host ~/.h-ssh/known_hosts and ~/.ssh/known_hosts hold
    different keys for is refused, as the ssh transport refuses it (the
    review's repro, #150): with both files in UserKnownHostsFile OpenSSH
    takes a match in either, so the key pinned in one was overridden by
    the other and the password went. The host is looked up under the name
    OpenSSH looks it up under, which its configuration decides (a
    HostKeyAlias; else the HostName, as `[name]:port` off port 22, the
    Port there counting where the target names none): `ssh -G` says what
    it is, read as the probe reads it, since a check under the name as
    given would miss what a `Port` or `HostName` stanza moved. Both files
    are read as the ssh transport reads them, by its parser, and a pin
    file line that holds no pin is the same refusal here; @cert-authority
    lines are no keys and stay OpenSSH's to check. Without paramiko the
    files cannot be read, and OpenSSH is left to its own."""
    if not _ssh.AVAILABLE:
        return
    from ..probe import _ssh_g, _Unknown     # hssh.probe imports the drivers, which load this module
    try:
        route = _ssh_g(host, port, 22, user, 30.0)
    except _Unknown as exc:
        raise RuntimeError("SSH transport failed: %s." % exc) from exc
    name = route.alias or (route.host if route.port == 22 else "[%s]:%d" % (route.host, route.port))
    with _ssh._PIN_LOCK:
        pinned, _ = _ssh._parsed(_pin_file(), system=False, timeout=30.0)
        known, _ = _ssh._parsed(_system_file(), system=True, timeout=30.0)
    reason = _ssh.disagreement(pinned, known, name, _pin_file())
    if reason is not None:
        raise RuntimeError("Host key verification failed for %s: %s." % (host, reason))


def _base_opts(connect_timeout, port: Optional[int],
               control_path: Optional[str], have_password: bool) -> List[str]:
    """ssh's options. `connect_timeout` is the connect phase's seconds:
    OpenSSH's ConnectTimeout bounds the TCP connect and the banner exchange
    together, as --connect-timeout does (#126)."""
    policy = host_key_policy()
    system = _system_file()
    opts = [
        # OpenSSH's own `no` lets a changed key through; h-ssh's `no` spares
        # an unknown host the refusal and nothing else, which for OpenSSH is
        # accept-new (it pins on first contact, where paramiko's `no` does not).
        "-o", "StrictHostKeyChecking=%s" % ("accept-new" if policy == "no" else policy),
        # One pin store: h-ssh's own file first (a new pin goes there, made
        # 0600 beforehand), then OpenSSH's own. A changed key in either is refused.
        "-o", "UserKnownHostsFile=%s %s" % (_quoted(_pin_file()), _quoted(system)),
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
    diagnostics (its non-debug log lines) apart from them; `lost` when the
    session was lost under the command (_exec)."""

    def __init__(self, args, returncode, stdout, stderr, diag, log="", lost=False):
        self.args, self.returncode, self.stdout, self.stderr, self.diag = args, returncode, stdout, stderr, diag
        self.log = log      # ssh's whole -v log, for the phase a failure happened in
        self.lost = lost


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
          control_path: Optional[str], connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
          log_in: bool = False) -> _Result:
    """Run one command through ssh. ConnectTimeout bounds the TCP connect and
    the banner, nothing in OpenSSH bounds the key exchange after it (L9), so
    the session has --session-timeout from the start to be up, judged by ssh's
    own -v log, and the command has --command-timeout from that moment. The
    connect phase has --connect-timeout from the start (#126), on the same
    clock: a ConnectTimeoutError when it runs out, whichever clock fires.
    With `log_in` it runs no command: it is the ssh that logs in for `cmd`
    and what comes after it (_log_in).

    A command through the login's ControlMaster that exits 255 with nothing
    of ssh's own in its log is the device's exit status, or a session lost
    under the command: that takes the master with it, and this ssh, its
    client, logs no word of it at -v. The master tells them apart
    (_master_running): gone, the result is `lost` (#143)."""
    connect_s = budget(connect_timeout, session_timeout)
    # "--" ends the options: a host that starts with "-" is still the host,
    # which matters for a library caller that passes no user.
    fd, log_path = tempfile.mkstemp(prefix="hssh-ssh-", suffix=".log")
    os.close(fd)
    argv = (["ssh", "-n"] + (["-N"] if log_in else []) + ["-v", "-E", log_path]
            + _base_opts(connect_s, port, control_path, askpass.passwd is not None)
            + ["--", "%s@%s" % (user, host) if user else host] + ([] if log_in else [cmd]))
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
            said = _own_lines(log)
            lost = (not log_in and control_path is not None and proc.returncode == 255 and not said
                    and not _master_running(host, user, control_path, port, session_timeout))
            return _Result(argv, proc.returncode,
                           outf.read().decode("utf-8", "replace"),
                           errf.read().decode("utf-8", "replace"),
                           said, log, lost)
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


def _master_running(host: str, user: str, control_path: str, port: Optional[int], timeout: int) -> bool:
    """Whether the login's ControlMaster still holds its session to the
    device, as `ssh -O check` hears from it. A master whose session was lost
    exits and removes its socket; one on its way out answers nothing."""
    if not os.path.exists(control_path):
        return False
    try:
        return subprocess.run(
            ["ssh", "-O", "check", "-o", "ControlPath=%s" % control_path]
            + (["-p", str(port)] if port else [])
            + ["--", "%s@%s" % (user, host) if user else host],
            capture_output=True, timeout=float(timeout), env=_without_password()).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _log_in(host: str, user: str, askpass, cmd: str, session_timeout: int, command_timeout: int,
            port: Optional[int], control_path: str, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> None:
    """Log in once, for `cmd` and the commands after it: `ssh -N` as the
    ControlMaster, which goes to the background once the session is up, so
    each command then runs through it and logs in to nothing itself. OpenSSH
    prints the server's login banner on the stderr of the ssh that logs in,
    as soon as its log level is INFO or above, and `-v` puts it there over
    `-o LogLevel=ERROR`: a login message became every command's STDERR block,
    and one that starts `error:` failed every show as refused (#143). This
    ssh's stderr is read only to say why the login failed. The host key
    check of the two files (#150) comes first, once for the session."""
    _refuse_disagreement(host, user, port)
    proc = _exec(host, user, askpass, cmd, session_timeout, command_timeout, port, control_path,
                 connect_timeout, log_in=True)
    if proc.returncode != 0:
        raise RuntimeError(_describe_failure(host, proc))


def _describe_failure(host: str, proc, cmd: Optional[str] = None) -> str:
    """OpenSSH reports the real reason in its own log; surface it instead of
    an exit code. With `cmd`, proc ran that command: ssh exits with the
    command's own status, and 255 for a failure of its own, which its log
    then says, or for a session lost under the command, which it does not
    (`proc.lost`, the master gone with it): `connection to HOST lost before
    'CMD' finished`, as on the ssh transport, not the first line of a reply
    cut short. Any other status, or 255 with nothing in the log and the
    master still up, is the device's word on a command that failed, from
    its stderr or stdout, `exit N from 'cmd': ...`, never read as ssh's: a
    device's `Permission denied` is not a failed login (#143)."""
    said = (getattr(proc, "diag", "") or "").strip()
    if cmd is not None and getattr(proc, "lost", False):
        return "connection to %s lost before '%s' finished" % (host, cmd)
    if cmd is not None and (proc.returncode != 255 or not said):
        detail = (proc.stderr or "").strip() or (proc.stdout or "").strip()
        if detail:
            return "exit %d from '%s': %s" % (proc.returncode, cmd, detail.splitlines()[0])
        return "exit %d from '%s' with no diagnostic output." % (proc.returncode, cmd)
    detail = said or (proc.stderr or "").strip() or (proc.stdout or "").strip()
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
    if "REVOKED HOST KEY" in detail or "marked as revoked" in detail:
        # Before the generic branch: its re-keyed advice would have the
        # operator delete the revocation, and the next run pin the revoked
        # key and send it the password (#150).
        return "Host key verification failed for %s: its key is marked @revoked in ~/.ssh/known_hosts." % host
    if "Host key verification failed" in detail:
        return ("Host key verification failed for %s: the key is not the one pinned. If the device was "
                "re-keyed, remove its line from ~/.h-ssh/known_hosts (or ~/.ssh/known_hosts)." % host)
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
        _refuse_disagreement(host, user, port)
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

    tmpdir = tempfile.mkdtemp(prefix="hssh-")
    # Unix socket paths cap near 104 bytes, so keep the name short.
    control_path = os.path.join(tmpdir, "cm")
    try:
        with _AskPass(passwd) as askpass:
            outputs = []
            for i, cmd in enumerate(commands):
                try:
                    if i == 0:
                        _log_in(host, user, askpass, cmd, session_timeout, command_timeout, port,
                                control_path, connect_timeout)
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
                if proc.lost:
                    raise ConnectionError(_describe_failure(host, proc, cmd))
                if proc.returncode != 0:
                    raise RuntimeError(_describe_failure(host, proc, cmd))
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
                capture_output=True, text=True, timeout=float(session_timeout), env=_without_password())
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
    the CLI takes either as a key (cli.refuse_control_characters). So is one
    with nothing to apply, nothing but blank lines and comments (`#`, and
    `!` for an IOS-shaped dialect), but for Junos's candidate, where it is
    NO CHANGES (cli.refuse_empty_edit).
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
        refuse_empty_edit(payload, d)
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
    else:
        refuse_empty_edit(payload, d)
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
    """Execute multiple commands over one multiplexed SSH connection, logged
    in once (_log_in). A connect phase that runs out before any command ran
    ends the batch as one failure, as on the other transports, where a
    batch has one connection: each command after it would cost another
    connect timeout for the same silence (#126). A login that fails
    otherwise is the command's failure, and the next command logs in
    again, as it does after a command whose session was lost (the login
    went with it). Once a command has its result, the results stand: a
    connect that runs out after that is that command's failure, and the
    batch goes on."""
    if not AVAILABLE:
        raise RuntimeError("no 'ssh' binary found on PATH.")

    d = _dialect(vendor_hint)
    tmpdir = tempfile.mkdtemp(prefix="hssh-")
    control_path = os.path.join(tmpdir, "cm")
    try:
        with _AskPass(passwd) as askpass:
            results = []
            logged_in = False
            for cmd in cmds:
                try:
                    if not logged_in:
                        _log_in(host, user, askpass, cmd, session_timeout, command_timeout, port,
                                control_path, connect_timeout)
                        logged_in = True
                    proc = _exec(host, user, askpass, cmd, session_timeout,
                                 command_timeout, port, control_path, connect_timeout)
                    refused = refused_reply(proc.stderr, proc.stdout, dialect=d) if proc.returncode == 0 else None
                    if proc.returncode != 0:
                        results.append({"command": cmd, "ok": False,
                                        "error": _describe_failure(host, proc, cmd)})
                        logged_in = not proc.lost
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
    double quote in it, or with no text or over 512 bytes, is refused before
    connecting (cli.refuse_comment)."""
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
    tmpdir = tempfile.mkdtemp(prefix="hssh-")
    control_path = os.path.join(tmpdir, "cm")
    try:
        with _AskPass(passwd) as askpass:
            try:
                _log_in(host, user, askpass, full, session_timeout, command_timeout, port, control_path,
                        connect_timeout)
                proc = _exec(host, user, askpass, full, session_timeout, command_timeout, port, control_path,
                             connect_timeout)
            except OSError as exc:
                raise RuntimeError("SSH transport failed: %s" % exc)
    finally:
        _close_master(host, user, control_path, tmpdir, session_timeout, port)
    if proc.lost:
        raise ConnectionError(_describe_failure(host, proc, full))
    if proc.returncode != 0:
        raise RuntimeError(_describe_failure(host, proc, full))
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
    """The ssh this module runs for `cmd`, for logs and bug reports: the
    command's half, its options without the -v log (`-E`) and the
    ControlMaster ones. Each call first logs in on a ControlMaster, an
    `ssh -N` with the same options, and the command runs through it; this
    line run alone logs in by itself, and the server's login banner lands
    in its stderr, where h-ssh keeps it out of the command's."""
    argv = (["ssh", "-n"] + _base_opts(budget(connect_timeout, session_timeout), port, None, False)
            + ["--", "%s@%s" % (user, host) if user else host, cmd])
    return " ".join(shlex.quote(part) for part in argv)
