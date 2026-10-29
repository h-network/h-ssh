"""The openssh communicator: the system ssh binary on a forced pty, driven by the CLI engine (section 3.4)."""

from __future__ import annotations

import os
import re
import select
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from typing import TYPE_CHECKING

from hssh.dialects.base import Dialect
from hssh.model import Credentials, Fault, FaultKind, HostKeyPolicy, Result, Target, Timeouts

if TYPE_CHECKING:
    from hssh.communicators.cli_engine import CliEngine

AVAILABLE = shutil.which("ssh") is not None

# SSH_ASKPASS_REQUIRE=force (OpenSSH 8.4) is what lets askpass run with no TTY and no DISPLAY.
_MIN_OPENSSH = (8, 4)

# The helper carries no secret: it prints the 0600 file beside it, so the password is never in argv or env.
_ASKPASS_HELPER = """#!/bin/sh
cat "${0%/*}/secret"
"""

_STRICT_HOST_KEY = {"accept-new": "accept-new", "strict": "yes", "off": "no"}

_EXIT_GRACE = 2.0

_SESSION_UP = ("Authenticated to ", "Entering interactive session")


def _without_password() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != "HSSH_PASSWORD"}


def _openssh_version() -> tuple[int, ...]:
    try:
        proc = subprocess.run(["ssh", "-V"], capture_output=True, text=True, timeout=10, env=_without_password())
    except (OSError, subprocess.SubprocessError):
        return ()
    m = re.search(r"OpenSSH_(\d+)\.(\d+)", (proc.stderr or "") + (proc.stdout or ""))
    return (int(m.group(1)), int(m.group(2))) if m else ()


class _AskPass:
    """A short-lived SSH_ASKPASS helper and the environment that points ssh at it."""

    def __init__(self, password: str | None):
        self.password = password
        self.dir: str | None = None
        self.path: str | None = None
        self.secret: str | None = None

    def __enter__(self) -> _AskPass:
        if not self.password:
            return self
        version = _openssh_version()
        if version and version < _MIN_OPENSSH:
            raise Fault(FaultKind.LOCAL, "password authentication needs OpenSSH >= %d.%d for SSH_ASKPASS_REQUIRE "
                        "(found %d.%d)" % (_MIN_OPENSSH + version), reached_device=False)
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
                fh.write(self.password + "\n")
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    @property
    def env(self) -> dict[str, str]:
        env = _without_password()
        env["TERM"] = "vt100"
        if not self.password:
            return env
        env["SSH_ASKPASS"] = self.path
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env.pop("DISPLAY", None)
        return env

    def __exit__(self, *_exc) -> bool:
        for made in (self.secret, self.path):
            if made:
                _unlink(made)
        if self.dir:
            try:
                os.rmdir(self.dir)
            except OSError:
                pass
        return False


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


def _ssh_argv(target: Target, creds: Credentials, timeouts: Timeouts, policy: HostKeyPolicy,
              log_path: str) -> list[str]:
    """The ssh command line for one pty session; -v to the -E log is how failures are read afterwards."""
    argv = ["ssh", "-tt", "-e", "none", "-v", "-E", log_path,
            "-o", "StrictHostKeyChecking=%s" % _STRICT_HOST_KEY[policy],
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=%d" % max(1, timeouts.connect),
            "-o", "NumberOfPasswordPrompts=1"]
    if policy == "off":
        argv += ["-o", "UserKnownHostsFile=/dev/null"]
    if creds.password:
        argv += ["-o", "PubkeyAuthentication=no", "-o", "IdentitiesOnly=yes"]
    else:
        argv += ["-o", "BatchMode=yes"]
    if creds.key_file:
        argv += ["-i", creds.key_file]
    if target.port:
        argv += ["-p", str(target.port)]
    return argv + ["--", "%s@%s" % (creds.username, target.host)]


def _login_fault(host: str, log: str) -> Fault:
    """Classify a failed login from ssh's own log; the device was reached once its banner is in it."""
    detail = "\n".join(ln for ln in log.splitlines() if ln.strip() and not ln.startswith("debug"))
    reached = "Remote protocol version" in log
    if "Permission denied" in detail or "Authentication failed" in detail:
        return Fault(FaultKind.AUTH, detail, reached)
    if "Host key verification failed" in detail or "REMOTE HOST IDENTIFICATION HAS CHANGED" in detail:
        return Fault(FaultKind.HOST_KEY, detail, reached)
    if "timed out" in detail:
        return Fault(FaultKind.TIMEOUT if reached else FaultKind.UNREACHABLE, detail, reached)
    if any(marker in log for marker in _SESSION_UP):
        return Fault(FaultKind.SESSION_LOST, detail, True)
    return Fault(FaultKind.UNREACHABLE, detail, reached)


class ProcessChannel:
    """The ssh process's pipes as the CLI engine's channel: recv(n, timeout), send(data), close()."""

    def __init__(self, proc: subprocess.Popen, host: str, log_path: str):
        self.proc = proc
        self.host = host
        self.log_path = log_path
        self.closed = False

    @classmethod
    def open(cls, argv: list[str], env: dict[str, str], host: str, log_path: str) -> ProcessChannel:
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=env, bufsize=0)
        except OSError as exc:
            _unlink(log_path)
            raise Fault(FaultKind.LOCAL, str(exc), reached_device=False) from exc
        return cls(proc, host, log_path)

    def recv(self, n: int, timeout: float) -> bytes:
        try:
            ready, _, _ = select.select([self.proc.stdout], [], [], max(0.0, timeout))
        except (OSError, ValueError) as exc:
            raise ConnectionError("connection lost: %s" % exc) from exc
        if not ready:
            raise TimeoutError("nothing from %s within %.1fs" % (self.host, timeout))
        data = os.read(self.proc.stdout.fileno(), n)
        if not data and self._ended():
            raise ConnectionError(self.log())
        return data

    def _ended(self) -> bool:
        try:
            self.proc.wait(timeout=_EXIT_GRACE)
        except subprocess.TimeoutExpired:
            return False
        return self.proc.returncode != 0

    def send(self, data: bytes) -> None:
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise ConnectionError("connection lost: %s" % exc) from exc

    def log(self) -> str:
        return _read(self.log_path)

    def close(self) -> None:
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
        _unlink(self.log_path)


@dataclass
class OpenSSHSession:
    """One ssh process at the device's prompt, with the CLI engine that types at it."""

    target: Target
    channel: ProcessChannel
    engine: CliEngine
    timeouts: Timeouts


class OpenSSH:
    """Communicator for the system ssh binary; one driver instance per dialect."""

    def __init__(self, dialect: Dialect):
        self.dialect = dialect
        caps = {"show", "batch", "edit"}
        if dialect.has_candidate:
            caps |= {"commit_confirmed", "confirm", "commit_status"}
        self.capabilities = frozenset(caps)

    def open(self, target: Target, creds: Credentials, timeouts: Timeouts,
             host_key_policy: HostKeyPolicy) -> OpenSSHSession:
        from hssh.communicators.cli_engine import CliEngine

        if not AVAILABLE:
            raise Fault(FaultKind.LOCAL, "no 'ssh' binary found on PATH", reached_device=False)
        fd, log_path = tempfile.mkstemp(prefix="hssh-ssh-", suffix=".log")
        os.close(fd)
        with _AskPass(creds.password) as askpass:
            argv = _ssh_argv(target, creds, timeouts, host_key_policy, log_path)
            channel = ProcessChannel.open(argv, askpass.env, target.host, log_path)
            engine = CliEngine(channel, self.dialect, timeouts)
            try:
                engine.login()
            except (ConnectionError, TimeoutError) as exc:
                log = channel.log()
                channel.close()
                raise _login_fault(target.host, log) from exc
        return OpenSSHSession(target, channel, engine, timeouts)

    def close(self, session: OpenSSHSession) -> None:
        try:
            session.engine.close()
        finally:
            session.channel.close()

    def show(self, session: OpenSSHSession, command: str) -> Result:
        return session.engine.show(command)

    def structured(self, session: OpenSSHSession, rpc: str, fmt: str) -> Result:
        raise Fault(FaultKind.UNSUPPORTED, "openssh has no structured output", reached_device=False)

    def load(self, session: OpenSSHSession, lines: list[str]) -> Result:
        return session.engine.load(lines)

    def diff(self, session: OpenSSHSession) -> Result:
        return session.engine.diff()

    def commit(self, session: OpenSSHSession, confirmed_minutes: int | None, comment: str | None) -> Result:
        return session.engine.commit(confirmed_minutes, comment)

    def confirm(self, session: OpenSSHSession) -> Result:
        return session.engine.confirm()

    def commit_history(self, session: OpenSSHSession) -> Result:
        return session.engine.commit_history()
