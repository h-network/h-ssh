"""Dependency-free SSH transport that drives the OpenSSH client binary.

Exists for hosts where third-party packages cannot be installed: jump hosts
with no package index, no ensurepip, and no root. Everything here is stdlib
plus the `ssh` binary, which is already present wherever operators log in.

Key auth runs `ssh` under subprocess. Password auth runs it under a PTY,
because OpenSSH deliberately refuses to read a password from a pipe. The PTY
technique is taken from EuroFiber/ef-net (ef_net/device.py).

Multiple commands reuse one TCP connection and one authentication via OpenSSH
connection multiplexing (ControlMaster), so batch mode keeps per-command
output cleanly separated instead of parsing one merged stream.
"""

import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from typing import List, Optional

try:
    import pty
    import select
    _PTY = True
except ImportError:  # Windows
    _PTY = False

AVAILABLE = shutil.which("ssh") is not None

# OpenSSH writes auth prompts to the terminal, never to stdout/stderr.
_AUTH_PROMPT_RE = re.compile(br'(?:password|passphrase)[^\r\n]*:\s*$', re.I)

# Same prompt anywhere in a finished transcript, for scrubbing.
_PROMPT_LINE_RE = re.compile(r'^.*(?:password|passphrase)[^\r\n]*:.*$\n?', re.I | re.M)

# accept-new trusts a host the first time and pins it after, matching the
# WarningPolicy the paramiko transport uses. Override for stricter sites.
_HOST_KEY_POLICY = os.environ.get("HSSH_HOST_KEY_POLICY", "accept-new")


class _Result:
    """Stands in for CompletedProcess on the PTY path, where the two streams merge."""

    def __init__(self, returncode: int, stdout: str, stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _pty_run(argv: List[str], secret: bytearray, timeout: float) -> _Result:
    """Run OpenSSH on a PTY and answer only recognized auth prompts."""
    pid, master = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    output = bytearray()
    deadline = time.monotonic() + timeout
    prompts = 0
    status = None
    try:
        while status is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            ready, _, _ = select.select([master], [], [], min(remaining, 0.25))
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    chunk = b""
                if chunk:
                    output.extend(chunk)
                    tail = bytes(output[-512:]).replace(b"\r", b"")
                    if _AUTH_PROMPT_RE.search(tail):
                        prompts += 1
                        # A second prompt means the first answer was wrong;
                        # a third means we are feeding a password to something
                        # that keeps asking. Stop rather than spend attempts.
                        if prompts > 3:
                            raise OSError("too many authentication prompts")
                        os.write(master, bytes(secret))
                        os.write(master, b"\n")
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited == 0:
                status = None
        text = output.decode("utf-8", errors="replace").replace("\r", "")
        # A PTY echoes by default. OpenSSH turns echo off while reading a
        # password, but a device or jump host in the path may not, and this
        # transcript flows on to logs, --save-output and the audit trail. Drop
        # the prompt line outright rather than trust every hop to behave.
        text = _PROMPT_LINE_RE.sub("", text)
        return _Result(os.waitstatus_to_exitcode(status), text)
    except BaseException:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
        raise
    finally:
        os.close(master)


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


def _exec(host: str, user: str, secret: Optional[bytearray], cmd: str,
          session_timeout: int, command_timeout: int, port: Optional[int],
          control_path: Optional[str]):
    argv = (["ssh", "-n"]
            + _base_opts(session_timeout, port, control_path, secret is not None)
            + ["%s@%s" % (user, host) if user else host, cmd])
    timeout = float(session_timeout + command_timeout)
    if secret is not None:
        if not _PTY:
            raise RuntimeError(
                "password authentication needs a PTY, unavailable on this platform; "
                "use key authentication")
        return _pty_run(argv, secret, timeout)
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


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


def _secret(passwd: Optional[str]) -> Optional[bytearray]:
    return bytearray(passwd.encode("utf-8")) if passwd else None


def _burn(secret: Optional[bytearray]) -> None:
    """Best-effort erasure; the copy OpenSSH received is out of our hands."""
    if secret is None:
        return
    for i in range(len(secret)):
        secret[i] = 0
    secret.clear()


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

    secret = _secret(passwd)
    tmpdir = tempfile.mkdtemp(prefix="hssh-") if len(commands) > 1 else None
    # Unix socket paths cap near 104 bytes, so keep the name short.
    control_path = os.path.join(tmpdir, "cm") if tmpdir else None
    try:
        outputs = []
        for cmd in commands:
            try:
                proc = _exec(host, user, secret, cmd, session_timeout,
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
        _burn(secret)
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

    secret = _secret(passwd)
    tmpdir = tempfile.mkdtemp(prefix="hssh-")
    control_path = os.path.join(tmpdir, "cm")
    try:
        results = []
        for cmd in cmds:
            try:
                proc = _exec(host, user, secret, cmd, session_timeout,
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
        _burn(secret)
        _close_master(host, user, control_path, tmpdir, session_timeout, port)


def ssh_command_line(host: str, user: str, cmd: str, session_timeout: int = 8,
                     port: int = None) -> str:
    """The exact command line this module would run, for logs and bug reports."""
    argv = (["ssh", "-n"] + _base_opts(session_timeout, port, None, False)
            + ["%s@%s" % (user, host) if user else host, cmd])
    return " ".join(shlex.quote(part) for part in argv)
