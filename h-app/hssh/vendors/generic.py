"""Generic SSH implementation using Paramiko.

Host keys follow the same HSSH_HOST_KEY_POLICY as the openssh transport. The
default, accept-new, trusts a host on first contact and pins its key in
~/.h-ssh/known_hosts; from then on a different key is refused before any
credential is sent. ~/.ssh/known_hosts is read as well, never written: paramiko
saves by rewriting the whole file, which would flatten the comments, markers
and hashed entries OpenSSH keeps there.

A command's exit status is checked the way the openssh transport checks the
ssh binary's: a non-zero status is a failure, not output.
"""

import socket
import time
import os
import threading
from pathlib import Path
from typing import List, Optional

try:
    import paramiko
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

# Pins are saved by rewriting the file, so workers of one run pinning
# different hosts at once must take turns, and re-read before writing, or
# the last one to save would drop the others' pins.
_PIN_LOCK = threading.Lock()


def _known_hosts() -> str:
    """h-ssh's own known_hosts, created empty and 0600 the first time."""
    path = Path.home() / ".h-ssh" / "known_hosts"
    path.parent.mkdir(mode=0o700, exist_ok=True)
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except FileExistsError:
        pass
    return str(path)


class _PinPolicy:
    """accept-new: an unknown host is trusted once and its key pinned."""

    def __init__(self, path: str):
        self.path = path

    def missing_host_key(self, client, hostname, key):
        with _PIN_LOCK:
            keys = client.get_host_keys()
            keys.load(self.path)  # merge what other workers pinned meanwhile
            keys.add(hostname, key.get_name(), key)
            keys.save(self.path)


class _RejectPolicy:
    """yes: a host that is not pinned is refused."""

    def missing_host_key(self, client, hostname, key):
        raise RuntimeError(
            "Host key verification failed for %s: not in known_hosts and "
            "HSSH_HOST_KEY_POLICY=yes." % hostname)


def _host_key_policy(known_hosts: str):
    """The missing-host-key policy HSSH_HOST_KEY_POLICY asks for.

    Only an unknown host is a policy matter. A pinned host that presents a
    different key is refused by paramiko itself, whatever the policy.
    """
    policy = os.environ.get("HSSH_HOST_KEY_POLICY", "accept-new")
    if policy == "accept-new":
        return _PinPolicy(known_hosts)
    if policy == "yes":
        return _RejectPolicy()
    if policy == "no":
        return paramiko.WarningPolicy()
    raise RuntimeError("invalid HSSH_HOST_KEY_POLICY=%r (expected accept-new, yes or no)"
                       % policy)


def _connect(host: str, user: str, passwd: Optional[str], session_timeout: int,
             port: Optional[int]):
    """A connected SSHClient, host key checked, ready for exec_command."""
    if not AVAILABLE:
        raise RuntimeError("paramiko not available in this environment.")

    known_hosts = _known_hosts()
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    with _PIN_LOCK:
        client.load_host_keys(known_hosts)
    client.set_missing_host_key_policy(_host_key_policy(known_hosts))

    session_timeout_float = float(session_timeout)

    conn_params = {
        "hostname": host,
        "username": user,
        "port": port or 22,
        "timeout": session_timeout_float,
        "banner_timeout": session_timeout_float,
        "auth_timeout": session_timeout_float,
    }

    if passwd is not None:
        conn_params["password"] = passwd
        conn_params["look_for_keys"] = False
        conn_params["allow_agent"] = False
    else:
        conn_params["look_for_keys"] = True
        conn_params["allow_agent"] = True

    try:
        client.connect(**conn_params)
    except paramiko.BadHostKeyException as exc:
        client.close()
        raise RuntimeError(
            "Host key verification failed for %s: the key is not the one pinned. "
            "If the device was re-keyed, remove its line from %s (or ~/.ssh/known_hosts)."
            % (host, known_hosts)) from exc
    except BaseException:
        # A refused login or a dropped handshake leaves a Transport thread
        # and a socket behind unless the client is closed.
        client.close()
        raise
    return client


def _drain(stream, deadline: float, cmd: str) -> str:
    """Everything a stream sends before the deadline. A device that keeps
    sending, or stops without closing, ends in a TimeoutError, not a worker
    pinned for the rest of the run."""
    chunks = []
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError(f"'{cmd}': the device was still sending when the command timeout ran out")
        try:
            chunk = stream.read(65536)
        except socket.timeout as e:
            raise TimeoutError(f"'{cmd}': no output within the command timeout") from e
        if not chunk:
            return b"".join(chunks).decode(errors="replace")
        chunks.append(chunk)


def _exec(client, cmd: str, command_timeout: int):
    """(exit status, stdout, stderr) of one command; -1 when the server sent no status.

    Every wait is bounded by command_timeout: the reads, and the exit status
    after them. A device that sends EOF and then neither a status nor a
    close once held a worker thread forever (and with it the whole run)."""
    deadline = time.monotonic() + float(command_timeout)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=float(command_timeout))
    channel = stdout.channel
    # Both streams are drained first: the status only arrives once the
    # command has ended, and a chatty command cannot end while its output
    # has nowhere to go.
    out = _drain(stdout, deadline, cmd)
    err = _drain(stderr, deadline, cmd)
    status_event = getattr(channel, "status_event", None)
    if status_event is not None and not status_event.wait(max(0.0, deadline - time.monotonic())):
        try:
            channel.close()
        except Exception:
            pass
        raise TimeoutError(f"'{cmd}': the device sent no exit status within {command_timeout}s; channel closed")
    return channel.recv_exit_status(), out, err


def _describe_failure(cmd: str, rc: int, out: str, err: str) -> str:
    """The device's own words for a failed command; stderr first, stdout if that is empty."""
    detail = err.strip() or out.strip()
    first = detail.splitlines()[0] if detail else ""
    if first:
        return "exit %d from '%s': %s" % (rc, cmd, first)
    return "exit %d from '%s' with no diagnostic output." % (rc, cmd)


def _format(cmd: str, out: str, err: str) -> str:
    block = [f"$ {cmd}"]
    if out.strip():
        block.append(out.rstrip())
    if err.strip():
        block.append("STDERR:")
        block.append(err.rstrip())
    return "\n".join(block)


def show(host: str, user: str, passwd: str, cmd: str, session_timeout: int,
         command_timeout: int, port: int = None, vendor_hint: str = None) -> str:
    """Execute a show command via SSH."""
    return _run_commands(host, user, passwd, [cmd], session_timeout, command_timeout, port=port)


def edit(host: str, user: str, passwd: str, payload: str, session_timeout: int,
         command_timeout: int, commit_confirmed: int = None, port: int = None,
         vendor_hint: str = None) -> str:
    """Execute configuration commands via SSH. A rollback timer has no
    equivalent over an exec channel: asking for one is refused, not dropped."""
    if commit_confirmed is not None:
        raise ValueError("commit_confirmed is not supported by the 'ssh' transport; "
                         "nothing was sent to the device")
    commands = [ln.strip() for ln in payload.strip().splitlines() if ln.strip()]
    return _run_commands(host, user, passwd, commands, session_timeout, command_timeout, port=port)


def _run_commands(host: str, user: str, passwd: str, commands: List[str],
                  session_timeout: int, command_timeout: int, port: int = None) -> str:
    """Execute commands via SSH on any device."""
    client = _connect(host, user, passwd, session_timeout, port)

    try:
        outputs = []
        for cmd in commands:
            rc, out, err = _exec(client, cmd, command_timeout)
            # A server that reports no status at all (-1) is not reporting
            # a failure; some network OSes never send one.
            if rc > 0:
                raise RuntimeError(_describe_failure(cmd, rc, out, err))
            outputs.append(_format(cmd, out, err))
        return "\n\n".join(outputs).strip() + "\n"
    finally:
        client.close()


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = None) -> List[dict]:
    """Execute multiple commands on a single SSH connection."""
    client = _connect(host, user, passwd, session_timeout, port)
    try:
        results = []
        for cmd in cmds:
            try:
                rc, out, err = _exec(client, cmd, command_timeout)
                if rc > 0:
                    results.append({"command": cmd, "ok": False,
                                    "error": _describe_failure(cmd, rc, out, err)})
                else:
                    results.append({"command": cmd, "ok": True, "output": _format(cmd, out, err)})
            except Exception as e:
                results.append({"command": cmd, "ok": False, "error": str(e)})
        return results
    finally:
        client.close()
