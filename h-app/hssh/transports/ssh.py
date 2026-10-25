"""The paramiko transport (``ssh``): SSH to any device, in the dialect the
vendor_hint names (none for the plain `ssh` driver).

Shows, and the none dialect's edits, run on an exec channel: one exec_command
per command, its exit status checked the way the openssh transport checks the
ssh binary's (a non-zero status is a failure, not output) and its reply read
for the dialect's refusal. A dialect's edits and confirms (junos@ssh, ios@ssh,
nxos@ssh, eos@ssh) go through the CLI engine (hssh.transports.cli) on a shell
channel: a candidate configuration, its lock, a diff and a rollback timer need
one session that stays in configuration mode. eos@ssh's structured reads ask
the exec channel for `<cmd> | json`.

Host keys follow the same HSSH_HOST_KEY_POLICY as the openssh transport. The
default, accept-new, trusts a host on first contact and pins its key in
~/.h-ssh/known_hosts; from then on a different key is refused before any
credential is sent. ~/.ssh/known_hosts is read as well, never written: paramiko
saves by rewriting the whole file, which would flatten the comments, markers
and hashed entries OpenSSH keeps there.
"""

import fcntl
import json
import socket
import time
import os
import threading
from pathlib import Path
from typing import List, Optional

from .. import drivers
from ..core import refusal_line, refused_reply
from ..dialects.base import Dialect
from ..drivers import results as R
from .cli import Cli, edit_policy, refuse_commit_lines

try:
    import paramiko
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

# Pins are saved by rewriting the file, so workers of one run pinning
# different hosts at once must take turns, and re-read before writing, or
# the last one to save would drop the others' pins.
_PIN_LOCK = threading.Lock()


def _dialect(vendor_hint: Optional[str]) -> Dialect:
    """The dialect behind a vendor_hint: junos@ssh is junos, ios@ssh is ios,
    plain ssh (and None, and a name the registry does not know) is none. The
    hint is a driver's name, alias or canonical."""
    try:
        return drivers.get(vendor_hint or "ssh").dialect
    except ValueError:
        return drivers.NONE


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
        # The thread lock serialises this process's workers; the file lock
        # serialises processes, so two h-ssh runs pinning at once cannot
        # rewrite the file over each other's pins.
        with _PIN_LOCK:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                keys = client.get_host_keys()
                keys.load(self.path)  # merge what other processes pinned meanwhile
                keys.add(hostname, key.get_name(), key)
                keys.save(self.path)
                # `keys` is the process's shared copy of the file (see
                # _parsed); it now matches what was just written.
                _PINS[self.path] = (_signature(self.path), keys)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)


class _RejectPolicy:
    """yes: a host that is not pinned is refused."""

    def missing_host_key(self, client, hostname, key):
        raise RuntimeError(
            "Host key verification failed for %s: not in known_hosts and "
            "HSSH_HOST_KEY_POLICY=yes." % hostname)


# The known_hosts files, parsed once per process and shared by every
# connection until the file changes. Parsing is ~50 µs a line; done again for
# every connection, under the lock, a 250-device fleet spent 250 × 13 ms in
# a row on its own pin file, and the cost grew with the square of the fleet.
_PINS: dict = {}            # path -> (signature, HostKeys)


def _signature(path: str):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_ino, st.st_size, st.st_mtime_ns)


def _parsed(path: str) -> "paramiko.HostKeys":
    """The file's keys, parsed once and shared until the file changes; a
    missing file is no keys. Caller holds _PIN_LOCK."""
    signature = _signature(path)
    cached = _PINS.get(path)
    if cached is not None and cached[0] == signature:
        return cached[1]
    keys = paramiko.HostKeys()
    if signature is not None:
        keys.load(path)
    _PINS[path] = (signature, keys)
    return keys


def _load_pins(client, known_hosts: str) -> None:
    """~/.ssh/known_hosts (read only) and h-ssh's own pin file. A line that
    cannot be parsed is a refusal, not a skip: the pin it was meant to hold
    is unknown, and retrying the file cannot change it."""
    system = str(Path.home() / ".ssh" / "known_hosts")
    for path in (system, known_hosts):
        try:
            with _PIN_LOCK:
                keys = _parsed(path)
        except (paramiko.hostkeys.InvalidHostKey, paramiko.SSHException, ValueError) as exc:
            line = getattr(exc, "line", None)
            shown = f": {line.strip()!r}" if isinstance(line, str) and line.strip() else ""
            raise ValueError(f"{path}: malformed known_hosts line{shown}; fix or remove it") from exc
        # What load_system_host_keys()/load_host_keys() would have filled,
        # without parsing the file for this client alone.
        if path == known_hosts:
            client._host_keys = keys
            client._host_keys_filename = known_hosts
        else:
            client._system_host_keys = keys


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
    _load_pins(client, known_hosts)
    client.set_missing_host_key_policy(_host_key_policy(known_hosts))

    session_timeout_float = float(session_timeout)

    conn_params = {
        "hostname": host,
        "username": user,
        "port": port or 22,
        "timeout": session_timeout_float,
        "banner_timeout": session_timeout_float,
        "auth_timeout": session_timeout_float,
        # The shell for an edit opens a channel with no clock of its own;
        # paramiko would wait an hour for a device that authenticates and
        # then says nothing. (A show's exec channel has the command timeout.)
        "channel_timeout": session_timeout_float,
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
    except paramiko.SSHException as exc:
        client.close()
        if "no authentication methods available" in str(exc).lower():
            # paramiko found nothing to offer: no password, no ~/.ssh/id_*, no agent key.
            raise RuntimeError(
                "No authentication methods available for %s@%s: no password was given and "
                "no key was found in ~/.ssh or from an agent." % (user, host)) from exc
        raise
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


class ShellChannel:
    """A paramiko shell channel as the CLI engine's Channel: recv(n, timeout)
    raises TimeoutError when nothing arrived in time and ConnectionError when
    the channel failed; an empty read is the peer closing, which the engine
    reports."""

    def __init__(self, chan):
        self.chan = chan

    def recv(self, n: int, timeout: float) -> bytes:
        self.chan.settimeout(timeout)
        try:
            return self.chan.recv(n)
        except TimeoutError:          # socket.timeout since Python 3.10
            raise
        except (OSError, paramiko.SSHException) as e:
            raise ConnectionError(f"connection lost: {e}") from e

    def send(self, data: bytes) -> None:
        self.chan.sendall(data)

    def close(self) -> None:
        try:
            self.chan.close()
        except Exception:
            pass


def _shell_session(host: str, user: str, passwd: Optional[str], session_timeout: int,
                   port: Optional[int], dialect: Dialect):
    """(client, session): a CLI session at the device's own prompt on a shell
    channel of a fresh connection; the caller closes both. The terminal is
    wide so the device never wraps the echo of a long line, which the engine
    must recognise as the echo. There is no login dialogue over SSH: login()
    reads the banner up to the prompt and learns this device's own."""
    client = _connect(host, user, passwd, session_timeout, port)
    try:
        chan = client.invoke_shell(term="vt100", width=511, height=1000)
        session = Cli(ShellChannel(chan), dialect, session_timeout)
        session.login(user, passwd)
    except BaseException:
        client.close()
        raise
    return client, session


def show(host: str, user: str, passwd: str, cmd: str, session_timeout: int,
         command_timeout: int, port: int = None, vendor_hint: str = None) -> str:
    """One show command on an exec channel; a reply the dialect's CLI opens
    with a refusal is a failure, not output."""
    return _run_commands(host, user, passwd, [cmd], session_timeout, command_timeout, port=port,
                         dialect=_dialect(vendor_hint))


def edit(host: str, user: str, passwd: str, payload: str, session_timeout: int,
         command_timeout: int, commit_confirmed: int = None, port: int = None,
         vendor_hint: str = None, dry_run: bool = False,
         expected_diff: Optional[str] = None) -> R.EditResult:
    """Push configuration.

    The none dialect (the plain `ssh` driver) runs each line as its own exec
    command and applies what it is given: a rollback timer has no equivalent
    there, so asking for one is refused, not dropped, and so are a dry run
    and a diff check. A dialect's edit goes through the CLI engine on a shell
    channel: Junos gets configure exclusive, the lines, show | compare and a
    commit (confirmed with a timer, or rollback 0 for a dry run, or only if
    the diff is still what the dry run showed); an IOS-shaped dialect gets
    configure terminal, the lines, end, and refuses dry_run, commit_confirmed
    and expected_diff before anything is sent.
    """
    d = _dialect(vendor_hint)
    if d is drivers.NONE:
        if commit_confirmed is not None:
            raise ValueError("commit_confirmed is not supported by the 'ssh' transport; "
                             "nothing was sent to the device")
        edit_policy(d, vendor_hint or "ssh", dry_run, None, expected_diff)
        commands = [ln.strip() for ln in payload.strip().splitlines() if ln.strip()]
        return _run_commands(host, user, passwd, commands, session_timeout, command_timeout, port=port,
                             edit=True, dialect=d)
    if d.cli is None:
        raise ValueError(f"{vendor_hint}: the {d.title} dialect has no CLI to type at; "
                         "nothing was sent to the device")
    edit_policy(d, vendor_hint, dry_run, commit_confirmed, expected_diff)
    if d.cli.has_candidate:
        refuse_commit_lines(payload)
    client, session = _shell_session(host, user, passwd, session_timeout, port, d)
    try:
        if d.cli.has_candidate:
            return session.edit_candidate(payload, dry_run=dry_run, confirmed_minutes=commit_confirmed or 0,
                                          expected_diff=expected_diff)
        return session.edit_lines(payload)
    finally:
        session.close()
        client.close()


def confirm(host: str, user: str, passwd: str, session_timeout: int, command_timeout: int,
            port: int = None, vendor_hint: str = "junos@ssh",
            comment: Optional[str] = None) -> R.EditResult:
    """Confirm a pending commit-confirmed on a Junos device over SSH: `show
    system commit` must show one waiting, then configure exclusive, a bare
    `commit` (`commit comment "…"` with a comment), exit. Only a dialect with
    a candidate and a commit history has anything to confirm."""
    d = _dialect(vendor_hint)
    if d.cli is None or not d.cli.has_candidate or d.commit_pending is None:
        raise ValueError(f"confirm is only for a Junos dialect, not {vendor_hint}; nothing was sent")
    client, session = _shell_session(host, user, passwd, session_timeout, port, d)
    try:
        return session.confirm(command_timeout, comment)
    finally:
        session.close()
        client.close()


def show_structured(host: str, user: str, passwd: str, cmd: str,
                    session_timeout: int, command_timeout: int,
                    port: int = None, vendor_hint: str = None,
                    binding: Optional[dict] = None):
    """A command's own JSON, for a dialect whose CLI renders one: EOS answers
    `<cmd> | json` with the data its text would show, so the exec channel runs
    that and the reply is parsed. `binding` is the field map the NETCONF
    driver needs and EOS does not: accepted for the shared signature, ignored.
    Any other dialect refuses before anything is sent."""
    d = _dialect(vendor_hint)
    if d is not drivers.EOS:
        raise ValueError(f"--structured is not supported by {vendor_hint or 'ssh'}; "
                         "nothing was sent to the device")
    full = f"{cmd} | json"
    client = _connect(host, user, passwd, session_timeout, port)
    try:
        rc, out, err = _exec(client, full, command_timeout)
    finally:
        client.close()
    if rc > 0:
        raise RuntimeError(_describe_failure(full, rc, out, err))
    refused = refused_reply(err, out, dialect=d)
    if refused:
        raise RuntimeError("'%s' was refused by the device: %s" % (full, refused))
    try:
        return json.loads(out)
    except ValueError:
        first = next((ln.strip() for ln in out.splitlines() if ln.strip()), "")
        raise RuntimeError(f"'{full}' did not return JSON: {first!r}") from None


def _run_commands(host: str, user: str, passwd: str, commands: List[str],
                  session_timeout: int, command_timeout: int, port: int = None,
                  edit: bool = False, dialect: Optional[Dialect] = None) -> str:
    """Execute commands via SSH on any device. The reply is read as well as
    the exit status: a CLI that answers "error: ..." or "% ..." (or whatever
    the dialect's `refused` says) and exits 0 has refused the line, and the
    edit stops there; a show whose reply opens that way got no answer, and is
    failed rather than reported as output."""
    client = _connect(host, user, passwd, session_timeout, port)

    try:
        outputs = []
        for cmd in commands:
            rc, out, err = _exec(client, cmd, command_timeout)
            # A server that reports no status at all (-1) is not reporting
            # a failure; some network OSes never send one.
            if rc > 0:
                raise RuntimeError(_describe_failure(cmd, rc, out, err))
            refused = (refusal_line(err, out, dialect=dialect) if edit
                       else refused_reply(err, out, dialect=dialect))
            if refused:
                raise RuntimeError("'%s' was refused by the device: %s" % (cmd, refused))
            outputs.append(_format(cmd, out, err))
        text = "\n\n".join(outputs).strip() + "\n"
        return R.EditResult(R.APPLIED, message=text) if edit else text
    finally:
        client.close()


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = None) -> List[dict]:
    """Execute multiple commands on a single SSH connection."""
    d = _dialect(vendor_hint)
    client = _connect(host, user, passwd, session_timeout, port)
    try:
        results = []
        for cmd in cmds:
            try:
                rc, out, err = _exec(client, cmd, command_timeout)
                refused = refused_reply(err, out, dialect=d) if rc <= 0 else None
                if rc > 0:
                    results.append({"command": cmd, "ok": False,
                                    "error": _describe_failure(cmd, rc, out, err)})
                elif refused:
                    results.append({"command": cmd, "ok": False,
                                    "error": "'%s' was refused by the device: %s" % (cmd, refused)})
                else:
                    results.append({"command": cmd, "ok": True, "output": _format(cmd, out, err)})
            except Exception as e:
                results.append({"command": cmd, "ok": False, "error": str(e)})
        return R.BatchResult(results)
    finally:
        client.close()
