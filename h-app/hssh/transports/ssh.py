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
credential is sent. A pin is written to a new file that is renamed over the
old one, so a reader never sees a part of it. ~/.ssh/known_hosts is read as
well, never written: it is OpenSSH's. Its @revoked keys are refused, and its
@cert-authority lines are passed over: paramiko cannot check a host
certificate.
"""

import base64
import fcntl
import functools
import json
import socket
import stat
import tempfile
import time
import os
import threading
from pathlib import Path
from typing import List, Optional

from .. import drivers
from ..core import refusal_line, refused_reply
from ..dialects.base import Dialect
from ..drivers import results as R
from ..errors import ConnectTimeoutError, LocalError, NotAppliedError
from .cli import Cli, edit_policy, refuse_comment, refuse_commit_lines, refuse_control_characters
from .connect import (DEFAULT as DEFAULT_CONNECT_TIMEOUT, answered, budget, is_timeout, no_banner,
                      tcp_timed_out, where)

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

    def __init__(self, path: str, timeout: float = 30.0):
        self.path = path
        self.timeout = timeout      # how long another run may hold the lock with nothing pinned

    def missing_host_key(self, client, hostname, key):
        # The thread lock serialises this process's workers; the file lock
        # serialises processes, so two h-ssh runs pinning at once cannot
        # rewrite the file over each other's pins. The host is looked up
        # again in the file as it is now: a pin another run wrote since this
        # connection read the file is checked, never pinned over.
        with _PIN_LOCK:
            fd = _locked(self.path, fcntl.LOCK_EX, self.timeout)
            try:
                old = os.fstat(fd)
                signature, text = _read(fd)
                cached = _PINS.get(self.path)
                if cached is not None and cached[0] == signature:
                    # The file as this process parsed it last; a copy, as
                    # connections are reading the shared one.
                    keys = paramiko.HostKeys()
                    keys._entries = list(cached[1]._entries)
                else:
                    keys, _ = _parse(text, self.path, system=False)
                pinned = keys.lookup(hostname)
                if pinned is None:
                    if text and not text.endswith("\n"):
                        text += "\n"
                    signature = _save(self.path, f"{text}{hostname} {key.get_name()} {key.get_base64()}\n", old)
                    keys.add(hostname, key.get_name(), key)
                elif pinned.get(key.get_name()) != key:
                    raise paramiko.BadHostKeyException(hostname, key, list(pinned.values())[0])
                # The process's shared copy of the file (see _parsed), as it now is.
                _PINS[self.path] = (signature, keys, frozenset())
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
_PINS: dict = {}            # path -> (signature, HostKeys, revoked key blobs)


def _stamp(st):
    return (st.st_ino, st.st_size, st.st_mtime_ns)


def _signature(path: str):
    try:
        return _stamp(os.stat(path))
    except OSError:
        return None


# The pin file as it was when a wait for its lock last gave up, by path. A
# wait that finds the lock still held on that same file gives up at once: the
# workers queued behind the one that waited do not each wait a session
# timeout in turn for a run that has not moved since.
_GAVE_UP: dict = {}         # path -> signature


def _locked(path: str, op: int, timeout: float) -> int:
    """An fd on our pin file, flock()ed with `op`: LOCK_SH to read it,
    LOCK_EX to pin. Caller holds _PIN_LOCK, and the wait starts there: the
    time queued behind this run's own pins is no other run's doing. Another
    run holds the lock as long as a pin takes, and every pin changes the
    file, so the wait goes on while the file does. A lock held `timeout`
    seconds with the file as it was (a run stopped with Ctrl-Z in the middle
    of a pin) is an error that says so, not a wait with no end. A pin
    replaces the file (see _save), so a lock won on the file it replaced is
    let go and taken again on the new one."""
    pause = 0.001
    seen = _signature(path)
    deadline = time.monotonic() + timeout
    while True:
        fd = os.open(path, (os.O_RDWR if op == fcntl.LOCK_EX else os.O_RDONLY) | os.O_CREAT, 0o600)
        try:
            while True:
                try:
                    fcntl.flock(fd, op | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    current = _signature(path)
                    if current != seen:             # the holder pinned: it is alive
                        seen, deadline = current, time.monotonic() + timeout
                    elif time.monotonic() >= deadline or (path in _GAVE_UP and _GAVE_UP[path] == current):
                        _GAVE_UP[path] = current
                        raise LocalError(f"{path} is locked by another h-ssh run (one stopped with Ctrl-Z "
                                           "while it pinned?); resume or end it") from None
                    time.sleep(pause)
                    pause = min(pause * 2, 0.05)
            held, now = os.fstat(fd), os.stat(path)
            if (held.st_dev, held.st_ino) == (now.st_dev, now.st_ino):
                _GAVE_UP.pop(path, None)
                return fd
        except FileNotFoundError:
            pass                # removed under us: open it again
        except BaseException:
            os.close(fd)
            raise
        os.close(fd)


def _read(fd: int):
    """(signature, text) of the file open on fd. A byte that is not UTF-8
    is kept as it is (surrogateescape), so _save writes it back unchanged.
    The signature is the file's before the read: stamped after it, a line
    OpenSSH appended to ~/.ssh/known_hosts in between was cached as read,
    for good. A file that changed during the read gets a signature equal to
    nothing, so what was read is matched with no file and no parse."""
    before = _stamp(os.fstat(fd))
    with open(fd, "rb", closefd=False) as f:
        data = f.read()
    signature = before if _stamp(os.fstat(fd)) == before else object()
    return signature, data.decode("utf-8", "surrogateescape")


def _save(path: str, text: str, old: os.stat_result):
    """Write the pin file anew and rename it over the old one: a reader has
    the old file or the new one, never a part. (paramiko's save truncated
    the file and wrote it again; a run reading in between saw no pins.)
    The new file keeps the old one's (`old`) mode, and its owner and group
    as far as this user may set them. Returns the new file's signature."""
    target = os.path.realpath(path)         # a pin file that is a symlink stays one
    fd, tmp = tempfile.mkstemp(prefix=".known_hosts.", dir=os.path.dirname(target))
    try:
        with open(fd, "w", encoding="utf-8", errors="surrogateescape") as f:
            for uid in (old.st_uid, -1):
                try:
                    os.fchown(fd, uid, old.st_gid)
                    break
                except OSError:
                    pass
            try:
                os.fchmod(fd, stat.S_IMODE(old.st_mode))
            except OSError:
                pass            # a file system without modes: mkstemp's 0600 stays
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
            signature = _stamp(os.fstat(f.fileno()))
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return signature


class _UnknownKeyType(ValueError):
    pass


def _hashed(name: str) -> bool:
    """A hashed host name as paramiko reads one: |1|salt|hash, each 20 bytes."""
    parts = name.split("|")
    try:
        return len(parts) == 4 and all(len(base64.b64decode(p, validate=True)) == 20 for p in parts[2:])
    except ValueError:
        return False


def _entry(line: str):
    """The pin on a known_hosts line (its marker taken off) as paramiko's
    HostKeyEntry; ValueError saying why for a line that holds none."""
    fields = line.split()
    if len(fields) < 3:
        raise ValueError("expected host, key type and key")
    names, kind, blob = fields[:3]
    if any(n.startswith("|1|") and not _hashed(n) for n in names.split(",")):
        raise ValueError("a hashed host name that is not |1|salt|hash")
    try:
        base64.b64decode(blob, validate=True)
    except ValueError:
        raise ValueError("the key is not base64") from None
    try:
        entry = paramiko.hostkeys.HostKeyEntry.from_line(f"{names} {kind} {blob}")
    except Exception:
        raise ValueError(f"the key does not decode as {kind}") from None
    if entry is None:
        raise _UnknownKeyType(f"unknown key type {kind}")
    return entry


def _parse(text: str, path: str, system: bool):
    """(HostKeys, revoked key blobs) of a known_hosts file's text.

    paramiko's own load() drops a line it cannot use without a word: the host
    it pinned counts as unknown, is pinned again on trust, and the line goes
    at the next save; a hashed name with a bad salt fails every lookup with
    an empty AssertionError. Here such a line is a refusal that names it.
    ~/.ssh/known_hosts (system) is OpenSSH's and read as OpenSSH reads it:
    a line that holds no key OpenSSH or paramiko can use is passed over, and
    so are @cert-authority lines (paramiko cannot check a host certificate)
    and lines with a marker OpenSSH does not have. Its @revoked keys are
    returned, to be refused whenever a server presents one; an @revoked line
    that cannot be read is still a refusal: a revocation is never dropped.
    A line ends at a newline only, as OpenSSH reads it (splitlines() ended
    one at a form feed too)."""
    keys = paramiko.HostKeys()
    revoked = set()
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        marker = line.split(None, 1)[0] if line.startswith("@") else ""
        if system and marker not in ("", "@revoked"):
            continue        # @cert-authority, or a marker OpenSSH does not have and passes over
        try:
            if marker and not system:
                raise ValueError("markers are read from ~/.ssh/known_hosts only")
            entry = _entry(line[len(marker):])
        except ValueError as e:
            # OpenSSH passes such a line over; a revoked key of a type
            # paramiko does not know is not one paramiko can be shown.
            if system and (not marker or isinstance(e, _UnknownKeyType)):
                continue
            raise ValueError(f"{path}: malformed known_hosts line {n}: {line!r} ({e}); "
                             "fix or remove it") from None
        if marker:
            revoked.add(entry.key.asbytes())
        else:
            keys._entries.append(entry)     # as load() does, less its O(n²) de-duplication
    return keys, frozenset(revoked)


def _parsed(path: str, system: bool, timeout: float):
    """(HostKeys, revoked) of a known_hosts file, parsed once and shared
    until the file changes; a missing file is none. Our own pin file is read
    under a shared file lock: a save in progress is waited for (see _locked,
    `timeout` the session timeout), not read half done. Caller holds
    _PIN_LOCK."""
    signature = _signature(path)
    cached = _PINS.get(path)
    if cached is not None and cached[0] == signature:
        return cached[1], cached[2]
    if signature is None:
        keys, revoked = paramiko.HostKeys(), frozenset()
    else:
        fd = os.open(path, os.O_RDONLY) if system else _locked(path, fcntl.LOCK_SH, timeout)
        try:
            signature, text = _read(fd)
        finally:
            os.close(fd)        # and with it the lock
        keys, revoked = _parse(text, path, system)
    _PINS[path] = (signature, keys, revoked)
    return keys, revoked


def _load_pins(client, known_hosts: str, timeout: float = 30.0) -> frozenset:
    """~/.ssh/known_hosts (read only) and h-ssh's own pin file; returns the
    keys ~/.ssh/known_hosts marks @revoked. A pin file line that cannot be
    parsed is a refusal, not a skip: the pin it was meant to hold is
    unknown, and retrying the file cannot change it. Another run's lock on
    the pin file is waited for as _locked says, `timeout` being the session
    timeout."""
    system = str(Path.home() / ".ssh" / "known_hosts")
    with _PIN_LOCK:
        system_keys, revoked = _parsed(system, system=True, timeout=timeout)
        keys, _ = _parsed(known_hosts, system=False, timeout=timeout)
    # What load_system_host_keys()/load_host_keys() would have filled,
    # without parsing the file for this client alone.
    client._system_host_keys = system_keys
    client._host_keys = keys
    client._host_keys_filename = known_hosts
    return revoked


def _host_key_policy(known_hosts: str, timeout: float = 30.0):
    """The missing-host-key policy HSSH_HOST_KEY_POLICY asks for.

    Only an unknown host is a policy matter. A pinned host that presents a
    different key is refused by paramiko itself, whatever the policy.
    """
    policy = os.environ.get("HSSH_HOST_KEY_POLICY", "accept-new")
    if policy == "accept-new":
        return _PinPolicy(known_hosts, timeout)
    if policy == "yes":
        return _RejectPolicy()
    if policy == "no":
        return paramiko.WarningPolicy()
    raise RuntimeError("invalid HSSH_HOST_KEY_POLICY=%r (expected accept-new, yes or no)"
                       % policy)


class _RevokedKey(Exception):
    """The server presented a key ~/.ssh/known_hosts marks @revoked."""


if AVAILABLE:
    class _Transport(paramiko.Transport):
        """paramiko's Transport with what SSHClient.connect() cannot be
        told: the banner is due by the end of the connect phase
        (`banner_by`, --connect-timeout from the TCP connect on, #126), the
        negotiation after it gets the session timeout rather than the TCP
        connect's timeout that connect() hands on, the key exchange the
        session timeout rather than a fixed 15 s after the banner, and a
        key ~/.ssh/known_hosts marks @revoked is refused the moment it
        arrives, before any pin is looked at or any credential sent,
        whatever the policy."""

        def __init__(self, sock, handshake_timeout=15.0, revoked=frozenset(), banner_by=None,
                     negotiation_timeout=None, **kw):
            super().__init__(sock, **kw)
            self.handshake_timeout = handshake_timeout
            self._hssh_revoked = revoked
            self._hssh_banner_by = banner_by
            self._hssh_negotiation = negotiation_timeout

        @property
        def banner_timeout(self):
            # Read by paramiko's own thread when it starts waiting for the banner.
            by = self.__dict__.get("_hssh_banner_by")
            if by is None:
                return self.__dict__.get("_hssh_banner_timeout", 15)
            return max(0.1, by - time.monotonic())

        @banner_timeout.setter
        def banner_timeout(self, value):
            self.__dict__["_hssh_banner_timeout"] = value

        def start_client(self, event=None, timeout=None):
            if self._hssh_negotiation is not None:
                timeout = self._hssh_negotiation
            return super().start_client(event=event, timeout=timeout)

        def get_remote_server_key(self):
            key = super().get_remote_server_key()
            if key.asbytes() in self._hssh_revoked:
                raise _RevokedKey()
            return key


# What a connect that stopped between the server's banner and the end of the
# key exchange says. paramiko says EOFError('') (its handshake timer, or the
# server closing) or 'No existing session' (start_client() ran out of time and
# connect() asked for the server's key anyway), and the FAIL line was empty.
_KEX_UNFINISHED = "the banner came, but key exchange did not finish"


def _kex_unfinished(t, exc) -> bool:
    """True when connect() stopped in the key exchange with nothing to say
    for itself."""
    if t is None or not t.remote_version or t.initial_kex_done:
        return False
    return isinstance(exc, EOFError) or str(exc) == "No existing session"


def _no_banner(t, exc) -> bool:
    """True when connect() stopped before the server's banner came, for
    want of time: paramiko's banner wait ran out (a timeout under "Error
    reading SSH protocol banner"), or start_client() gave up first and
    connect() asked for the server's key anyway ("No existing session"). A
    server that closed first is an EOF under the same words, and not this."""
    if t is None or getattr(t, "remote_version", ""):
        return False
    if str(exc) == "No existing session":
        return True
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, TimeoutError):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


# The resolver's own answer that the name does not exist: the same name gets
# the same answer. Any other failure of the lookup, EAI_AGAIN above all (no
# answer from the resolver in time), may pass.
_NO_SUCH_NAME = frozenset({socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)})


def _tcp_failure(exc: OSError, host: str, at: str, seconds) -> Exception:
    """The TCP connect's end in words (#126). paramiko lets a timeout and a
    resolver failure through as they are, and wraps a refusal or no route in
    NoValidConnectionsError, whose message ("Unable to connect to port 22 on
    HOST") says neither; the OS's own answer is in its `errors`. A name
    that does not exist is "cannot resolve HOST" and fails once; a lookup
    that failed otherwise is said in the OS's words and, nothing sent, is
    tried again, an edit too."""
    if isinstance(exc, socket.gaierror):
        if exc.errno in _NO_SUCH_NAME:
            return RuntimeError(f"cannot resolve {host}")
        return NotAppliedError(f"name lookup for {host} failed: {exc.strerror or exc}")
    errors = list((getattr(exc, "errors", None) or {}).values())
    if errors:
        exc = errors[-1]                     # the last address tried, as ssh reports it
    if is_timeout(exc):
        return ConnectTimeoutError(tcp_timed_out(at, seconds))
    return RuntimeError(answered(exc, at))


def _connect(host: str, user: str, passwd: Optional[str], session_timeout: int,
             port: Optional[int], connect_timeout: int = DEFAULT_CONNECT_TIMEOUT):
    """A connected SSHClient, host key checked, ready for exec_command. The
    TCP connect and the banner have --connect-timeout between them (#126);
    the key exchange, the authentication and a channel open have the session
    timeout each."""
    if not AVAILABLE:
        raise RuntimeError("paramiko not available in this environment.")

    session_timeout_float = float(session_timeout)
    connect_s = budget(connect_timeout, session_timeout)
    at = where(host, port or 22)
    known_hosts = _known_hosts()
    client = paramiko.SSHClient()
    revoked = _load_pins(client, known_hosts, session_timeout_float)
    client.set_missing_host_key_policy(_host_key_policy(known_hosts, session_timeout_float))

    conn_params = {
        "hostname": host,
        "username": user,
        "port": port or 22,
        # The TCP connect, each address of the name; connect() hands it on
        # to the negotiation too, which _Transport takes back.
        "timeout": float(connect_s),
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

    started = time.monotonic()
    # connect() takes no handshake_timeout: the key exchange had a fixed 15 s
    # after the banner, whatever --session-timeout said; and its banner_timeout
    # is a wait of its own, which here is what is left of the connect phase.
    conn_params["transport_factory"] = functools.partial(
        _Transport, handshake_timeout=session_timeout_float, revoked=revoked,
        banner_by=started + connect_s, negotiation_timeout=session_timeout_float)
    try:
        client.connect(**conn_params)
    except _RevokedKey:
        client.close()
        raise RuntimeError("Host key verification failed for %s: its key is marked @revoked "
                           "in ~/.ssh/known_hosts." % host) from None
    except paramiko.BadHostKeyException as exc:
        client.close()
        raise RuntimeError(
            "Host key verification failed for %s: the key is not the one pinned. "
            "If the device was re-keyed, remove its line from %s (or ~/.ssh/known_hosts)."
            % (host, known_hosts)) from exc
    except (paramiko.SSHException, EOFError) as exc:
        t = client.get_transport()
        kex, banner = _kex_unfinished(t, exc), _no_banner(t, exc)
        client.close()
        if "no authentication methods available" in str(exc).lower():
            # paramiko found nothing to offer: no password, no ~/.ssh/id_*, no agent key.
            raise RuntimeError(
                "No authentication methods available for %s@%s: no password was given and "
                "no key was found in ~/.ssh or from an agent." % (user, host)) from exc
        if banner:
            raise ConnectTimeoutError(no_banner(at, connect_s)) from exc
        if kex:
            elapsed = time.monotonic() - started
            if elapsed < session_timeout_float / 2:
                raise RuntimeError(f"{host} dropped the session before login after {elapsed:.1f}s "
                                   f"({_KEX_UNFINISHED})") from exc
            raise RuntimeError(f"no SSH session to {host} within {session_timeout}s: {_KEX_UNFINISHED}") from exc
        raise
    except OSError as exc:
        # Before the Transport exists, the TCP connect; after it, something
        # paramiko let through as it was, which stays as it is.
        before = client.get_transport() is None
        client.close()
        if before:
            raise _tcp_failure(exc, host, at, connect_s) from exc
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
                   port: Optional[int], dialect: Dialect, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT):
    """(client, session): a CLI session at the device's own prompt on a shell
    channel of a fresh connection; the caller closes both. The terminal is
    wide so the device never wraps the echo of a long line, which the engine
    must recognise as the echo. There is no login dialogue over SSH: login()
    reads the banner up to the prompt and learns this device's own."""
    client = _connect(host, user, passwd, session_timeout, port, connect_timeout)
    try:
        chan = client.invoke_shell(term="vt100", width=511, height=1000)
        session = Cli(ShellChannel(chan), dialect, session_timeout)
        session.login(user, passwd)
    except BaseException:
        client.close()
        raise
    return client, session


def show(host: str, user: str, passwd: str, cmd: str, session_timeout: int,
         command_timeout: int, port: int = None, vendor_hint: str = None,
         connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> str:
    """One show command on an exec channel; a reply the dialect's CLI opens
    with a refusal is a failure, not output. `connect_timeout` bounds the
    TCP connect and the SSH banner, never more than `session_timeout` (every
    function here that connects takes it)."""
    return _run_commands(host, user, passwd, [cmd], session_timeout, command_timeout, port=port,
                         dialect=_dialect(vendor_hint), connect_timeout=connect_timeout)


def edit(host: str, user: str, passwd: str, payload: str, session_timeout: int,
         command_timeout: int, commit_confirmed: int = None, port: int = None,
         vendor_hint: str = None, dry_run: bool = False,
         expected_diff: Optional[str] = None, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> R.EditResult:
    """Push configuration.

    The none dialect (the plain `ssh` driver) runs each line as its own exec
    command and applies what it is given: a rollback timer has no equivalent
    there, so asking for one is refused, not dropped, and so are a dry run
    and a diff check. A dialect's edit goes through the CLI engine on a shell
    channel: Junos gets configure exclusive, the lines, show | compare and a
    commit (confirmed with a timer, or rollback 0 for a dry run, or only if
    the diff is still what the dry run showed); an IOS-shaped dialect gets
    configure terminal, the lines, end, and refuses dry_run, commit_confirmed
    and expected_diff before anything is sent. A payload the CLI engine would
    type with a control character or a Tab in it is refused before connecting:
    the CLI takes either as a key (cli.refuse_control_characters).
    """
    d = _dialect(vendor_hint)
    if d is drivers.NONE:
        if commit_confirmed is not None:
            raise ValueError("commit_confirmed is not supported by the 'ssh' transport; "
                             "nothing was sent to the device")
        edit_policy(d, vendor_hint or "ssh", dry_run, None, expected_diff)
        commands = [ln.strip() for ln in payload.strip().splitlines() if ln.strip()]
        return _run_commands(host, user, passwd, commands, session_timeout, command_timeout, port=port,
                             edit=True, dialect=d, connect_timeout=connect_timeout)
    if d.cli is None:
        raise ValueError(f"{vendor_hint}: the {d.title} dialect has no CLI to type at; "
                         "nothing was sent to the device")
    edit_policy(d, vendor_hint, dry_run, commit_confirmed, expected_diff)
    refuse_control_characters(payload)
    if d.cli.has_candidate:
        refuse_commit_lines(payload)
    client, session = _shell_session(host, user, passwd, session_timeout, port, d, connect_timeout)
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
            comment: Optional[str] = None, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> R.EditResult:
    """Confirm a pending commit-confirmed on a Junos device over SSH: `show
    system commit` must show one waiting, then configure exclusive, a bare
    `commit` (`commit comment "…"` with a comment), exit. Only a dialect with
    a candidate and a commit history has anything to confirm. A comment with
    a control character, a Tab or a double quote in it is refused before
    connecting (cli.refuse_comment)."""
    d = _dialect(vendor_hint)
    if d.cli is None or not d.cli.has_candidate or d.commit_pending is None:
        raise ValueError(f"confirm is only for a Junos dialect, not {vendor_hint}; nothing was sent")
    refuse_comment(comment)
    client, session = _shell_session(host, user, passwd, session_timeout, port, d, connect_timeout)
    try:
        return session.confirm(command_timeout, comment)
    finally:
        session.close()
        client.close()


def show_structured(host: str, user: str, passwd: str, cmd: str,
                    session_timeout: int, command_timeout: int,
                    port: int = None, vendor_hint: str = None,
                    binding: Optional[dict] = None, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT):
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
    client = _connect(host, user, passwd, session_timeout, port, connect_timeout)
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
                  edit: bool = False, dialect: Optional[Dialect] = None,
                  connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> str:
    """Execute commands via SSH on any device. The reply is read as well as
    the exit status: a CLI that answers "error: ..." or "% ..." (or whatever
    the dialect's `refused` says) and exits 0 has refused the line, and the
    edit stops there; a show whose reply opens that way got no answer, and is
    failed rather than reported as output."""
    client = _connect(host, user, passwd, session_timeout, port, connect_timeout)

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
               port: int = None, vendor_hint: str = None,
               connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> List[dict]:
    """Execute multiple commands on a single SSH connection."""
    d = _dialect(vendor_hint)
    client = _connect(host, user, passwd, session_timeout, port, connect_timeout)
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
