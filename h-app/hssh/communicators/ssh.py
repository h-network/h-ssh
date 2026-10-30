from __future__ import annotations

import base64
import fcntl
import os
from pathlib import Path
import socket
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, cast

from hssh.communicators.base import Communicator, Session
from hssh.dialects.base import Dialect
from hssh.model import Credentials, Fault, FaultKind, HostKeyPolicy, Result, Target, Timeouts

if TYPE_CHECKING:
    from paramiko import Channel, SSHClient, Transport
    from hssh.communicators.cli_engine import CliEngine

IDLE_CHECK_SECONDS = 30
PROBE_SECONDS = 5
_KEYS_LOCK = threading.Lock()
_KEYS: dict = {}


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("SSH deadline expired")
    return remaining


def _stamp(st: os.stat_result) -> tuple[int, int, int, int]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns


def _parse_keys(text: str, path: Path):
    import paramiko

    keys, revoked = paramiko.HostKeys(), set()
    for number, raw in enumerate(text.split("\n"), 1):
        fields = raw.split()
        if not fields or fields[0].startswith("#"):
            continue
        marker = fields.pop(0) if fields[0].startswith("@") else ""
        if marker not in ("", "@revoked"):
            continue
        try:
            names, kind, blob = fields[:3]
            base64.b64decode(blob, validate=True)
            for name in names.split(","):
                if name.startswith("|"):
                    parts = name.split("|")
                    if (len(parts) != 4 or parts[1] != "1" or
                            any(len(base64.b64decode(p, validate=True)) != 20 for p in parts[2:])):
                        raise ValueError("invalid hashed host name")
            entry = paramiko.hostkeys.HostKeyEntry.from_line(f"{names} {kind} {blob}")
            if entry is None:
                continue
        except Exception as exc:
            if marker:
                raise Fault(FaultKind.LOCAL, f"{path}: invalid @revoked entry on line {number}: {exc}", False) from exc
            continue
        if marker:
            revoked.add(entry.key.asbytes())
        else:
            keys._entries.append(entry)
    return keys, frozenset(revoked)


def _flock(file, operation: int, deadline: float) -> None:
    while True:
        _remaining(deadline)
        try:
            fcntl.flock(file, operation | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            time.sleep(min(0.02, _remaining(deadline)))


def _read_keys(path: Path, deadline: float):
    if not _KEYS_LOCK.acquire(timeout=_remaining(deadline)):
        raise TimeoutError("waiting to read SSH known_hosts")
    try:
        while True:
            _remaining(deadline)
            try:
                before = path.stat()
                cached = _KEYS.get(str(path))
                if cached is not None and cached[0] == _stamp(before):
                    return cached[1]
                with path.open(encoding="utf-8", errors="surrogateescape") as source:
                    _flock(source, fcntl.LOCK_SH, deadline)
                    before = os.fstat(source.fileno())
                    text = source.read()
                    if _stamp(os.fstat(source.fileno())) != _stamp(before):
                        continue
                if _stamp(path.stat()) != _stamp(before):
                    continue
            except FileNotFoundError:
                return _parse_keys("", path)
            parsed = _parse_keys(text, path)
            _KEYS[str(path)] = (_stamp(before), parsed)
            return parsed
    except TimeoutError:
        raise
    except OSError as exc:
        raise Fault(FaultKind.LOCAL, f"cannot read {path}: {exc}", False) from exc
    finally:
        _KEYS_LOCK.release()


def _verify(keys, revoked, hostname: str, key) -> bool:
    if key.asbytes() in revoked:
        raise Fault(FaultKind.HOST_KEY, f"SSH key for {hostname} is marked @revoked", True)
    known = keys.lookup(hostname)
    if known is None:
        return False
    if known.get(key.get_name()) != key:
        raise Fault(FaultKind.HOST_KEY, f"SSH key for {hostname} differs from known_hosts", True)
    return True


def _accept_key(path: Path, hostname: str, key, deadline: float) -> None:
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_APPEND, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8", errors="surrogateescape") as out:
            _flock(out, fcntl.LOCK_EX, deadline)
            text = out.read()
            keys, revoked = _parse_keys(text, path)
            if _verify(keys, revoked, hostname, key):
                return
            _remaining(deadline)
            prefix = "\n" if text and not text.endswith("\n") else ""
            out.write(f"{prefix}{hostname} {key.get_name()} {key.get_base64()}\n")
            out.flush()
            os.fsync(out.fileno())
    except TimeoutError:
        raise
    except OSError as exc:
        raise Fault(FaultKind.LOCAL, f"cannot update {path}: {exc}", True) from exc


def _abort(client: SSHClient | Transport, sock: socket.socket | None) -> None:
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
    try:
        client.close()
    except Exception:
        pass


class _Deadline:
    def __init__(self, deadline: float, abort: Callable[[], None]) -> None:
        self.deadline = deadline
        self.abort = abort
        self.expired = False
        self.lock = threading.Lock()
        self.timer: threading.Timer | None = None
        self.active = True
        self.arm()

    def arm(self) -> None:
        if self.timer is not None:
            self.timer.cancel()
        self.timer = threading.Timer(max(0, self.deadline - time.monotonic()), self.expire, (self.deadline,))
        self.timer.daemon = True
        self.timer.start()

    def expire(self, deadline: float) -> None:
        with self.lock:
            if not self.active or self.deadline != deadline:
                return
            self.expired = True
        # Socket shutdown wakes request acknowledgements and rekey-blocked writes.
        self.abort()

    def finish(self) -> None:
        with self.lock:
            _remaining(self.deadline)
            if self.expired:
                raise TimeoutError("SSH deadline expired")
            self.active = False

    def stop(self) -> None:
        with self.lock:
            self.active = False
            if self.timer is not None:
                self.timer.cancel()


class _Opening(_Deadline):
    def __init__(self, client: SSHClient, timeouts: Timeouts) -> None:
        self.sock: socket.socket | None = None
        self.timeouts = timeouts
        self.banner = False
        self.stage = "TCP connect"
        super().__init__(time.monotonic() + timeouts.connect, lambda: _abort(client, self.sock))

    def received_banner(self) -> None:
        with self.lock:
            _remaining(self.deadline)
            self.banner = True
            self.stage = "key exchange"
            self.deadline = time.monotonic() + self.timeouts.setup
            self.arm()

    def connect(self, host: str, port: int) -> socket.socket:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        errors = []
        for family, kind, proto, _, address in addresses:
            _remaining(self.deadline)
            sock = self.sock = socket.socket(family, kind, proto)
            try:
                sock.settimeout(_remaining(self.deadline))
                sock.connect(address)
                self.stage = "SSH banner"
                return sock
            except OSError as exc:
                errors.append(exc)
                sock.close()
        if errors:
            raise errors[-1]
        raise OSError("no addresses returned for SSH endpoint")


def _open_fault(exc: Exception, opening: _Opening) -> Fault:
    import paramiko

    if isinstance(exc, Fault):
        return exc
    detail = f"{opening.stage}: {type(exc).__name__}: {exc}"
    causes = []
    cause = exc
    while cause is not None and id(cause) not in {id(e) for e in causes}:
        causes.append(cause)
        cause = cause.__cause__ or cause.__context__
    if opening.expired or any(isinstance(e, TimeoutError) for e in causes):
        kind = FaultKind.TIMEOUT
    elif isinstance(exc, paramiko.BadHostKeyException):
        kind = FaultKind.HOST_KEY
    elif isinstance(exc, (paramiko.AuthenticationException, paramiko.PasswordRequiredException)):
        kind = FaultKind.AUTH
    elif isinstance(exc, paramiko.SSHException) and "no authentication methods" in str(exc).lower():
        kind = FaultKind.AUTH
    elif isinstance(exc, socket.gaierror):
        kind = FaultKind.UNREACHABLE if exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)) else FaultKind.SESSION_LOST
    elif opening.stage == "TCP connect" and isinstance(exc, OSError):
        kind = FaultKind.UNREACHABLE
    elif isinstance(exc, (FileNotFoundError, PermissionError, ValueError)):
        kind = FaultKind.LOCAL
    else:
        kind = FaultKind.SESSION_LOST
    return Fault(kind, detail, opening.banner)


class ShellChannel:
    def __init__(self, channel: Channel) -> None:
        self.channel = channel

    def recv(self, n: int, timeout: float) -> bytes:
        try:
            self.channel.settimeout(timeout)
            data = self.channel.recv(n)
            if not data:
                raise ConnectionError("SSH channel closed by peer")
            return data
        except TimeoutError:
            raise
        except Exception as exc:
            raise ConnectionError(str(exc) or type(exc).__name__) from exc

    def send(self, data: bytes, deadline: float) -> None:
        _remaining(deadline)
        transport = self.channel.get_transport()
        guard = _Deadline(deadline, lambda: _abort(transport, transport.sock))
        try:
            while data:
                self.channel.settimeout(_remaining(deadline))
                sent = self.channel.send(data)
                if sent <= 0:
                    raise ConnectionError("SSH channel closed by peer")
                data = data[sent:]
            guard.finish()
        except TimeoutError:
            raise
        except Exception as exc:
            if guard.expired or time.monotonic() >= deadline:
                raise TimeoutError("SSH write deadline expired") from exc
            raise ConnectionError(str(exc) or type(exc).__name__) from exc
        finally:
            guard.stop()

    def close(self) -> None:
        self.channel.close()


@dataclass
class SSHSession:
    client: SSHClient
    engine: CliEngine


class SSHCommunicator(Communicator):
    default_port: int = 22
    banner: bytes | None = b"SSH-"
    ssh_config = None
    capabilities: frozenset[str] = frozenset({"show", "batch"})

    def __init__(self, dialect: Dialect) -> None:
        self.dialect = dialect

    def open(self, target: Target, creds: Credentials, timeouts: Timeouts,
             host_key_policy: HostKeyPolicy) -> SSHSession:
        try:
            import paramiko
        except ImportError as exc:
            raise Fault(FaultKind.LOCAL, "Paramiko is required for SSH", False) from exc
        from hssh.communicators.cli_engine import CliEngine

        client = paramiko.SSHClient()
        opening = _Opening(client, timeouts)
        path = Path("~/.ssh/known_hosts").expanduser()
        revoked = frozenset()

        class Policy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                if host_key_policy == "off":
                    return
                if host_key_policy == "strict":
                    raise Fault(FaultKind.HOST_KEY, f"SSH key for {hostname} is absent from {path}", True)
                _accept_key(path, hostname, key, opening.deadline)

        class Transport(paramiko.Transport):
            def _check_banner(self):
                super()._check_banner()
                opening.received_banner()

            def start_client(self, event=None, timeout=None):
                return super().start_client(event=event, timeout=None)

            def get_remote_server_key(self):
                key = super().get_remote_server_key()
                if key.asbytes() in revoked:
                    raise Fault(FaultKind.HOST_KEY, "SSH key is marked @revoked in known_hosts", True)
                opening.stage = "authentication"
                return key

        try:
            if host_key_policy not in ("off", "strict", "accept-new"):
                raise Fault(FaultKind.LOCAL, f"unknown SSH host-key policy: {host_key_policy}", False)
            if host_key_policy != "off":
                client._host_keys, revoked = _read_keys(path, opening.deadline)
            client.set_missing_host_key_policy(Policy())
            sock = opening.connect(target.host, self.default_port if target.port is None else target.port)

            def transport_factory(sock, **kwargs):
                transport = Transport(sock, **kwargs)
                transport.handshake_timeout = timeouts.setup
                return transport

            implicit_keys = creds.password is None and creds.key_file is None
            client.connect(hostname=target.host, port=self.default_port if target.port is None else target.port,
                           sock=sock, username=creds.username, password=creds.password,
                           key_filename=os.path.expanduser(creds.key_file) if creds.key_file else None,
                           allow_agent=implicit_keys, look_for_keys=implicit_keys,
                           banner_timeout=_remaining(opening.deadline), auth_timeout=timeouts.setup,
                           channel_timeout=timeouts.setup, transport_factory=transport_factory)
            opening.stage = "channel open and PTY/shell acknowledgement"
            channel = client.invoke_shell(term="vt100", width=511, height=1000)
            opening.stage = "CLI prompt discovery"
            engine = CliEngine(ShellChannel(channel), self.dialect, timeouts, echoes=True)
            engine.login(opening.deadline)
            opening.finish()
            return SSHSession(client, engine)
        except BaseException as exc:
            _abort(client, opening.sock)
            if isinstance(exc, Fault):
                raise
            if isinstance(exc, Exception):
                raise _open_fault(exc, opening) from exc
            raise
        finally:
            opening.stop()

    def close(self, session: Session) -> None:
        ssh_session = cast(SSHSession, session)
        sock = getattr(ssh_session.client.get_transport(), "sock", None)
        guard = _Deadline(time.monotonic() + ssh_session.engine.timeouts.command,
                          lambda: _abort(ssh_session.client, sock))
        try:
            ssh_session.engine.close()
        finally:
            guard.stop()
            _abort(ssh_session.client, sock)

    def reuse(self, session: Session, timeouts: Timeouts, idle_seconds: int) -> bool:
        ssh_session = cast(SSHSession, session)
        transport = ssh_session.client.get_transport()
        channel = ssh_session.engine.channel.channel
        if (transport is None or not transport.is_active() or not transport.is_authenticated() or
                channel.closed or channel.eof_received or not ssh_session.engine.ready):
            return False
        ssh_session.engine.timeouts = timeouts
        return idle_seconds < IDLE_CHECK_SECONDS or ssh_session.engine.probe(time.monotonic() + PROBE_SECONDS)

    def release(self, session: Session) -> None:
        cast(SSHSession, session).engine.release()

    def discard(self, session: Session) -> None:
        ssh_session = cast(SSHSession, session)
        _abort(ssh_session.client, getattr(ssh_session.client.get_transport(), "sock", None))
        ssh_session.engine.discard()

    def show(self, session: Session, command: str) -> Result:
        return cast(SSHSession, session).engine.show(command)

    def structured(self, session: Session, rpc: str, fmt: str) -> Result:
        raise Fault(FaultKind.UNSUPPORTED, "Structured RPCs require NETCONF", False)

    def load(self, session: Session, lines: list[str]) -> Result:
        return cast(SSHSession, session).engine.load(lines)

    def diff(self, session: Session) -> Result:
        return cast(SSHSession, session).engine.diff()

    def commit(self, session: Session, confirmed_minutes: int | None, comment: str | None) -> Result:
        return cast(SSHSession, session).engine.commit(confirmed_minutes, comment)

    def confirm(self, session: Session) -> Result:
        return cast(SSHSession, session).engine.confirm()

    def commit_history(self, session: Session) -> Result:
        return cast(SSHSession, session).engine.commit_history()
