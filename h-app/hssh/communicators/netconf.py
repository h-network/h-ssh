"""NETCONF show and batch sessions through PyEZ; edit and structured RPCs are stubs."""

from __future__ import annotations

from base64 import b64decode
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import errno
import fcntl
import hmac
import os
from pathlib import Path
import socket
from threading import RLock, Timer
from time import monotonic, sleep
from typing import TYPE_CHECKING, cast

from hssh.communicators.base import Communicator, Session
from hssh.dialects.base import Dialect
from hssh.model import Credentials, Fault, FaultKind, HostKeyPolicy, Result, Target, Timeouts

if TYPE_CHECKING:
    from jnpr.junos import Device
    from jnpr.junos.utils.config import Config
    from paramiko import PKey


try:
    from ncclient.transport import session as _ncclient_session
except ImportError:
    pass
else:
    # Poll queued NETCONF sends every 10 ms to reduce request and close latency.
    _ncclient_session.TICK = 0.01


_HOST_KEYS_LOCK = RLock()
_HOST_KEYS: dict[Path, list[tuple[str | tuple[bytes, bytes], PKey]]] = {}
_REVOKED: dict[Path, set[bytes]] = {}
_RESOLVED: dict[tuple[Path, str, int], dict[str, dict[str, PKey]]] = {}
_HOST_KEY_PORT: ContextVar[int | None] = ContextVar("netconf_host_key_port", default=None)
_HOST_KEY_LOADER_INSTALLED = False
_OPENING: ContextVar[_Opening | None] = ContextVar("netconf_opening", default=None)
_SETUP_HOOKS_INSTALLED = False


@dataclass
class _Opening:
    host: str
    port: int
    timeouts: Timeouts
    connected: bool = False
    banner: bool = False
    expired: bool = False
    transport: object = None
    connect_error: OSError | None = None
    timer: Timer | None = None
    lock: object = field(default_factory=RLock)

    def __post_init__(self):
        self.deadline = monotonic() + self.timeouts.connect

    def arm(self):
        with self.lock:
            if self.timer:
                self.timer.cancel()
            deadline = self.deadline

            def expire():
                with self.lock:
                    if self.deadline == deadline:
                        self.expired = True
                        self.transport.close()

            self.timer = Timer(max(0, deadline - monotonic()), expire)
            self.timer.daemon = True
            self.timer.start()

    def finish(self):
        with self.lock:
            self.expired = self.expired or monotonic() >= self.deadline
            self.deadline = float("inf")
            if self.timer:
                self.timer.cancel()

    def timeout_fault(self):
        if not self.connected:
            detail = f"no TCP answer from {self.host}:{self.port} within {self.timeouts.connect}s"
        elif not self.banner:
            detail = f"no SSH banner from {self.host}:{self.port} within {self.timeouts.connect}s"
        elif not self.transport.initial_kex_done:
            detail = f"the banner came, but key exchange did not finish within {self.timeouts.setup}s"
        else:
            detail = f"no NETCONF hello within {self.timeouts.setup}s"
        return Fault(FaultKind.TIMEOUT, detail, self.banner)


@contextmanager
def _opening(host: str, port: int, timeouts: Timeouts):
    state = _Opening(host, port, timeouts)
    token = _OPENING.set(state)
    try:
        yield state
        state.finish()
        if state.expired:
            raise state.timeout_fault()
    except Exception as error:
        raise _fault(error, state.banner, opening=True, setup=state) from error
    finally:
        state.finish()
        _OPENING.reset(token)


def _install_setup_hooks():
    global _SETUP_HOOKS_INSTALLED
    with _HOST_KEYS_LOCK:
        if _SETUP_HOOKS_INSTALLED:
            return
        from ncclient.transport import ssh

        class ConnectSocket(socket.socket):
            def __init__(self, *args, **kwargs):
                try:
                    super().__init__(*args, **kwargs)
                except OSError as error:
                    _OPENING.get().connect_error = error
                    raise

            def connect(self, address):
                state = _OPENING.get()
                self.settimeout(max(0.001, state.deadline - monotonic()))
                try:
                    super().connect(address)
                except OSError as error:
                    state.connect_error = error
                    raise
                state.connected = True

        class DeadlineTransport(ssh.paramiko.Transport):
            def __init__(self, *args, **kwargs):
                self.setup = _OPENING.get()
                super().__init__(*args, **kwargs)
                state = self.setup
                state.connected, state.transport = True, self
                self.banner_timeout = max(0.001, state.deadline - monotonic())
                self.handshake_timeout = self.auth_timeout = self.channel_timeout = state.timeouts.setup
                state.arm()

            def _check_banner(self):
                super()._check_banner()
                state = self.setup
                with state.lock:
                    if state.expired:
                        raise TimeoutError("SSH banner deadline expired")
                    state.banner = True
                    state.deadline = monotonic() + state.timeouts.setup
                    state.arm()

        class ScopedModule:
            def __init__(self, module, name, replacement):
                self.module, self.name, self.replacement = module, name, replacement

            def __getattr__(self, name):
                if name == self.name and _OPENING.get() is not None:
                    return self.replacement
                return getattr(self.module, name)

        original = ssh.SSHSession._post_connect

        def post_connect(session, timeout=60):
            state = _OPENING.get()
            if state is not None:
                timeout = max(0.001, state.deadline - monotonic())
            return original(session, timeout)

        # Only our opens use the deadline socket/transport and remaining hello budget.
        ssh.socket = ScopedModule(ssh.socket, "socket", ConnectSocket)
        ssh.paramiko = ScopedModule(ssh.paramiko, "Transport", DeadlineTransport)
        ssh.SSHSession._post_connect = post_connect
        _SETUP_HOOKS_INSTALLED = True


def _known_keys(path: Path, host: str, port: int) -> dict[str, dict[str, PKey]]:
    from paramiko import SSHException
    from paramiko.hostkeys import HostKeyEntry

    with _HOST_KEYS_LOCK:
        if path not in _HOST_KEYS:
            entries = []
            revoked = set()
            lines = path.read_text(encoding="utf-8", errors="surrogateescape").split("\n") if path.exists() else ()
            for number, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                marker = line.split(None, 1)[0] if line.startswith("@") else ""
                if marker not in ("", "@revoked"):
                    continue
                try:
                    fields = line[len(marker):].split()
                    if marker and len(fields) < 3:
                        raise ValueError("invalid revoked key")
                    entry = HostKeyEntry.from_line(" ".join(fields[:3]))
                except (SSHException, ValueError) as error:
                    if marker:
                        raise ValueError(f"{path}: invalid @revoked entry at line {number}: {error}") from error
                    if not isinstance(error, SSHException):
                        raise
                    continue
                if entry is None:
                    continue
                if marker:
                    revoked.add(entry.key.asbytes())
                    continue
                for name in entry.hostnames:
                    pattern = name
                    if name.startswith("|1|"):
                        _, _, salt, digest = name.split("|")
                        pattern = (b64decode(salt), b64decode(digest))
                        if len(pattern[0]) != 20:
                            raise ValueError("invalid known-hosts hash salt")
                    entries.append((pattern, entry.key))
            _HOST_KEYS[path] = entries
            _REVOKED[path] = revoked
        cache_key = (path, host, port)
        if cache_key not in _RESOLVED:
            resolved = {host: {}, f"[{host}]:{port}": {}}
            encoded = {name: name.encode() for name in resolved}
            for pattern, key in _HOST_KEYS[path]:
                for name, keys in resolved.items():
                    matches = (pattern == name if isinstance(pattern, str) else
                               hmac.compare_digest(hmac.digest(pattern[0], encoded[name], "sha1"), pattern[1]))
                    if matches:
                        keys.setdefault(key.get_name(), key)
            _RESOLVED[cache_key] = resolved
        return _RESOLVED[cache_key]


class _SessionKeys:
    def __init__(self, path: Path, port: int) -> None:
        self.path, self.port = path, port
        self.keys: dict[str, dict[str, PKey]] = {}

    def lookup(self, name: str) -> dict[str, PKey] | None:
        if name not in self.keys:
            host = name[1:name.rindex("]:")] if name.startswith("[") and "]:" in name else name
            resolved = _known_keys(self.path, host, self.port)
            # ncclient merges port-specific keys into the bare-host mapping during negotiation.
            self.keys.update({name: dict(keys) for name, keys in resolved.items()})
        return self.keys.get(name) or None

    def check(self, name: str, key: PKey) -> bool:
        known = (self.lookup(name) or {}).get(key.get_name())
        _reject_revoked(self.path, key)
        return known is not None and known.asbytes() == key.asbytes()


class _SocketForNcclient:
    def __init__(self, module):
        self.module = module

    def __getattr__(self, name):
        return getattr(self.module, name)

    def socket(self, *args, **kwargs):
        try:
            return self.module.socket(*args, **kwargs)
        except OSError as error:
            if _HOST_KEY_PORT.get() is not None and error.errno in (errno.EMFILE, errno.ENFILE):
                # ncclient catches OSError and replaces it with an unreachable-host error.
                raise Fault(FaultKind.LOCAL, str(error), False) from error
            raise


def _reject_revoked(path: Path, key: PKey) -> None:
    if key.asbytes() in _REVOKED.get(path, ()):
        raise Fault(FaultKind.HOST_KEY, f"server key is marked @revoked in {path}", False)


def _forget_host_keys(path: Path) -> None:
    _HOST_KEYS.pop(path, None)
    _REVOKED.pop(path, None)
    for cached in list(_RESOLVED):
        if cached[0] == path:
            del _RESOLVED[cached]


def _install_host_key_loader() -> None:
    global _HOST_KEY_LOADER_INSTALLED
    with _HOST_KEYS_LOCK:
        if _HOST_KEY_LOADER_INSTALLED:
            return
        from ncclient.transport.ssh import SSHSession
        from ncclient.transport import ssh

        # PyEZ creates the SSHSession internally; the context marker scopes this hook.
        original = SSHSession.load_known_hosts

        def load_known_hosts(session, filename=None):
            port = _HOST_KEY_PORT.get()
            if port is None:
                return original(session, filename)
            path = Path(filename).expanduser() if filename else Path.home() / ".ssh" / "known_hosts"
            session._host_keys = _SessionKeys(path, port)

        SSHSession.load_known_hosts = load_known_hosts
        ssh.socket = _SocketForNcclient(ssh.socket)
        _HOST_KEY_LOADER_INSTALLED = True


def _accept_new(host: str, port: int, timeouts: Timeouts) -> None:
    """Pin an unknown key before PyEZ authenticates, then let PyEZ verify it."""
    import paramiko
    from ncclient.transport import ssh

    timeout = timeouts.connect
    path = Path.home() / ".ssh" / "known_hosts"
    name = host if port == 22 else f"[{host}]:{port}"
    if any(_known_keys(path, host, port).values()):
        return
    with _opening(host, port, timeouts), socket.create_connection((host, port), timeout=timeout) as sock:
        with ssh.paramiko.Transport(sock) as transport:
            transport.start_client()
            key = transport.get_remote_server_key()
    with _HOST_KEYS_LOCK:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as known_hosts:
            deadline = monotonic() + timeout
            while True:
                try:
                    fcntl.flock(known_hosts, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if monotonic() >= deadline:
                        raise Fault(FaultKind.LOCAL, f"{path}: known_hosts lock timed out after {timeout}s", False)
                    sleep(min(0.05, max(0, deadline - monotonic())))
            # Another process may have pinned or revoked this key while we connected.
            _forget_host_keys(path)
            resolved = _known_keys(path, host, port)
            _reject_revoked(path, key)
            current = resolved[host] or resolved[f"[{host}]:{port}"]
            if current:
                expected = current.get(key.get_name())
                if expected != key:
                    raise paramiko.BadHostKeyException(host, key, expected or next(iter(current.values())))
            else:
                size = os.fstat(fd).st_size
                if size and os.pread(fd, 1, size - 1) != b"\n":
                    known_hosts.write("\n")
                known_hosts.write(f"{name} {key.get_name()} {key.get_base64()}\n")
                known_hosts.flush()
                _forget_host_keys(path)
                _known_keys(path, host, port)


def _fault(error: Exception, reached_device: bool, *, opening: bool = False, setup: _Opening | None = None) -> Fault:
    if isinstance(error, Fault):
        return error
    if setup is not None and (setup.expired or monotonic() >= setup.deadline):
        return setup.timeout_fault()
    if isinstance(error, ImportError):
        return Fault(FaultKind.LOCAL, str(error), reached_device)
    from jnpr.junos import exception as pyez
    from ncclient.operations.errors import TimeoutExpiredError
    from ncclient.operations.rpc import RPCError
    from ncclient.transport import errors as transport
    from paramiko import AuthenticationException, BadHostKeyException, SSHException

    errors = []
    if setup is not None and not setup.connected and setup.connect_error is not None:
        error = setup.connect_error
    cause = error
    while isinstance(cause, BaseException) and cause not in errors:
        if isinstance(cause, Fault):
            return cause
        errors.append(cause)
        cause = getattr(cause, "_orig", None) or cause.__cause__ or cause.__context__
    detail = str(errors[-1])
    for cause in errors:
        if isinstance(cause, OSError) and cause.errno in (errno.EMFILE, errno.ENFILE):
            return Fault(FaultKind.LOCAL, str(cause), reached_device)
        if opening and isinstance(cause, OSError) and cause.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH):
            return Fault(FaultKind.UNREACHABLE, str(cause), False)
    mappings = (
        ((transport.SSHUnknownHostError, BadHostKeyException), FaultKind.HOST_KEY),
        ((pyez.ConnectAuthError, transport.AuthenticationError, AuthenticationException), FaultKind.AUTH),
        ((ValueError, TypeError, FileNotFoundError, PermissionError), FaultKind.LOCAL),
        ((pyez.ConnectTimeoutError, pyez.RpcTimeoutError, TimeoutExpiredError, TimeoutError), FaultKind.TIMEOUT),
        ((pyez.ConnectClosedError,), FaultKind.SESSION_LOST),
        ((pyez.RpcError, RPCError), FaultKind.REFUSED),
        ((socket.gaierror, ConnectionRefusedError), FaultKind.UNREACHABLE if opening else FaultKind.SESSION_LOST),
        ((transport.TransportError, SSHException, EOFError, ConnectionError), FaultKind.SESSION_LOST),
        ((pyez.ConnectRefusedError, pyez.ConnectUnknownHostError),
         FaultKind.UNREACHABLE if opening else FaultKind.SESSION_LOST),
        ((pyez.ConnectError,), FaultKind.SESSION_LOST),
        ((OSError,), FaultKind.UNREACHABLE if opening else FaultKind.LOCAL),
    )
    for types, kind in mappings:
        if any(isinstance(exc, types) for exc in errors):
            if opening and kind == FaultKind.TIMEOUT and setup is not None:
                return setup.timeout_fault()
            if opening and kind in (FaultKind.SESSION_LOST, FaultKind.UNREACHABLE):
                reached_device = kind == FaultKind.SESSION_LOST
            return Fault(kind, detail, reached_device)
    return Fault(FaultKind.LOCAL, detail, reached_device)


@dataclass
class NetconfSession(Session):
    device: Device
    timeouts: Timeouts
    config: Config | None = None
    locked: bool = False
    dirty: bool = False


class NetconfCommunicator(Communicator):
    default_port: int = 830
    banner: bytes | None = b"SSH-"
    capabilities: frozenset[str] = frozenset({"show", "batch"})

    def __init__(self, dialect: Dialect) -> None:
        self.dialect = dialect

    def open(
        self,
        target: Target,
        creds: Credentials,
        timeouts: Timeouts,
        host_key_policy: HostKeyPolicy,
    ) -> NetconfSession:
        port = target.port if target.port is not None else self.default_port
        if port in (23, "23"):
            raise Fault(FaultKind.LOCAL, "port 23 is telnet, not NETCONF", False)
        device = None
        try:
            from jnpr.junos import Device

            _install_setup_hooks()
            if host_key_policy == "accept-new":
                _accept_new(target.host, port, timeouts)
            device = Device(
                host=target.host, port=port, user=creds.username, passwd=creds.password,
                ssh_private_key_file=str(Path(creds.key_file).expanduser()) if creds.key_file else None,
                allow_agent=creds.password is None and creds.key_file is None,
                look_for_keys=creds.password is None and creds.key_file is None,
                conn_open_timeout=timeouts.connect, gather_facts=False, huge_tree=True,
                hostkey_verify=host_key_policy != "off",
            )
            _install_host_key_loader()
            token = _HOST_KEY_PORT.set(int(device.port))
            try:
                with _opening(target.host, port, timeouts):
                    device.open()
            finally:
                _HOST_KEY_PORT.reset(token)
            device.timeout = timeouts.command
            return NetconfSession(device=device, timeouts=timeouts)
        except Exception as error:
            if device is not None:
                try:
                    device.close()
                except Exception:
                    pass
            raise _fault(error, False, opening=True) from error

    def close(self, session: Session) -> None:
        """Discard uncommitted changes and unlock before closing the PyEZ device."""
        netconf = cast(NetconfSession, session)

        def close_device() -> None:
            try:
                netconf.device.timeout = 5
                netconf.device.close()
            except Exception:
                try:
                    netconf.device._conn._session.close()
                except Exception:
                    pass
                raise

        actions = []
        if netconf.config is not None:
            actions.extend((netconf.config.rollback, netconf.config.unlock))
        actions.append(close_device)
        failure = None
        for action in actions:
            reached_device = bool(netconf.device.connected)
            try:
                action()
            except Exception as error:
                if failure is None:
                    failure = _fault(error, reached_device)
        if failure is not None:
            raise failure
        netconf.config = None
        netconf.locked = netconf.dirty = False

    def show(self, session: Session, command: str) -> Result:
        from lxml import etree

        device = cast(NetconfSession, session).device
        reached_device = bool(device.connected)
        try:
            if command.rstrip().endswith("| no-more"):
                command = command.rstrip()[:-len("| no-more")].rstrip()
            reply = device.rpc.cli(command, format="text")
            if reply is True:
                return Result(output="")
            # Childless rpc-reply text is a diagnostic, not normal CLI output.
            diagnostic = reply.tag == "rpc-reply" and len(reply) == 0
            if reply.tag == "configuration-information":
                output = reply.findtext("configuration-output") or ""
            else:
                if reply.tag == "output" and reply.getparent() is not None:
                    reply = reply.getparent()
                output = etree.tostring(reply, method="text", with_tail=False, encoding="unicode")
            output = output.strip("\r\n")
            if any(pattern.search(output) if diagnostic else pattern.match(output)
                   for pattern in self.dialect.refusal_patterns):
                raise Fault(FaultKind.REFUSED, output, reached_device)
            return Result(output=output)
        except Exception as error:
            raise _fault(error, reached_device) from error

    def structured(self, session: Session, rpc: str, fmt: str) -> Result:
        raise NotImplementedError

    def load(self, session: Session, lines: list[str]) -> Result:
        raise NotImplementedError

    def diff(self, session: Session) -> Result:
        raise NotImplementedError

    def commit(
        self,
        session: Session,
        confirmed_minutes: int | None,
        comment: str | None,
    ) -> Result:
        raise NotImplementedError

    def confirm(self, session: Session) -> Result:
        raise NotImplementedError

    def commit_history(self, session: Session) -> Result:
        raise NotImplementedError
