"""NETCONF show and batch sessions through PyEZ; edit and structured RPCs are stubs."""

from __future__ import annotations

from base64 import b64decode
from contextvars import ContextVar
from dataclasses import dataclass
import fcntl
import hmac
import os
from pathlib import Path
import socket
from threading import RLock
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
_RESOLVED: dict[tuple[Path, str, int], dict[str, dict[str, PKey]]] = {}
_HOST_KEY_PORT: ContextVar[int | None] = ContextVar("netconf_host_key_port", default=None)
_HOST_KEY_LOADER_INSTALLED = False


def _known_keys(path: Path, host: str, port: int) -> dict[str, dict[str, PKey]]:
    from paramiko import SSHException
    from paramiko.hostkeys import HostKeyEntry

    with _HOST_KEYS_LOCK:
        if path not in _HOST_KEYS:
            entries = []
            lines = path.read_text().split("\n") if path.exists() else ()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    entry = HostKeyEntry.from_line(line)
                except SSHException:
                    continue
                if entry is None:
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
        return known is not None and known.asbytes() == key.asbytes()


def _install_host_key_loader() -> None:
    global _HOST_KEY_LOADER_INSTALLED
    with _HOST_KEYS_LOCK:
        if _HOST_KEY_LOADER_INSTALLED:
            return
        from ncclient.transport.ssh import SSHSession

        # PyEZ creates the SSHSession internally; the context marker scopes this hook.
        original = SSHSession.load_known_hosts

        def load_known_hosts(session, filename=None):
            port = _HOST_KEY_PORT.get()
            if port is None:
                return original(session, filename)
            path = Path(filename).expanduser() if filename else Path.home() / ".ssh" / "known_hosts"
            session._host_keys = _SessionKeys(path, port)

        SSHSession.load_known_hosts = load_known_hosts
        _HOST_KEY_LOADER_INSTALLED = True


def _accept_new(host: str, port: int, timeout: int) -> None:
    """Pin an unknown key before PyEZ authenticates, then let PyEZ verify it."""
    import paramiko

    path = Path.home() / ".ssh" / "known_hosts"
    name = host if port == 22 else f"[{host}]:{port}"
    if any(_known_keys(path, host, port).values()):
        return
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with paramiko.Transport(sock) as transport:
            transport.start_client(timeout=timeout)
            key = transport.get_remote_server_key()
    with _HOST_KEYS_LOCK:
        resolved = _known_keys(path, host, port)
        current = resolved[host] or resolved[f"[{host}]:{port}"]
        if current:
            expected = current.get(key.get_name())
            if expected != key:
                raise paramiko.BadHostKeyException(host, key, expected or next(iter(current.values())))
        else:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a") as known_hosts:
                fcntl.flock(known_hosts, fcntl.LOCK_EX)
                known_hosts.write(f"{name} {key.get_name()} {key.get_base64()}\n")
                known_hosts.flush()
                del _HOST_KEYS[path]
                for cached in list(_RESOLVED):
                    if cached[0] == path:
                        del _RESOLVED[cached]
                _known_keys(path, host, port)


def _fault(error: Exception, reached_device: bool, *, opening: bool = False) -> Fault:
    if isinstance(error, Fault):
        return error
    if isinstance(error, ImportError):
        return Fault(FaultKind.LOCAL, str(error), reached_device)
    from jnpr.junos import exception as pyez
    from ncclient.operations.errors import TimeoutExpiredError
    from ncclient.operations.rpc import RPCError
    from ncclient.transport import errors as transport
    from paramiko import AuthenticationException, BadHostKeyException, SSHException

    errors = []
    cause = error
    while isinstance(cause, BaseException) and cause not in errors:
        errors.append(cause)
        cause = getattr(cause, "_orig", None) or cause.__cause__ or cause.__context__
    detail = str(errors[-1])
    mappings = (
        ((transport.SSHUnknownHostError, BadHostKeyException), FaultKind.HOST_KEY),
        ((pyez.ConnectAuthError, transport.AuthenticationError, AuthenticationException), FaultKind.AUTH),
        ((ValueError, TypeError, FileNotFoundError, PermissionError), FaultKind.LOCAL),
        ((pyez.RpcTimeoutError, TimeoutExpiredError, TimeoutError),
         FaultKind.UNREACHABLE if opening else FaultKind.TIMEOUT),
        ((pyez.ConnectClosedError,), FaultKind.SESSION_LOST),
        ((pyez.RpcError, RPCError), FaultKind.REFUSED),
        ((pyez.ConnectError, transport.TransportError, SSHException, EOFError, ConnectionError),
         FaultKind.UNREACHABLE if opening else FaultKind.SESSION_LOST),
        ((OSError,), FaultKind.UNREACHABLE if opening else FaultKind.LOCAL),
    )
    for types, kind in mappings:
        if any(isinstance(exc, types) for exc in errors):
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

            if host_key_policy == "accept-new":
                _accept_new(target.host, port, timeouts.connect)
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
        actions = []
        if netconf.config is not None:
            actions.extend((netconf.config.rollback, netconf.config.unlock))
        actions.append(netconf.device.close)
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
        device = cast(NetconfSession, session).device
        reached_device = bool(device.connected)
        try:
            if command.rstrip().endswith("| no-more"):
                command = command.rstrip()[:-len("| no-more")].rstrip()
            output = (device.cli(command, warning=False) or "").strip("\r\n")
            if any(pattern.match(output) for pattern in self.dialect.refusal_patterns):
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
