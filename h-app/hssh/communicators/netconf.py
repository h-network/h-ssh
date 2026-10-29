"""NETCONF show and batch sessions through PyEZ; edit and structured RPCs are stubs."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import socket
from threading import Lock
from typing import TYPE_CHECKING, cast

from hssh.communicators.base import Communicator, Session
from hssh.dialects.base import Dialect
from hssh.model import Credentials, Fault, FaultKind, HostKeyPolicy, Result, Target, Timeouts

if TYPE_CHECKING:
    from jnpr.junos import Device
    from jnpr.junos.utils.config import Config
    from paramiko import HostKeys


DEFAULT_PORT = 830
_HOST_KEYS_LOCK = Lock()
_HOST_KEYS: HostKeys | None = None


def _accept_new(host: str, port: int, timeout: int) -> None:
    """Pin an unknown key before PyEZ authenticates, then let PyEZ verify it."""
    import paramiko

    global _HOST_KEYS
    path = Path.home() / ".ssh" / "known_hosts"
    name = host if port == 22 else f"[{host}]:{port}"
    with _HOST_KEYS_LOCK:
        if _HOST_KEYS is None:
            keys = paramiko.HostKeys()
            if path.exists():
                keys.load(str(path))
            _HOST_KEYS = keys
        keys = _HOST_KEYS
        if keys.lookup(host) or keys.lookup(name):
            return
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with paramiko.Transport(sock) as transport:
            transport.start_client(timeout=timeout)
            key = transport.get_remote_server_key()
    with _HOST_KEYS_LOCK:
        keys = _HOST_KEYS
        current = keys.lookup(host) or keys.lookup(name)
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
                _HOST_KEYS = paramiko.HostKeys(str(path))


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
        port = target.port if target.port is not None else DEFAULT_PORT
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
            device.open()
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
            return Result(output=(device.cli(command, warning=False) or "").strip("\r\n"))
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
