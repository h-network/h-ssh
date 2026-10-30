"""Telnet skeleton; connection, negotiation and CLI operations are not wired yet."""

from __future__ import annotations

import socket
import time

from hssh.communicators.base import Session
from hssh.dialects.base import Dialect
from hssh.model import Credentials, HostKeyPolicy, Result, Target, Timeouts


def negotiate(sock: socket.socket) -> str:
    raise NotImplementedError


class TelnetChannel:
    def __init__(self, sock: socket.socket, initial: str = "") -> None:
        self.sock = sock
        self.initial = initial

    @classmethod
    def connect(cls, host: str, port: int, timeout: int) -> TelnetChannel:
        raise NotImplementedError

    def recv(self, n: int, timeout: float) -> bytes:
        self.sock.settimeout(timeout)
        data = self.sock.recv(n)
        if not data:
            raise ConnectionError("Telnet connection closed by peer")
        return data

    def send(self, data: bytes, deadline: float) -> None:
        while data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("write not finished by its deadline")
            self.sock.settimeout(remaining)
            data = data[self.sock.send(data):]

    def close(self) -> None:
        self.sock.close()


class TelnetCommunicator:
    default_port: int = 23
    banner: bytes | None = None
    capabilities: frozenset[str] = frozenset()

    def __init__(self, dialect: Dialect) -> None:
        self.dialect = dialect

    def open(
        self, target: Target, creds: Credentials, timeouts: Timeouts,
        host_key_policy: HostKeyPolicy,
    ) -> Session:
        raise NotImplementedError

    def close(self, session: Session) -> None:
        raise NotImplementedError

    def reuse(self, session: Session, timeouts: Timeouts, idle_seconds: int) -> bool:
        return False

    def release(self, session: Session) -> None:
        self.close(session)

    def discard(self, session: Session) -> None:
        try:
            self.close(session)
        except Exception:  # noqa: BLE001 - a session in doubt is torn down, never reported
            pass

    def show(self, session: Session, command: str) -> Result:
        raise NotImplementedError

    def structured(self, session: Session, rpc: str, fmt: str) -> Result:
        raise NotImplementedError

    def load(self, session: Session, lines: list[str]) -> Result:
        raise NotImplementedError

    def diff(self, session: Session) -> Result:
        raise NotImplementedError

    def commit(
        self, session: Session, confirmed_minutes: int | None, comment: str | None,
    ) -> Result:
        raise NotImplementedError

    def confirm(self, session: Session) -> Result:
        raise NotImplementedError

    def commit_history(self, session: Session) -> Result:
        raise NotImplementedError
