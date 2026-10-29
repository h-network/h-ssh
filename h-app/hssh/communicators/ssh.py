"""Paramiko transport skeleton; connection setup is not implemented."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from hssh.communicators.base import Communicator, Session
from hssh.dialects.base import Dialect
from hssh.model import Credentials, HostKeyPolicy, Result, Target, Timeouts

if TYPE_CHECKING:
    from paramiko import Channel, SSHClient

    from hssh.communicators.cli_engine import CliEngine


class ShellChannel:
    def __init__(self, channel: Channel) -> None:
        self.channel = channel

    def recv(self, n: int, timeout: float) -> bytes:
        self.channel.settimeout(timeout)
        return self.channel.recv(n)

    def send(self, data: bytes) -> None:
        self.channel.sendall(data)

    def close(self) -> None:
        self.channel.close()


@dataclass
class SSHSession:
    client: SSHClient
    engine: CliEngine


class SSHCommunicator(Communicator):
    # Advertise operations once connection setup is implemented.
    capabilities: frozenset[str] = frozenset()

    def __init__(self, dialect: Dialect) -> None:
        self.dialect = dialect

    def open(
        self,
        target: Target,
        creds: Credentials,
        timeouts: Timeouts,
        host_key_policy: HostKeyPolicy,
    ) -> SSHSession:
        raise NotImplementedError

    def close(self, session: Session) -> None:
        ssh_session = cast(SSHSession, session)
        try:
            ssh_session.engine.close()
        finally:
            ssh_session.client.close()

    def show(self, session: Session, command: str) -> Result:
        return cast(SSHSession, session).engine.show(command)

    def structured(self, session: Session, rpc: str, fmt: str) -> Result:
        raise NotImplementedError("Structured RPCs require NETCONF")

    def load(self, session: Session, lines: list[str]) -> Result:
        return cast(SSHSession, session).engine.load(lines)

    def diff(self, session: Session) -> Result:
        return cast(SSHSession, session).engine.diff()

    def commit(
        self,
        session: Session,
        confirmed_minutes: int | None,
        comment: str | None,
    ) -> Result:
        return cast(SSHSession, session).engine.commit(confirmed_minutes, comment)

    def confirm(self, session: Session) -> Result:
        return cast(SSHSession, session).engine.confirm()

    def commit_history(self, session: Session) -> Result:
        return cast(SSHSession, session).engine.commit_history()
