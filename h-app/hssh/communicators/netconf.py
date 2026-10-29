"""NETCONF skeleton; connection, RPC and edit lifecycle operations are stubs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from hssh.communicators.base import Communicator, Session
from hssh.dialects.base import Dialect
from hssh.model import Credentials, HostKeyPolicy, Result, Target, Timeouts

if TYPE_CHECKING:
    from jnpr.junos import Device
    from jnpr.junos.utils.config import Config


DEFAULT_PORT = 830


@dataclass
class NetconfSession(Session):
    device: Device
    timeouts: Timeouts
    config: Config | None = None
    locked: bool = False
    dirty: bool = False


class NetconfCommunicator(Communicator):
    capabilities: frozenset[str] = frozenset({
        "show", "batch", "structured", "edit", "confirm", "commit_status",
        "commit_confirmed",
    })

    def __init__(self, dialect: Dialect) -> None:
        self.dialect = dialect

    def open(
        self,
        target: Target,
        creds: Credentials,
        timeouts: Timeouts,
        host_key_policy: HostKeyPolicy,
    ) -> NetconfSession:
        raise NotImplementedError

    def close(self, session: Session) -> None:
        """Discard uncommitted changes and unlock before closing the PyEZ device."""
        raise NotImplementedError

    def show(self, session: Session, command: str) -> Result:
        device = cast(NetconfSession, session).device
        if command.rstrip().endswith("| no-more"):
            command = command.rstrip()[:-len("| no-more")].rstrip()
        return Result(output=device.cli(command, warning=False) or "")

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
