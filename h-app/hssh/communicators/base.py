"""The communicator interface every transport implements (section 4.1)."""

from __future__ import annotations

from typing import Literal, Protocol

from hssh.dialects.base import Dialect
from hssh.model import Credentials, HostKeyPolicy, Result, Target, Timeouts


class Session(Protocol):
    """An open connection to one device, owned by the communicator that opened it."""


class Communicator(Protocol):
    """One transport: opens sessions, executes one operation per call, returns Result or raises Fault; capability names are the mode names plus commit_confirmed and synchronize."""

    capabilities: frozenset[str]
    dialect: Dialect
    default_port: int
    banner: bytes | None
    ssh_config: Literal["paramiko", "openssh"] | None

    def open(self, target: Target, creds: Credentials, timeouts: Timeouts, host_key_policy: HostKeyPolicy) -> Session: ...

    def close(self, session: Session) -> None:
        """Discard any uncommitted changes, each communicator in its own way, then close the session."""
        ...

    def reuse(self, session: Session, timeouts: Timeouts, idle_seconds: int) -> bool:
        """Before a borrow of a kept session: apply these timeouts and say whether it is worth reusing; the cheap check every time, the device asked only past idle_seconds."""
        ...

    def release(self, session: Session) -> None:
        """The end of a borrow: leave the session clean for the next one (discard the candidate, unlock), raising Fault when that fails."""
        ...

    def discard(self, session: Session) -> None:
        """The session is in doubt: tear the transport down with no rollback or unlock, interrupt a call still running on it, never raise."""
        ...

    def show(self, session: Session, command: str) -> Result: ...

    def structured(self, session: Session, rpc: str, fmt: str) -> Result: ...

    def load(self, session: Session, lines: list[str]) -> Result: ...

    def diff(self, session: Session) -> Result:
        """Result.data is a bool: whether anything changed."""
        ...

    def commit(self, session: Session, confirmed_minutes: int | None, comment: str | None,
               synchronize: bool = False) -> Result:
        """synchronize asks for commit synchronize; only a communicator with the synchronize capability accepts it, the others raise Fault(UNSUPPORTED)."""
        ...

    def confirm(self, session: Session, synchronize: bool = False) -> Result: ...

    def commit_history(self, session: Session) -> Result:
        """Result.data is a CommitStatus."""
        ...
