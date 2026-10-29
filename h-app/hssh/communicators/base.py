"""The communicator interface every transport implements (section 4.1)."""

from __future__ import annotations

from typing import Protocol

from hssh.model import Credentials, Result, Target, Timeouts


class Session(Protocol):
    """An open connection to one device, owned by the communicator that opened it."""


class Communicator(Protocol):
    """One transport: opens sessions, executes one operation per call, returns Result or raises Fault; capability names are the mode names plus commit_confirmed."""

    capabilities: frozenset[str]

    def open(self, target: Target, creds: Credentials, timeouts: Timeouts) -> Session: ...

    def close(self, session: Session) -> None: ...

    def show(self, session: Session, command: str) -> Result: ...

    def structured(self, session: Session, rpc: str, fmt: str) -> Result: ...

    def load(self, session: Session, lines: list[str]) -> Result: ...

    def diff(self, session: Session) -> Result: ...

    def commit(self, session: Session, confirmed_minutes: int | None, comment: str | None) -> Result: ...

    def confirm(self, session: Session) -> Result: ...

    def rollback(self, session: Session, index: int = 0) -> Result: ...

    def commit_history(self, session: Session) -> Result: ...
