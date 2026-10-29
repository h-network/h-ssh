"""Operations on one session, and the edit state machine (section 5.3)."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Callable

from hssh.communicators.base import Communicator, Session
from hssh.dialects.base import Dialect
from hssh.model import EditSettings, Fault, OperationResult, Result, Target


class Stage(Enum):
    OPEN = auto()
    LOAD = auto()
    DIFF = auto()
    COMMIT = auto()
    PENDING = auto()
    CLOSE = auto()


@dataclass(frozen=True)
class EditOutcome:
    """What an edit came to: its operations, the stage reached, the lines the device took, and whether a commit is pending."""

    operations: tuple[OperationResult, ...]
    stage: Stage
    applied: int = 0
    pending: bool = False


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


async def operation(command: str, call: Callable[[], Result]) -> OperationResult:
    """`call` on the thread pool, timed; a Fault it raises is the operation's outcome."""
    started, t0 = now(), time.monotonic()
    try:
        outcome: Result | Fault = await asyncio.to_thread(call)
    except Fault as f:
        outcome = f
    return OperationResult(command, outcome, started, int((time.monotonic() - t0) * 1000))


def failed(op: OperationResult) -> bool:
    return isinstance(op.outcome, Fault)


def confirm_command(target: Target) -> str:
    """The command that confirms the target's pending commit, for the report."""
    ...


class EditLifecycle:
    """OPEN → LOAD → DIFF → (dry run) CLOSE, or (apply) COMMIT → PENDING → CLOSE. Faults after LOAD end at CLOSE, which discards."""

    def __init__(self, communicator: Communicator, dialect: Dialect, session: Session) -> None:
        self.communicator = communicator
        self.dialect = dialect
        self.session = session

    async def load(self, lines: list[str]) -> tuple[list[OperationResult], int]:
        """The candidate loaded in one call; without a candidate model, line by line, so the lines applied are known."""
        if self.dialect.has_candidate:
            op = await operation("load", lambda: self.communicator.load(self.session, lines))
            return [op], 0 if failed(op) else len(lines)
        ops: list[OperationResult] = []
        for line in lines:
            ops.append(await operation(line, lambda: self.communicator.load(self.session, [line])))
            if failed(ops[-1]):
                break
        return ops, len(ops) - (1 if ops and failed(ops[-1]) else 0)

    async def diff(self) -> OperationResult:
        return await operation("diff", lambda: self.communicator.diff(self.session))

    async def commit(self, edit: EditSettings) -> OperationResult:
        return await operation("commit", lambda: self.communicator.commit(self.session, edit.confirmed_minutes, edit.comment))

    async def run(self, lines: list[str], edit: EditSettings) -> EditOutcome:
        """The state machine from LOAD; the caller has opened the session and closes it after."""
        ops, applied = await self.load(lines)
        if failed(ops[-1]):
            return EditOutcome(tuple(ops), Stage.LOAD, applied)
        ops.append(await self.diff())
        if failed(ops[-1]) or not edit.apply:
            return EditOutcome(tuple(ops), Stage.DIFF, applied)
        ops.append(await self.commit(edit))
        pending = not failed(ops[-1]) and bool(edit.confirmed_minutes)
        return EditOutcome(tuple(ops), Stage.PENDING if pending else Stage.COMMIT, applied, pending)


async def confirm(communicator: Communicator, session: Session) -> OperationResult:
    return await operation("confirm", lambda: communicator.confirm(session))


async def commit_history(communicator: Communicator, session: Session) -> OperationResult:
    return await operation("commit_history", lambda: communicator.commit_history(session))
