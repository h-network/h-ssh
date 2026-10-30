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
from hssh.model import CommitStatus, EditSettings, Fault, FaultKind, OperationResult, Result, Timeouts
from hssh.orchestrator.defaults import GRACE_SECONDS


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


async def operation(command: str, call: Callable[[], Result], timeout: float | None = None) -> OperationResult:
    """`call` on a worker thread, timed; a Fault it raises is the operation's outcome. One that has not returned within `timeout` plus GRACE_SECONDS is a TIMEOUT fault, and its thread is left to finish."""
    started, t0 = now(), time.monotonic()
    budget = None if timeout is None else timeout + GRACE_SECONDS
    try:
        outcome: Result | Fault = await asyncio.wait_for(asyncio.to_thread(call), budget)
    except Fault as f:
        outcome = f
    except asyncio.TimeoutError:
        outcome = Fault(FaultKind.TIMEOUT, f"no result within {budget:g}s: the communicator call has not returned", True)
    return OperationResult(command, outcome, started, int((time.monotonic() - t0) * 1000))


def failed(op: OperationResult) -> bool:
    return isinstance(op.outcome, Fault)


class EditLifecycle:
    """OPEN → LOAD → DIFF → (dry run) CLOSE, or (apply) COMMIT → PENDING → CLOSE. Faults after LOAD end at CLOSE, which discards. Budgets allow two device calls per step (lock then load; diff then commit-check) and lock, history read and commit for a confirm."""

    def __init__(self, communicator: Communicator, dialect: Dialect, session: Session, timeouts: Timeouts) -> None:
        self.communicator = communicator
        self.dialect = dialect
        self.session = session
        self.timeouts = timeouts

    async def load(self, lines: list[str]) -> tuple[list[OperationResult], int]:
        """The candidate loaded in one call; without a candidate model, line by line, so the lines applied are known."""
        if self.dialect.has_candidate:
            op = await operation("load", lambda: self.communicator.load(self.session, lines), 2 * self.timeouts.command)
            return [op], 0 if failed(op) else len(lines)
        ops: list[OperationResult] = []
        for line in lines:
            ops.append(await operation(line, lambda: self.communicator.load(self.session, [line]), self.timeouts.command))
            if failed(ops[-1]):
                break
        return ops, len(ops) - (1 if ops and failed(ops[-1]) else 0)

    async def diff(self) -> OperationResult:
        return await operation("diff", lambda: self.communicator.diff(self.session), 2 * self.timeouts.command)

    async def commit(self, edit: EditSettings) -> OperationResult:
        return await operation("commit", lambda: self.communicator.commit(self.session, edit.confirmed_minutes, edit.comment),
                               self.timeouts.commit)

    async def run(self, lines: list[str], edit: EditSettings, before_commit: Callable[[], None] = lambda: None) -> EditOutcome:
        """The state machine from LOAD; the caller has opened the session and closes it after. A diff whose data is False ends it: nothing to commit. `before_commit` runs once the commit is about to be sent, so an interrupt waits for it."""
        ops, applied = await self.load(lines)
        if failed(ops[-1]):
            return EditOutcome(tuple(ops), Stage.LOAD, applied)
        ops.append(await self.diff())
        if failed(ops[-1]) or not edit.apply or ops[-1].outcome.data is False:
            return EditOutcome(tuple(ops), Stage.DIFF, applied)
        before_commit()
        ops.append(await self.commit(edit))
        pending = not failed(ops[-1]) and bool(edit.confirmed_minutes)
        return EditOutcome(tuple(ops), Stage.PENDING if pending else Stage.COMMIT, applied, pending)


async def confirm(communicator: Communicator, session: Session, timeouts: Timeouts) -> list[OperationResult]:
    """The commit history read first; the confirm is sent only when its CommitStatus says a commit is pending, else refused: a bare confirm would commit whatever waits in the candidate."""
    history = await commit_history(communicator, session, timeouts)
    if failed(history):
        return [history]
    status = history.outcome.data
    if not isinstance(status, CommitStatus) or not status.pending:
        refused = Fault(FaultKind.REFUSED, "nothing to confirm: no commit-confirmed is pending", True)
        return [history, OperationResult("confirm", refused, now(), 0)]
    return [history, await operation("confirm", lambda: communicator.confirm(session),
                                     2 * timeouts.command + timeouts.commit)]


async def commit_history(communicator: Communicator, session: Session, timeouts: Timeouts) -> OperationResult:
    return await operation("commit_history", lambda: communicator.commit_history(session), timeouts.command)
