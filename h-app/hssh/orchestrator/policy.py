"""Policy: maps each Fault to an action and applies the safety gate (sections 3.2 and 4.4)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum, auto
from typing import Protocol

from hssh.dialects.base import Dialect
from hssh.model import Fault, FaultKind, PolicySettings, Target

DEFAULT_POLICY = PolicySettings(retries=2, retry_pause=1)

# The communicator's operation that opens the session: a fault from it is "before login".
OPEN = "open"


class Action(Enum):
    RETRY = auto()
    FAIL = auto()
    SKIP = auto()


@dataclass(frozen=True)
class Verdict:
    """What the policy decided for one fault: the action, whether the device is cooled down, and a note for the report."""

    action: Action
    cool_down: bool = False
    note: str | None = None


class SafetyGate(Protocol):
    """The per-device gate (hssh.safety): asked before OPEN for edits, released or cooled after."""

    def check(self, target: Target, login: bool) -> str | None:
        """None when the target may be contacted, else why it is held."""
        ...

    def release(self, target: Target) -> None: ...

    def cool_down(self, target: Target) -> None: ...

    def close(self) -> None: ...


def is_read(dialect: Dialect, command: str) -> bool:
    """The dialect's read rule, except that a command with a line break never is one: a retry would run every line again."""
    return "\n" not in command and "\r" not in command and dialect.is_read(command)


def decide(fault: Fault, *, read: bool, editing: bool, operation: str, attempt: int,
           settings: PolicySettings = DEFAULT_POLICY) -> Verdict:
    """The default policy table (section 4.4) for one fault on attempt `attempt` (1-based) of operation `operation`."""
    kind = fault.kind
    retries_left = attempt <= settings.retries
    if kind in (FaultKind.UNREACHABLE, FaultKind.TIMEOUT) and operation == OPEN:
        return Verdict(Action.RETRY if retries_left else Action.FAIL)
    if kind in (FaultKind.AUTH, FaultKind.HOST_KEY, FaultKind.UNSUPPORTED, FaultKind.LOCAL):
        return Verdict(Action.FAIL)
    if kind is FaultKind.OUTCOME_UNKNOWN:
        return Verdict(Action.FAIL, cool_down=True, note="commit outcome unknown: check the device")
    if kind in (FaultKind.TIMEOUT, FaultKind.SESSION_LOST):
        if read and retries_left:
            return Verdict(Action.RETRY)
        return Verdict(Action.FAIL, cool_down=editing and fault.reached_device)
    return Verdict(Action.FAIL, cool_down=editing)


class Policy:
    """Retry, cooldown and safety-gate decisions for one run."""

    def __init__(self, settings: PolicySettings | None, gate: SafetyGate | None) -> None:
        self.settings = settings or DEFAULT_POLICY
        self.gate = gate

    def admit(self, target: Target, login: bool) -> str | None:
        """Why the safety gate holds `target`, or None when it may be contacted."""
        return self.gate.check(target, login) if self.gate else None

    def settle(self, target: Target, verdict: Verdict | None) -> None:
        """Release the target in the gate, or cool it down as the verdict says."""
        if self.gate is None:
            return
        if verdict is not None and verdict.cool_down:
            self.gate.cool_down(target)
        else:
            self.gate.release(target)

    async def pause(self) -> None:
        await asyncio.sleep(self.settings.retry_pause)
