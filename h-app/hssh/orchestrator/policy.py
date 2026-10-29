"""Policy: maps each Fault to an action and applies the safety gate (sections 3.2 and 4.4)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum, auto
from typing import Protocol, Sequence

from hssh.dialects.base import Dialect
from hssh.model import Fault, FaultKind, PolicySettings, Target
from hssh.orchestrator.defaults import DEFAULT_POLICY

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
    """What the policy calls on hssh.safety.SafetyGate."""

    def check_device(self, target: Target, *, login: bool = True) -> tuple[bool, str]:
        """(admitted, reason); admission reserves the device until release_device or set_cooldown."""
        ...

    def holds(self, targets: Sequence[Target]) -> dict[str, str]:
        """Target names held by a cooldown, and why, without reserving anything."""
        ...

    def release_device(self, target: Target) -> None: ...

    def set_cooldown(self, target: Target) -> None: ...

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

    def admit(self, target: Target, login: bool = True) -> str | None:
        """Why the safety gate turns `target` away, or None when it is admitted and reserved; `login` counts against the rate limit."""
        if self.gate is None:
            return None
        allowed, reason = self.gate.check_device(target, login=login)
        return None if allowed else reason

    def held(self, targets: Sequence[Target]) -> dict[str, str]:
        """Targets a cooldown holds now, for the probe to leave alone."""
        return self.gate.holds(targets) if self.gate else {}

    def settle(self, target: Target, verdict: Verdict | None) -> None:
        """Release the target in the gate, or cool it down as the verdict says."""
        if self.gate is None:
            return
        if verdict is not None and verdict.cool_down:
            self.gate.set_cooldown(target)
        else:
            self.gate.release_device(target)

    async def pause(self) -> None:
        await asyncio.sleep(self.settings.retry_pause)
