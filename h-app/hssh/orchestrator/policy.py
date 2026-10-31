"""Policy: maps each Fault to an action and applies the safety gate (sections 3.2 and 4.4)."""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from enum import Enum, auto
from typing import Protocol, Sequence

from hssh.dialects.base import Dialect
from hssh.model import Fault, FaultKind, PolicySettings, Target
from hssh.orchestrator.defaults import CONNECT_BACKOFF, DEFAULT_POLICY

# The communicator's operation that opens the session: a fault from it is "before login".
OPEN = "open"


class Action(Enum):
    RETRY = auto()
    FAIL = auto()
    SKIP = auto()


@dataclass(frozen=True)
class Verdict:
    """What the policy decided for one fault: the action and whether the device is cooled down."""

    action: Action
    cool_down: bool = False


class SafetyGate(Protocol):
    """What the policy calls on hssh.safety.SafetyGate."""

    def check_device(self, target: Target, *, login: bool = True) -> tuple[bool, str]:
        """(admitted, reason); admission reserves the device until release_device or set_cooldown."""
        ...

    def holds(self, targets: Sequence[Target]) -> dict[str, str]:
        """Target names held by a cooldown, and why, without reserving anything."""
        ...

    def count_login(self, target: Target) -> tuple[bool, str]:
        """(allowed, reason) for a further login to a device this run already holds: counted in the window, nothing reserved."""
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
    if operation == OPEN and kind in (FaultKind.TIMEOUT, FaultKind.SESSION_LOST):
        unanswered = kind is FaultKind.TIMEOUT and not fault.reached_device
        dropped = kind is FaultKind.SESSION_LOST
        return Verdict(Action.RETRY if (unanswered or dropped) and retries_left else Action.FAIL)
    if kind in (FaultKind.UNREACHABLE, FaultKind.AUTH, FaultKind.HOST_KEY, FaultKind.UNSUPPORTED, FaultKind.LOCAL):
        return Verdict(Action.FAIL)
    if kind is FaultKind.OUTCOME_UNKNOWN:
        return Verdict(Action.FAIL, cool_down=True)
    if kind in (FaultKind.TIMEOUT, FaultKind.SESSION_LOST):
        if read and retries_left:
            return Verdict(Action.RETRY)
        return Verdict(Action.FAIL, cool_down=editing and fault.reached_device)
    return Verdict(Action.FAIL, cool_down=editing and fault.reached_device)


class Policy:
    """Retry, cooldown and safety-gate decisions for one run."""

    def __init__(self, settings: PolicySettings | None, gate: SafetyGate | None) -> None:
        self.settings = settings or DEFAULT_POLICY
        self.gate = gate
        self._said = False

    def admit(self, target: Target, login: bool = True) -> str | None:
        """Why the safety gate turns `target` away, or None when it is admitted and reserved; `login` counts against the rate limit."""
        if self.gate is None:
            return None
        allowed, reason = self.gate.check_device(target, login=login)
        return None if allowed else reason

    def login(self, target: Target) -> str | None:
        """Why the gate refuses one more login to a device already admitted (a reopen inside a borrow), or None when it is counted."""
        if self.gate is None:
            return None
        allowed, reason = self.gate.count_login(target)
        return None if allowed else reason

    def held(self, targets: Sequence[Target]) -> dict[str, str]:
        """Targets a cooldown holds now, for the probe to leave alone."""
        return self.gate.holds(targets) if self.gate else {}

    def settle(self, target: Target, verdict: Verdict | None) -> None:
        """Release the target in the gate, or cool it down as the verdict says; a gate that cannot persist is said once, the verdict stands."""
        if self.gate is None:
            return
        try:
            if verdict is not None and verdict.cool_down:
                self.gate.set_cooldown(target)
            else:
                self.gate.release_device(target)
        except OSError as e:
            if not self._said:
                self._said = True
                print(f"safety gate: {e}; the run goes on", file=sys.stderr)

    async def pause(self, attempt: int, unanswered: bool) -> None:
        """Before attempt + 1: the connect backoff after a connect nothing answered, else the settings' retry pause, which also lets a device that dropped the setup recover."""
        backoff = CONNECT_BACKOFF[min(attempt, len(CONNECT_BACKOFF)) - 1] if unanswered else self.settings.retry_pause
        await asyncio.sleep(backoff)
