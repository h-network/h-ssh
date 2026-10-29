"""Shared data types for h-ssh: targets, specs, results, faults and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Literal, Mapping

Mode = Literal["show", "batch", "structured", "edit", "rollback", "confirm", "commit_status"]


@dataclass(frozen=True)
class Target:
    """One device to reach: its name, address, vendor and transport."""

    name: str
    host: str
    vendor: str
    transport: str
    port: int | None = None


@dataclass(frozen=True)
class Credentials:
    """Login material handed to a communicator; never recorded or logged."""

    username: str
    password: str | None = None
    key_file: str | None = None


@dataclass(frozen=True)
class Timeouts:
    """Seconds allowed before login and for each operation in a session."""

    connect: float
    command: float


@dataclass(frozen=True)
class RunSpec:
    """Everything the orchestrator needs to execute one run (section 5.1)."""

    targets: tuple[Target, ...]
    mode: Mode
    commands: tuple[str, ...] = ()
    config_lines: tuple[str, ...] = ()
    credentials: Credentials | None = None
    timeouts: Timeouts | None = None
    workers: int = 1
    safety: Mapping[str, object] = field(default_factory=dict)
    recording: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class Result:
    """Output of one successful operation (section 4.2)."""

    output: str
    data: object | None = None
    elapsed: float = 0.0


class FaultKind(Enum):
    """Why an operation failed (section 4.3)."""

    UNREACHABLE = auto()
    AUTH = auto()
    HOST_KEY = auto()
    TIMEOUT = auto()
    SESSION_LOST = auto()
    REFUSED = auto()
    COMMIT_FAILED = auto()
    OUTCOME_UNKNOWN = auto()
    UNSUPPORTED = auto()
    LOCAL = auto()


@dataclass(frozen=True)
class Fault(Exception):
    """A failed operation, with the library's own message and whether it reached the device."""

    kind: FaultKind
    detail: str
    reached_device: bool


@dataclass(frozen=True)
class RunReport:
    """What one run produced: per-target outcomes, counts and pending commits."""

    run_id: int
    mode: Mode
    started: str
    finished: str
    results: tuple[tuple[Target, Result | Fault | None], ...]
    ok: int
    failed: int
    skipped: int
    pending: Mapping[str, str] = field(default_factory=dict)
