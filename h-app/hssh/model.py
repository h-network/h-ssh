"""Shared data types for h-ssh: targets, specs, results, faults and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Literal, Sequence

Mode = Literal["show", "batch", "structured", "edit", "commit_confirmed", "rollback", "confirm", "commit_status"]

HostKeyPolicy = Literal["accept-new", "strict", "off"]

TargetStatus = Literal["ok", "failed", "skipped"]


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
    """Login material handed to a communicator; with neither password nor key_file set, the library uses the SSH agent."""

    username: str
    password: str | None = None
    key_file: str | None = None


@dataclass(frozen=True)
class Timeouts:
    """Seconds allowed before login, for each operation in a session, and for a commit."""

    connect: float
    command: float
    commit: float


@dataclass(frozen=True)
class SafetySettings:
    """Safety gate settings: cooldown after a failed edit and the rate limit."""

    cooldown_seconds: float
    rate_limit: float


@dataclass(frozen=True)
class RecordSettings:
    """Where the run is recorded: store, audit log, log and saved output."""

    store_path: str
    audit_log_path: str
    log_path: str | None = None
    save_output_path: str | None = None


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
    host_key_policy: HostKeyPolicy = "accept-new"
    safety: SafetySettings | None = None
    recording: RecordSettings | None = None


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
class TargetResult:
    """One target's outcome: its status and its Result or Fault, or None when skipped."""

    target: Target
    status: TargetStatus
    outcome: Result | Fault | None = None


@dataclass(frozen=True)
class RunReport:
    """What one run produced: per-target outcomes, counts and pending commits."""

    run_id: int
    mode: Mode
    started: str
    finished: str
    results: Sequence[TargetResult]
    ok: int
    failed: int
    skipped: int
    pending: dict[str, str] = field(default_factory=dict)
