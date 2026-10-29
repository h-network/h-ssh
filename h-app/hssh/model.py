"""Shared data types for h-ssh: targets, specs, results, faults and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Literal, Sequence

Mode = Literal["show", "batch", "structured", "edit", "confirm", "commit_status"]

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

    connect: int
    command: int
    commit: int


@dataclass(frozen=True)
class SafetySettings:
    """Safety gate settings: cooldown_seconds after a failed edit, and rate_limit as login attempts per minute per device."""

    cooldown_seconds: int
    rate_limit: int
    safety_file: str | None = None


@dataclass(frozen=True)
class RecordSettings:
    """Where the run is recorded: store, audit log, log and saved output, each optional."""

    store_path: str | None = None
    audit_log_path: str | None = None
    log_path: str | None = None
    save_output_path: str | None = None
    argv: tuple[str, ...] | None = None


@dataclass(frozen=True)
class EditSettings:
    """How an edit run commits: dry run unless apply is set."""

    apply: bool
    confirmed_minutes: int | None = None
    comment: str | None = None


@dataclass(frozen=True)
class PolicySettings:
    """Retry policy: attempts and the pause between them in whole seconds."""

    retries: int
    retry_pause: int


@dataclass(frozen=True)
class RunSpec:
    """Everything the orchestrator needs to execute one run (section 5.1)."""

    targets: tuple[Target, ...]
    mode: Mode
    commands: tuple[str, ...] = ()
    config_lines: tuple[str, ...] = ()
    format: str | None = None
    credentials: Credentials | None = None
    timeouts: Timeouts | None = None
    workers: int | None = None
    host_key_policy: HostKeyPolicy | None = None
    probe: bool | None = None
    edit: EditSettings | None = None
    policy: PolicySettings | None = None
    safety: SafetySettings | None = None
    recording: RecordSettings | None = None


@dataclass(frozen=True)
class Result:
    """Output of one successful operation (section 4.2)."""

    output: str
    data: object | None = None


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
class OperationResult:
    """One operation on a target: the command, or 'open' for a failure before any ran, with its Result or Fault and elapsed milliseconds."""

    command: str
    outcome: Result | Fault
    started: str
    elapsed_ms: int


@dataclass(frozen=True)
class TargetResult:
    """One target's outcome: its status and its operations in order."""

    target: Target
    status: TargetStatus
    operations: Sequence[OperationResult] = ()


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
    interrupted: bool = False
    pending: dict[str, str] = field(default_factory=dict)
