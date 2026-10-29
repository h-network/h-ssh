"""Recorder: every result to the store, every change to the audit log, with redaction (sections 3.6, 3.7, 6, 7)."""

from __future__ import annotations

import getpass
import re
from typing import Protocol, Sequence

from hssh.model import EditSettings, Fault, OperationResult, RecordSettings, RunReport, RunSpec, Target

REDACTED = "[REDACTED]"


class StoreWriter(Protocol):
    """The writing side of hssh.store, schema in section 6.1."""

    def begin_run(self, started: str, mode: str, argv: str | None, targets: int) -> int: ...

    def add_result(self, run_id: int, seq: int, target: str, host: str, driver: str, command: str, ok: bool,
                   fault: str | None, detail: str | None, output: str | None, started: str, elapsed_ms: int) -> None: ...

    def finish_run(self, run_id: int, finished: str, ok: int, failed: int, skipped: int) -> None: ...

    def close(self) -> None: ...


class AuditWriter(Protocol):
    """The append-only JSONL log of hssh.audit, entry format in section 6.2."""

    def append(self, entry: dict) -> None: ...


class OutputSaver(Protocol):
    """Saved device output, one 0600 file per target."""

    def save(self, target: str, text: str) -> None: ...


def redact(text: str, patterns: Sequence[re.Pattern[str]]) -> str:
    """Every match of the dialect's redaction patterns replaced; group 1 when the pattern has one, else the whole match."""
    for pattern in patterns:
        text = pattern.sub(lambda m: m.group(0).replace(m.group(1), REDACTED) if m.groups() else REDACTED, text)
    return text


class Recorder:
    """Writes the run: a row per run, a row per operation, an audit entry per change, output saved as asked."""

    def __init__(self, settings: RecordSettings | None, store: StoreWriter | None = None,
                 audit: AuditWriter | None = None, saver: OutputSaver | None = None) -> None:
        self.settings = settings or RecordSettings()
        self.store = store
        self.audit = audit
        self.saver = saver
        self.user = getpass.getuser()

    def begin(self, spec: RunSpec, started: str) -> int:
        """Open the run's row; 0 without a store."""
        if self.store is None:
            return 0
        argv = " ".join(self.settings.argv) if self.settings.argv else None
        return self.store.begin_run(started, spec.mode, argv, len(spec.targets))

    def result(self, run_id: int, target: Target, driver: str, seq: int, op: OperationResult,
               patterns: Sequence[re.Pattern[str]]) -> None:
        """One operation's row. The store keeps output as received; only fault detail is redacted."""
        if self.store is None:
            return
        fault = op.outcome if isinstance(op.outcome, Fault) else None
        self.store.add_result(run_id, seq, target.name, target.host, driver, op.command, fault is None,
                              fault.kind.name if fault else None, redact(fault.detail, patterns) if fault else None,
                              None if fault else op.outcome.output, op.started, op.elapsed_ms)

    def change(self, run_id: int, target: Target, driver: str, action: str, edit: EditSettings,
               diff: str | None, op: OperationResult, patterns: Sequence[re.Pattern[str]]) -> None:
        """One audit entry for an action that changed or could change the device, dry runs included."""
        ...

    def save_output(self, target: Target, text: str) -> None:
        ...

    def finish(self, report: RunReport) -> None:
        """Close the run's row with its counts."""
        if self.store is not None:
            self.store.finish_run(report.run_id, report.finished, report.ok, report.failed, report.skipped)
