"""Recorder: every result to the store, every change to the audit log, output saved as asked (sections 3.6, 3.7, 6, 7)."""

from __future__ import annotations

import getpass
from typing import Protocol

from hssh.dialects.base import Dialect
from hssh.model import EditSettings, OperationResult, RecordSettings, RunReport, RunSpec, Target


class StoreWriter(Protocol):
    """What the recorder calls on hssh.store.Store."""

    def start_run(self, spec: RunSpec, started: str) -> int: ...

    def add(self, run_id: int, target: Target, driver: str, seq: int, operation: OperationResult) -> None: ...

    def finish_run(self, report: RunReport) -> None: ...

    def close(self) -> None: ...


class Recorder:
    """Writes the run: a row per run, a row per operation, an audit entry per change, output saved as asked."""

    def __init__(self, settings: RecordSettings | None, store: StoreWriter | None = None) -> None:
        self.settings = settings or RecordSettings()
        self.store = store
        self.user = getpass.getuser()

    def begin(self, spec: RunSpec, started: str) -> int:
        """Open the run's row; 0 without a store."""
        return self.store.start_run(spec, started) if self.store is not None else 0

    def result(self, run_id: int, target: Target, driver: str, seq: int, op: OperationResult) -> None:
        """One operation's row; `driver` is "" when the target failed before a driver was resolved."""
        if self.store is not None:
            self.store.add(run_id, target, driver, seq, op)

    def change(self, run_id: int, target: Target, driver: str, dialect: Dialect, action: str,
               op: OperationResult, edit: EditSettings, diff: str = "") -> None:
        """One audit entry for an action that changed or could change the device, dry runs included."""
        if self.settings.audit_log_path is None:
            return
        from hssh.audit import write_audit_entry

        write_audit_entry(self.settings.audit_log_path, run_id=run_id, user=self.user, target=target, driver=driver,
                          dialect=dialect, action=action, operation=op, edit=edit, diff=diff)

    def save_output(self, target: Target, text: str) -> None:
        if self.settings.save_output_path is None:
            return
        from hssh.audit import secure_write

        secure_write(f"{self.settings.save_output_path}/{target.name}.output", text)

    def finish(self, report: RunReport) -> None:
        """Close the run's row with its counts."""
        if self.store is not None:
            self.store.finish_run(report)
