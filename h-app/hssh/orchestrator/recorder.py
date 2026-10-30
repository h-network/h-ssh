"""Recorder: every result to the store, every change to the audit log, output saved as asked (sections 3.6, 3.7, 6, 7)."""

from __future__ import annotations

import getpass
import sys
from pathlib import Path
from typing import Callable, Protocol, Sequence

from hssh.dialects.base import Dialect
from hssh.orchestrator.lifecycle import now
from hssh.model import (EditSettings, Fault, OperationResult, RecordSettings, Result, RunReport, RunSpec, Target,
                        TargetResult, TargetStatus)

AUDITED = ("load", "diff", "commit", "confirm")


class StoreWriter(Protocol):
    """What the recorder calls on hssh.store.Store."""

    def start_run(self, spec: RunSpec, started: str, *, user: str) -> int: ...

    def add(self, run_id: int, target: Target, driver: str, seq: int, operation: OperationResult, *,
            status: TargetStatus) -> None: ...

    def finish_run(self, report: RunReport) -> None: ...

    def close(self) -> None: ...


class Recorder:
    """Writes the run: a row per run, a row per operation, an audit entry per change, output saved as asked. A record that cannot be written is counted in `not_kept` and said once; it is never the target's failure."""

    def __init__(self, settings: RecordSettings | None, store: StoreWriter | None = None) -> None:
        self.settings = settings or RecordSettings()
        self.store = store
        self.user = getpass.getuser()
        self.not_kept = 0

    def preflight(self) -> None:
        """Prove the audit log, the run log and the saved-output directory usable; an OSError here refuses the run before any device."""
        for path in (self.settings.audit_log_path, self.settings.log_path):
            if path is not None:
                from hssh.audit import probe_append

                probe_append(path)
        if self.settings.save_output_path is not None:
            from hssh.audit import probe_output_dir

            probe_output_dir(self.settings.save_output_path)

    def begin(self, spec: RunSpec, started: str) -> int:
        """Open the run's row, which creates the store; 0 without a store. An OSError here refuses the run."""
        return self.store.start_run(spec, started, user=self.user) if self.store is not None else 0

    def _kept(self, write: Callable[[], None]) -> None:
        try:
            write()
        except Exception as e:  # noqa: BLE001 - whatever fails in a record write, the device outcome stands
            self.not_kept += 1
            print(f"record not kept: {type(e).__name__ if not str(e) else e}", file=sys.stderr)

    def result(self, run_id: int, target: Target, driver: str, seq: int, op: OperationResult, status: TargetStatus) -> None:
        """One operation's row with the target's final status; `driver` is "" when the target failed before a driver was resolved."""
        if self.store is not None:
            self._kept(lambda: self.store.add(run_id, target, driver, seq, op, status=status))

    def change(self, run_id: int, target: Target, driver: str, dialect: Dialect, action: str,
               op: OperationResult, edit: EditSettings, diff: str = "", lines: Sequence[str] = ()) -> None:
        """One audit entry for an action that changed or could change the device, dry runs included; `lines` is the payload a load sent."""
        if self.settings.audit_log_path is None:
            return
        from hssh.audit import write_audit_entry

        self._kept(lambda: write_audit_entry(self.settings.audit_log_path, run_id=run_id, user=self.user, target=target,
                                             driver=driver, dialect=dialect, action=action, operation=op, edit=edit,
                                             diff=diff, lines=lines))

    def changes(self, run_id: int, target: Target, driver: str, dialect: Dialect, ops: Sequence[OperationResult],
                edit: EditSettings, config_lines: Sequence[str] = ()) -> None:
        """An audit entry per audited operation; a line-by-line load keeps the config line as its command and is audited as 'load' with that line, a candidate load with the whole payload; the diff's output is carried on every entry after it."""
        diff = ""
        for op in ops:
            line_by_line = op.command in config_lines
            action = "load" if line_by_line else op.command
            if action == "diff" and isinstance(op.outcome, Result):
                diff = op.outcome.output
            if action in AUDITED:
                lines = ((op.command,) if line_by_line else tuple(config_lines)) if action == "load" else ()
                self.change(run_id, target, driver, dialect, action, op, edit, diff, lines)

    def save_output(self, target: Target, ops: Sequence[OperationResult]) -> None:
        """The target's device output, one file per target, named inside the saved-output directory."""
        if self.settings.save_output_path is None:
            return
        from hssh.audit import secure_write
        from hssh.paths import path_inside, validate_device_name

        def write() -> None:
            path = path_inside(Path(self.settings.save_output_path), f"{validate_device_name(target.name)}.output")
            secure_write(str(path), "\n".join(op.outcome.output for op in ops if isinstance(op.outcome, Result)))

        self._kept(write)

    def log(self, result: TargetResult) -> None:
        """One line per target in the run log."""
        if self.settings.log_path is None:
            return
        from hssh.audit import secure_append

        last = result.operations[-1] if result.operations else None
        detail = f" {last.outcome.kind.name}: {last.outcome.detail}" if last and isinstance(last.outcome, Fault) else ""
        self._kept(lambda: secure_append(self.settings.log_path, f"{now()} {result.target.name} {result.status}{detail}\n"))

    def finish(self, report: RunReport) -> None:
        """Close the run's row with its counts; a row that cannot be closed is counted like any other record."""
        if self.store is not None:
            self._kept(lambda: self.store.finish_run(report))

    def close(self) -> None:
        """Close the store; a close that fails is counted like any other record, never the run's end."""
        if self.store is not None:
            self._kept(self.store.close)
