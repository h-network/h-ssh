"""Private SQLite result writer; reader commands await the reader phase."""

from __future__ import annotations

import json
import math
import os
import sqlite3
import stat
import threading
import time
import weakref
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Literal

from hssh.audit import check_private_file, private_dir, private_file
from hssh.model import Fault, OperationResult, RunReport, RunSpec, Target, TargetStatus


_SCHEMA_VERSION = 1
_BUSY_TIMEOUT = 10.0
_WAL_WAIT = 5.0
_SCHEMA = """
CREATE TABLE runs (
  id INTEGER PRIMARY KEY,
  started TEXT NOT NULL, finished TEXT,
  mode TEXT NOT NULL, argv TEXT, user TEXT NOT NULL,
  format TEXT, origin TEXT, version TEXT,
  targets INTEGER NOT NULL,
  ok INTEGER, failed INTEGER, skipped INTEGER,
  interrupted INTEGER NOT NULL DEFAULT 0 CHECK (interrupted IN (0, 1)),
  not_kept INTEGER NOT NULL DEFAULT 0 CHECK (not_kept >= 0)
);
CREATE TABLE results (
  run_id INTEGER NOT NULL REFERENCES runs(id),
  seq INTEGER NOT NULL CHECK (seq >= 0), target TEXT NOT NULL, host TEXT NOT NULL,
  driver TEXT NOT NULL, command TEXT NOT NULL,
  target_status TEXT NOT NULL CHECK (target_status IN ('ok', 'failed', 'skipped')),
  ok INTEGER NOT NULL CHECK (ok IN (0, 1)),
  fault TEXT, detail TEXT, reached_device INTEGER CHECK (reached_device IN (0, 1)),
  output TEXT, data TEXT,
  started TEXT NOT NULL, elapsed_ms INTEGER NOT NULL,
  PRIMARY KEY (run_id, target, seq)
);
"""
_INCOMPATIBLE = "incompatible store schema; use develop's h-ssh-store to read old stores, or choose a new store path"


def _json_value(value: object) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("unsupported JSON data: nonfinite float")
    elif isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError(f"unsupported JSON key type: {type(key).__name__}")
            _json_value(child)
    elif isinstance(value, list):
        for child in value:
            _json_value(child)
    else:
        raise ValueError(f"unsupported JSON data type: {type(value).__name__}")


def json_data(value: object) -> bool | None | dict[str, object] | list[object]:
    try:
        if is_dataclass(value) and not isinstance(value, type):
            value = asdict(value)
        if value is not None and not isinstance(value, (bool, dict, list)):
            raise ValueError(f"unsupported Result.data type: {type(value).__name__}")
        _json_value(value)
    except RecursionError as error:
        raise ValueError(f"unsupported recursive or too deeply nested data: {type(value).__name__}") from error
    return value


def _schema_state(conn: sqlite3.Connection) -> bool:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    tables = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' ORDER BY name").fetchall()
    if version == 0 and not conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
        return False
    expected = sorted("".join(part.split()).lower() for part in _SCHEMA.split(";") if part.strip())
    actual = sorted("".join(row[0].split()).lower() for row in tables)
    if version != _SCHEMA_VERSION or actual != expected:
        raise OSError(_INCOMPATIBLE)
    return True


def _wal(conn: sqlite3.Connection) -> None:
    deadline = time.monotonic() + _WAL_WAIT
    conn.execute("PRAGMA busy_timeout = 0")
    try:
        while True:
            try:
                if conn.execute("PRAGMA journal_mode = WAL").fetchone()[0].lower() != "wal":
                    raise OSError("cannot enable WAL")
                return
            except sqlite3.OperationalError as error:
                if "locked" not in str(error).lower() or time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
    finally:
        conn.execute(f"PRAGMA busy_timeout = {int(_BUSY_TIMEOUT * 1000)}")


class Store:
    def __init__(self, path: str, readonly: bool = False) -> None:
        self.path = os.fspath(path)
        self.readonly = readonly
        self._conn: sqlite3.Connection | None = None
        self._directory: int | None = None
        self._release_directory: weakref.finalize | None = None
        self._name = os.path.basename(self.path)
        self._identity: tuple[int, int] | None = None
        self._writing = threading.RLock()
        self._closed = False
        if readonly:
            raise NotImplementedError("read-only stores await the reader phase")

    def _check_identity(self) -> None:
        info = os.stat(self._name, dir_fd=self._directory, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != self._identity:
            raise OSError("store file was replaced during the run")

    def _sidecars(self, *, chmod: bool = True) -> None:
        for suffix in ("-wal", "-shm", "-journal"):
            name = self._name + suffix
            try:
                check_private_file(os.stat(name, dir_fd=self._directory, follow_symlinks=False))
                if chmod:
                    # Closing a second descriptor on a sidecar releases SQLite's process locks.
                    os.chmod(name, 0o600, dir_fd=self._directory, follow_symlinks=False)
            except FileNotFoundError:
                pass

    def _release(self) -> None:
        conn, release_directory = self._conn, self._release_directory
        self._conn, self._directory, self._release_directory = None, None, None
        try:
            if conn is not None:
                conn.close()
        finally:
            if release_directory is not None:
                release_directory()

    def _open(self) -> None:
        directory = os.path.dirname(self.path) or "."
        private_dir(directory)
        self._directory = os.open(directory, getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY)
        self._release_directory = weakref.finalize(self, os.close, self._directory)
        try:
            info = os.fstat(self._directory)
            if info.st_uid != os.geteuid() or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                raise OSError("store directory must be owned by this user and not writable by others unless sticky")
            try:
                with private_file(self._name, os.O_RDWR | os.O_CREAT | os.O_EXCL, dir_fd=self._directory):
                    pass
            except FileExistsError:
                pass
            info = os.stat(self._name, dir_fd=self._directory, follow_symlinks=False)
            check_private_file(info)
            self._identity = (info.st_dev, info.st_ino)
            self._sidecars(chmod=False)
            resolved = Path(self.path).resolve(strict=True)
            info = resolved.stat()
            if (info.st_dev, info.st_ino) != self._identity:
                raise OSError("store file was replaced while opening")
            self._conn = sqlite3.connect(resolved.as_uri() + "?mode=rw", uri=True,
                                         timeout=_BUSY_TIMEOUT, check_same_thread=False)
            self._check_identity()
            info = resolved.stat()
            if (info.st_dev, info.st_ino) != self._identity:
                raise OSError("store file was replaced while opening")
            with self._conn:
                self._conn.execute("BEGIN")
                _schema_state(self._conn)
            os.chmod(self._name, 0o600, dir_fd=self._directory, follow_symlinks=False)
            self._sidecars()
            _wal(self._conn)
            self._conn.execute("PRAGMA synchronous = NORMAL")
            self._conn.execute("PRAGMA foreign_keys = ON")
            with self._conn:
                self._conn.execute("BEGIN IMMEDIATE")
                if not _schema_state(self._conn):
                    for statement in _SCHEMA.split(";"):
                        if statement.strip():
                            self._conn.execute(statement)
                    self._conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            self._sidecars()
            self._check_identity()
            self._conn.row_factory = sqlite3.Row
        except BaseException:
            self._release()
            raise

    @contextmanager
    def _transaction(self):
        with self._writing:
            try:
                if self._closed or self._conn is None:
                    raise OSError("store is not open")
                self._check_identity()
                self._sidecars()
                with self._conn:
                    yield self._conn
                    self._check_identity()
                self._sidecars()
                self._check_identity()
            except (OSError, sqlite3.Error, UnicodeError) as error:
                raise OSError(getattr(error, "errno", None), f"cannot write store: {error}", self.path) from error

    def start_run(self, spec: RunSpec, started: str, *, user: str) -> int:
        with self._writing:
            try:
                if self._closed:
                    raise OSError("store is closed")
                if self._conn is None:
                    self._open()
                recording = spec.recording
                argv = json.dumps(recording.argv) if recording and recording.argv is not None else None
                with self._transaction() as conn:
                    cursor = conn.execute(
                        "INSERT INTO runs (started, mode, argv, user, format, origin, version, targets) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (started, spec.mode, argv, user, spec.format,
                         recording.origin if recording else None, recording.version if recording else None,
                         len(spec.targets)),
                    )
                    run_id = cursor.lastrowid
                return run_id
            except (OSError, sqlite3.Error, UnicodeError) as error:
                self._release()
                raise OSError(getattr(error, "errno", None), f"cannot start store run: {error}", self.path) from error

    def add(
        self, run_id: int, target: Target, driver: str, seq: int,
        operation: OperationResult, *, status: TargetStatus,
    ) -> None:
        outcome = operation.outcome
        fault = outcome if isinstance(outcome, Fault) else None
        data, conversion_error = None, None
        if fault is None:
            try:
                value = json_data(outcome.data)
                data = json.dumps(value, allow_nan=False) if value is not None else None
            except (ValueError, TypeError, RecursionError) as error:
                conversion_error = error
        with self._transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO results "
                "(run_id, seq, target, host, driver, command, target_status, ok, fault, detail, "
                "reached_device, output, data, started, elapsed_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, seq, target.name, target.host, driver, operation.command, status, int(fault is None),
                 fault.kind.name if fault else None, fault.detail if fault else None,
                 int(fault.reached_device) if fault else None, None if fault else outcome.output, data,
                 operation.started, operation.elapsed_ms),
            )
        if conversion_error is not None:
            raise OSError(f"{self.path}: incomplete record for {target.name} seq {seq}: "
                          f"Result.data ({type(outcome.data).__name__}): {conversion_error}") from conversion_error

    def finish_run(self, report: RunReport) -> None:
        with self._transaction() as conn:
            cursor = conn.execute(
                "UPDATE runs SET finished = ?, ok = ?, failed = ?, skipped = ?, interrupted = ?, not_kept = ? "
                "WHERE id = ?",
                (report.finished, report.ok, report.failed, report.skipped, int(report.interrupted),
                 report.not_kept, report.run_id),
            )
            if cursor.rowcount != 1:
                raise OSError(f"no stored run {report.run_id}")

    def close(self) -> None:
        with self._writing:
            try:
                try:
                    if self._conn is not None:
                        self._check_identity()
                finally:
                    self._closed = True
                    self._release()
            except (OSError, sqlite3.Error, UnicodeError) as error:
                raise OSError(getattr(error, "errno", None), f"cannot close store: {error}", self.path) from error

    def runs(self, last: int | None = 20) -> Iterator[sqlite3.Row]:
        raise NotImplementedError

    def last_run_id(self) -> int | None:
        raise NotImplementedError

    def resolve_run(self, selector: int | str | None = None) -> int:
        raise NotImplementedError

    def results(
        self, run_id: int | None = None, target: str | None = None,
        command: str | None = None, ok: bool | None = None, *,
        status: TargetStatus | None = None, seq: int | None = None,
        order: Literal["sequence", "newest", "slowest"] = "sequence",
        limit: int | None = None,
    ) -> Iterator[sqlite3.Row]:
        raise NotImplementedError

    def output(self, run_id: int, target: str, seq: int = 0) -> sqlite3.Row:
        raise NotImplementedError

    def compare(self, before: int, after: int, target: str, seq: int = 0) -> str:
        raise NotImplementedError

    def export(
        self, run_id: int | None = None, *,
        format: Literal["jsonl", "csv"] = "jsonl",
        target: str | None = None, command: str | None = None,
        ok: bool | None = None, status: TargetStatus | None = None,
        seq: int | None = None,
    ) -> Iterator[str]:
        raise NotImplementedError


def main(argv: Sequence[str] | None = None) -> int:
    raise NotImplementedError
