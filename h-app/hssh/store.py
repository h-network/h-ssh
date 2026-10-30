"""Private SQLite result writer and streaming reader."""

from __future__ import annotations

import csv
import difflib
import io
import json
import re
import math
import os
import sqlite3
import stat
import threading
import time
import weakref
from collections.abc import Iterator
from contextlib import closing, contextmanager
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


def operation_dict(operation: OperationResult) -> dict[str, object]:
    result = {"command": operation.command, "started": operation.started,
              "elapsed_ms": operation.elapsed_ms, "ok": not isinstance(operation.outcome, Fault)}
    if isinstance(operation.outcome, Fault):
        result.update(fault=operation.outcome.kind.name, detail=operation.outcome.detail,
                      reached_device=operation.outcome.reached_device)
    else:
        result.update(output=operation.outcome.output, data=json_data(operation.outcome.data))
    return result


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


_RESULT_COLUMNS = ("run_id", "seq", "target", "host", "driver", "command", "target_status", "ok",
                   "fault", "detail", "reached_device", "output", "data", "started", "elapsed_ms")


def _archive_state(path: Path) -> tuple[int, int, int, int] | None:
    if os.path.lexists(str(path) + "-journal"):
        return None
    try:
        if os.stat(str(path) + "-wal").st_size:
            return None
    except FileNotFoundError:
        pass
    info = path.stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _integer(value: int, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def _limit(value: int | None) -> tuple[str, list[int]]:
    return ("", []) if value is None else (" LIMIT ?", [_integer(value, "limit")])


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
        self._resolved: Path | None = None
        self._archive_snapshot: tuple[int, int, int, int] | None = None
        if readonly:
            self._open_reader()

    def _open_reader(self) -> None:
        try:
            self._resolved = Path(self.path).resolve(strict=True)
            info = self._resolved.stat()
            if not stat.S_ISREG(info.st_mode):
                raise OSError("not a regular store file")
            self._name = self._resolved.name
            self._identity = (info.st_dev, info.st_ino)
            self._directory = os.open(self._resolved.parent, getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY)
            self._release_directory = weakref.finalize(self, os.close, self._directory)
            uri = self._resolved.as_uri() + "?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True, timeout=_BUSY_TIMEOUT, check_same_thread=False)
            try:
                self._conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
            except sqlite3.Error as error:
                name = getattr(error, "sqlite_errorname", "")
                if not (name.startswith("SQLITE_READONLY") or name.startswith("SQLITE_CANTOPEN")
                        or "readonly" in str(error).lower() or "unable to open" in str(error).lower()):
                    raise
                self._conn.close()
                self._conn = None
                self._archive_snapshot = _archive_state(self._resolved)
                if self._archive_snapshot is None:
                    raise OSError("archive has a pending WAL or journal; copy the store with its sidecars "
                                  "to a writable directory before reading") from error
                self._conn = sqlite3.connect(uri + "&immutable=1", uri=True, check_same_thread=False)
            self._conn.execute("PRAGMA query_only = ON")
            with self._conn:
                self._conn.execute("BEGIN")
                if not _schema_state(self._conn):
                    raise OSError(_INCOMPATIBLE)
            self._conn.row_factory = sqlite3.Row
            self._read_guard()
        except BaseException as error:
            self._release()
            if isinstance(error, (OSError, sqlite3.Error)):
                raise OSError(f"{self.path}: cannot read store: {error}") from error
            raise

    def _read_guard(self) -> None:
        self._check_identity()
        if self._archive_snapshot is not None and _archive_state(self._resolved) != self._archive_snapshot:
            raise OSError("archive changed while it was read; output may be incomplete, read it again")

    def _query(self, sql: str, parameters=()) -> Iterator[sqlite3.Row]:
        with self._writing:
            try:
                if self._closed or self._conn is None:
                    raise OSError("store is not open")
                self._read_guard()
                cursor = self._conn.execute(sql, parameters)
                try:
                    yield from cursor
                finally:
                    cursor.close()
                    self._read_guard()
            except (OSError, sqlite3.Error) as error:
                raise OSError(f"{self.path}: cannot read store: {error}") from error

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
                if self.readonly:
                    raise OSError("store is read-only")
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
                        self._read_guard()
                finally:
                    self._closed = True
                    self._release()
            except (OSError, sqlite3.Error, UnicodeError) as error:
                raise OSError(getattr(error, "errno", None), f"cannot close store: {error}", self.path) from error

    def runs(self, last: int | None = 20) -> Iterator[sqlite3.Row]:
        limit, parameters = _limit(last)
        return self._query("SELECT * FROM runs ORDER BY julianday(started) DESC, id DESC" + limit, parameters)

    def last_run_id(self) -> int | None:
        with closing(self.runs(last=1)) as rows:
            row = next(rows, None)
            return row["id"] if row is not None else None

    def resolve_run(self, selector: int | str | None = None) -> int:
        if selector is None:
            found = self.last_run_id()
            if found is None:
                raise ValueError("the store holds no runs")
            return found
        if type(selector) is int:
            _integer(selector, "run ID", 1)
        elif not isinstance(selector, str) or not re.fullmatch(r"[0-9]+", selector):
            raise ValueError("run selector must be a decimal ID or a literal decimal prefix")
        text = str(selector)
        with closing(self._query("SELECT id FROM runs WHERE CAST(id AS TEXT) = ?", (text,))) as rows:
            exact = next(rows, None)
        if exact is not None:
            return exact["id"]
        if isinstance(selector, str):
            matches = list(self._query("SELECT id FROM runs WHERE substr(CAST(id AS TEXT), 1, length(?)) = ? "
                                       "ORDER BY id LIMIT 2", (text, text)))
            if len(matches) == 1:
                return matches[0]["id"]
            if matches:
                raise ValueError(f"ambiguous run prefix {selector!r}")
        raise ValueError(f"no run {selector!r}")

    def results(
        self, run_id: int | None = None, target: str | None = None,
        command: str | None = None, ok: bool | None = None, *,
        status: TargetStatus | None = None, seq: int | None = None,
        order: Literal["sequence", "newest", "slowest"] = "sequence",
        limit: int | None = None,
    ) -> Iterator[sqlite3.Row]:
        orders = {"sequence": "run_id, target, seq", "newest": "julianday(started) DESC, run_id, target, seq",
                  "slowest": "elapsed_ms DESC, run_id, target, seq"}
        if order not in orders:
            raise ValueError(f"unknown result order {order!r}")
        if run_id is not None:
            _integer(run_id, "run ID", 1)
        if seq is not None:
            _integer(seq, "sequence")
        if status is not None and status not in ("ok", "failed", "skipped"):
            raise ValueError(f"invalid target status {status!r}")
        for name, value in (("target", target), ("command", command)):
            if value is not None and not value.strip():
                raise ValueError(f"{name} filter is empty")
        where, parameters = [], []
        for column, value in (("run_id", run_id), ("target", target), ("command", command),
                              ("ok", ok), ("target_status", status), ("seq", seq)):
            if value is not None:
                where.append(column + " = ?")
                parameters.append(value)
        sql = "SELECT * FROM results" + (" WHERE " + " AND ".join(where) if where else "")
        tail, count = _limit(limit)
        return self._query(sql + " ORDER BY " + orders[order] + tail, parameters + count)

    def output(self, run_id: int, target: str, seq: int = 0) -> sqlite3.Row:
        with closing(self.results(run_id, target, seq=seq, limit=1)) as rows:
            row = next(rows, None)
        if row is None:
            raise ValueError(f"no result for {target!r} sequence {seq} in run {run_id}")
        return row

    def compare(self, before: int, after: int, target: str, seq: int = 0) -> str:
        left, right = self.output(before, target, seq), self.output(after, target, seq)
        for run, row in ((before, left), (after, right)):
            if not row["ok"]:
                raise ValueError(f"cannot compare failed operation in run {run}: {row['fault']}: {row['detail']}")
        lines = difflib.unified_diff(left["output"].splitlines(), right["output"].splitlines(),
                                    fromfile=f"{target} {before}", tofile=f"{target} {after}", lineterm="")
        return "\n".join(lines)

    def export(
        self, run_id: int | None = None, *,
        format: Literal["jsonl", "csv"] = "jsonl",
        target: str | None = None, command: str | None = None,
        ok: bool | None = None, status: TargetStatus | None = None,
        seq: int | None = None,
    ) -> Iterator[str]:
        if format not in ("jsonl", "csv"):
            raise ValueError(f"unknown export format {format!r}")
        with closing(self.results(run_id, target, command, ok, status=status, seq=seq)) as rows:
            buffer = io.StringIO(newline="")
            writer = csv.writer(buffer)
            if format == "csv":
                writer.writerow(_RESULT_COLUMNS)
                yield buffer.getvalue()
            for row in rows:
                if format == "csv":
                    buffer.seek(0)
                    buffer.truncate()
                    writer.writerow(row[column] for column in _RESULT_COLUMNS)
                    yield buffer.getvalue()
                else:
                    record = dict(row)
                    if record["data"] is not None:
                        record["data"] = json.loads(record["data"])
                    yield json.dumps(record, ensure_ascii=False) + "\n"
