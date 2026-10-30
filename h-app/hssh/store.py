"""SQLite writer and reader skeleton; persistence is not implemented."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Sequence
from typing import Literal

from hssh.model import OperationResult, RunReport, RunSpec, Target, TargetStatus


def json_data(value: object) -> bool | None | dict[str, object] | list[object]:
    raise NotImplementedError


class Store:
    def __init__(self, path: str, readonly: bool = False) -> None:
        self.path = path
        self.readonly = readonly
        raise NotImplementedError

    def start_run(self, spec: RunSpec, started: str, *, user: str) -> int:
        raise NotImplementedError

    def add(
        self, run_id: int, target: Target, driver: str, seq: int,
        operation: OperationResult, *, status: TargetStatus,
    ) -> None:
        raise NotImplementedError

    def finish_run(self, report: RunReport) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

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
