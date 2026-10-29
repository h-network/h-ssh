"""SQLite writer and reader skeleton; persistence is not implemented."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Sequence

from hssh.model import OperationResult, RunReport, RunSpec, Target

DEFAULT = "h-ssh.db"


class Store:
    def __init__(self, path: str = DEFAULT, readonly: bool = False) -> None:
        self.path = path
        self.readonly = readonly
        raise NotImplementedError

    def start_run(self, spec: RunSpec, started: str) -> int:
        raise NotImplementedError

    def add(
        self, run_id: int, target: Target, driver: str, seq: int,
        operation: OperationResult,
    ) -> None:
        raise NotImplementedError

    def finish_run(self, report: RunReport) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def runs(self, last: int = 20) -> list[sqlite3.Row]:
        raise NotImplementedError

    def last_run_id(self) -> int | None:
        raise NotImplementedError

    def results(
        self, run_id: int, target: str | None = None,
        command: str | None = None, ok: bool | None = None,
    ) -> Iterator[sqlite3.Row]:
        raise NotImplementedError

    def output(self, run_id: int, target: str, seq: int = 0) -> sqlite3.Row:
        raise NotImplementedError

    def compare(self, before: int, after: int, target: str, seq: int = 0) -> str:
        raise NotImplementedError

    def export(self, run_id: int) -> Iterator[str]:
        """Yield one JSON object per stored result, as JSONL."""
        raise NotImplementedError


def main(argv: Sequence[str] | None = None) -> int:
    raise NotImplementedError
