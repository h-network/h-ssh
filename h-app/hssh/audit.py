"""Audit and private-file skeleton; append and write operations are not implemented."""

from __future__ import annotations

from pathlib import Path

from hssh.dialects.base import Dialect
from hssh.model import EditSettings, OperationResult, Target


def private_dir(path: str | Path) -> None:
    path = Path(path)
    for level in reversed([path, *path.parents]):
        if not level.is_dir():
            try:
                level.mkdir(mode=0o700)
            except FileExistsError:
                pass


def redact_secrets(text: str, dialect: Dialect) -> str:
    """Replace each complete pattern match; leave raw store output untouched."""
    for pattern in dialect.redaction_patterns:
        text = pattern.sub("[REDACTED]", text)
    return text


def secure_append(path: str, text: str) -> None:
    raise NotImplementedError


def probe_append(path: str) -> None:
    raise NotImplementedError


def secure_write(path: str, text: str) -> None:
    raise NotImplementedError


def write_audit_entry(
    path: str,
    *,
    run_id: int,
    user: str,
    target: Target,
    driver: str,
    dialect: Dialect,
    action: str,
    operation: OperationResult,
    edit: EditSettings,
    diff: str = "",
) -> None:
    """Append JSONL using operation.started as time; write errors propagate."""
    raise NotImplementedError
