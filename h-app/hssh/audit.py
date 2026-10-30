"""Private JSONL audit records with dialect-driven redaction."""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from collections.abc import Sequence
from pathlib import Path

from hssh.dialects.base import Dialect
from hssh.model import EditSettings, Fault, OperationResult, Target


def private_dir(path: str | Path) -> None:
    path = Path(path)
    for level in reversed([path, *path.parents]):
        if not level.is_dir():
            try:
                level.mkdir(mode=0o700)
            except FileExistsError:
                pass


def _mask_match(match: re.Match[str]) -> str:
    prefix = (match.group(1) or "") if match.re.groups else ""
    suffix = (match.group(3) or "") if match.re.groups >= 3 else ""
    masked = '"[REDACTED]"' if prefix.lstrip().startswith('"') and prefix.rstrip().endswith(":") else "[REDACTED]"
    return prefix + masked + suffix


def _redact_text(text: str, dialect: Dialect) -> str:
    for pattern in dialect.redaction_patterns:
        text = pattern.sub(_mask_match, text)
    return text


def _redact_value(value: object, dialect: Dialect) -> object:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if any(
                pattern.search(json.dumps(key) + ': "x"') for pattern in dialect.redaction_patterns
            ) else _redact_value(child, dialect)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(child, dialect) for child in value]
    if isinstance(value, str):
        return redact_secrets(value, dialect)
    return value


def redact_secrets(text: str, dialect: Dialect) -> str:
    """Mask JSON secret values by matching each key as '<JSON key>: "x"'; keep text prefixes and suffixes."""
    try:
        value = json.loads(text)
    except ValueError:
        return _redact_text(text, dialect)
    return json.dumps(_redact_value(value, dialect))


def check_private_file(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise OSError("not a regular file")
    if info.st_uid != os.geteuid():
        raise OSError("file is owned by another user")


@contextmanager
def private_file(path: str, flags: int, *, dir_fd: int | None = None, allow_character: bool = False):
    fd = os.open(path, flags | os.O_NONBLOCK | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        if not (allow_character and stat.S_ISCHR(info.st_mode)):
            check_private_file(info)
        yield fd
    finally:
        os.close(fd)


def _write_all(fd: int, text: str) -> None:
    data = memoryview(text.encode("utf-8"))
    while data:
        written = os.write(fd, data)
        if written <= 0:
            raise OSError("write made no progress")
        data = data[written:]


def _write_recording(path: str, text: str, *, append: bool) -> None:
    action = "append" if append else "write"
    try:
        private_dir(Path(path).parent)
        flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else 0)
        with private_file(path, flags) as fd:
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.fchmod(fd, 0o600)
            if not append:
                os.ftruncate(fd, 0)
            _write_all(fd, text)
    except (OSError, UnicodeError) as error:
        raise OSError(getattr(error, "errno", None), f"cannot {action} recording: {error}", path) from error


def secure_append(path: str, text: str) -> None:
    _write_recording(path, text, append=True)


def probe_append(path: str) -> None:
    secure_append(path, "")


def probe_output_dir(path: str) -> None:
    try:
        private_dir(path)
        fd, name = tempfile.mkstemp(prefix=".hssh-probe-", dir=path)
        try:
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        finally:
            os.unlink(name)
    except OSError as error:
        raise OSError(error.errno, f"cannot record saved output: {error}", path) from error


def secure_write(path: str, text: str) -> None:
    _write_recording(path, text, append=False)


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
    lines: Sequence[str] = (),
) -> None:
    """Append JSONL using operation.started as time; write errors propagate.
    Actions: load, diff, commit, confirm, probe (edit stopped by probe failure).
    """
    fault = operation.outcome if isinstance(operation.outcome, Fault) else None
    entry = {
        "time": operation.started,
        "run_id": run_id,
        "user": user,
        "target": target.name,
        "host": target.host,
        "driver": driver,
        "action": action,
        "payload": redact_secrets("\n".join(lines), dialect) if action == "load" else "",
        "dry_run": not edit.apply,
        "confirmed_minutes": edit.confirmed_minutes,
        "comment": redact_secrets(edit.comment, dialect) if edit.comment is not None else None,
        "diff": redact_secrets(diff, dialect),
        "ok": fault is None,
        "fault": {
            "kind": fault.kind.name,
            "detail": redact_secrets(fault.detail, dialect),
            "reached_device": fault.reached_device,
        } if fault is not None else None,
    }
    secure_append(path, json.dumps(entry) + "\n")
