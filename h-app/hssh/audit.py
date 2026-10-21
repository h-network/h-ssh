"""JSONL audit trail for network operations."""

import fcntl
import json
import logging
import os
import stat
from pathlib import Path
import re
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Patterns for redaction of sensitive credentials/tokens
_REDACT_PATTERNS = [
    (re.compile(r'((?:encrypted-password|secret|password|authentication-key|md5-key)\s+(?:\d+\s+)?)(?:("[^"]*"|\'[^\']*\'|[^\s\n;]+))', re.IGNORECASE),
     r'\1[REDACTED]'),
    (re.compile(r'((?:password|secret|token|api[_-]?key|passwd)\s*[:=]\s*)(?:("[^"]*"|\'[^\']*\'|[^\s,;]+))', re.IGNORECASE),
     r'\1[REDACTED]'),
    (re.compile(r'(\bcommunity\s+)(?:("[^"]*"|\'[^\']*\'|[^\s\n;]+))', re.IGNORECASE),
     r'\1[REDACTED]'),
    (re.compile(r'(\b(?:pre-shared-key|ascii-text|hexadecimal|hex-key|key-hex)\s+(?:(?:ascii-text|hexadecimal|hex-key|key-hex)\s+)?)(?:("[^"]*"|\'[^\']*\'|[^\s\n;]+))', re.IGNORECASE),
     r'\1[REDACTED]'),
]


def redact_secrets(text: Optional[str]) -> Optional[str]:
    """Redact passwords and secrets from text."""
    if not text:
        return text
    result = text
    for pattern, repl in _REDACT_PATTERNS:
        result = pattern.sub(repl, result)
    return result


# JSON keys whose whole value is a secret. A reply carried as data (--format
# json) puts "encrypted-password" in the key and the hash in the value, out
# of reach of the text patterns above.
_SECRET_KEYS = frozenset({
    "encrypted-password", "secret", "password", "passwd", "authentication-key",
    "md5-key", "community", "pre-shared-key", "ascii-text", "hexadecimal",
    "hex-key", "key-hex", "token", "api-key", "api_key",
})


def redact_values(data):
    """redact_secrets() over a JSON-shaped value: every string in it, and the
    whole value under a key that names a secret. Lists and dicts keep their
    shape, so a --log record stays data."""
    if isinstance(data, str):
        return redact_secrets(data)
    if isinstance(data, list):
        return [redact_values(v) for v in data]
    if isinstance(data, dict):
        return {k: ("[REDACTED]" if str(k).lower() in _SECRET_KEYS else redact_values(v))
                for k, v in data.items()}
    return data


def secure_append(path: str, text: str) -> None:
    """Append `text` to a 0600 regular file under an exclusive flock, creating
    it and its directory. The audit log and --log both go through here, so a
    file that holds payloads, replies and diffs is never world-readable.

    The name is opened without following a symlink and must be a regular
    file: a planted link once redirected the audit trail into (and chmod'ed)
    whatever it pointed at, and a planted FIFO blocked a fleet run forever.
    O_NONBLOCK makes a reader-less FIFO fail at open instead; a regular
    file ignores it. The mode is set on the descriptor, and a short write
    is finished or reported, never counted as done."""
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(log_path), flags, 0o600)
    except OSError as e:
        raise OSError(f"{path}: not a plain file that can be appended to ({e.strerror})") from e
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path}: not a regular file; refusing to write the log there")
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            os.fchmod(fd, 0o600)
            data = text.encode("utf-8")
            while data:
                written = os.write(fd, data)
                if written <= 0:
                    raise OSError(f"{path}: short write, {len(data)} bytes not written")
                data = data[written:]
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def write_audit_entry(
    path: str,
    device: str,
    host: str,
    vendor: str,
    mode: str,
    payload: str,
    ok: bool,
    diff: Optional[str] = None,
    error: Optional[str] = None,
    dry_run: bool = False,
    commit_confirmed: Optional[int] = None,
    comment: Optional[str] = None,
) -> bool:
    """Append a single audit entry (one line of JSON) to the audit log.

    Secured with 0600 permissions, fcntl.flock, and secret redaction.
    Failures do not raise exceptions, returning False instead to avoid
    disrupting execution loops.
    """
    try:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "device": device,
            "host": host,
            "vendor": vendor,
            "payload": redact_secrets(payload) if payload else "",
            "dry_run": dry_run,
            "ok": ok,
        }
        if commit_confirmed:
            entry["commit_confirmed"] = commit_confirmed
        if comment:
            entry["comment"] = comment
        if diff:
            entry["diff"] = redact_secrets(diff)
        if error:
            entry["error"] = redact_secrets(error)

        secure_append(path, json.dumps(entry) + "\n")
        return True
    except Exception as e:
        logger.warning("Failed to write audit entry to %s: %s", path, e)
        return False
