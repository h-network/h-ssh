"""JSONL audit trail for network operations."""

import fcntl
import json
import logging
import os
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
        if diff:
            entry["diff"] = redact_secrets(diff)
        if error:
            entry["error"] = redact_secrets(error)

        log_path = Path(path)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        line = json.dumps(entry) + "\n"
        fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                os.chmod(str(log_path), 0o600)
                os.write(fd, line.encode("utf-8"))
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return True
    except Exception as e:
        logger.warning("Failed to write audit entry to %s: %s", path, e)
        return False
