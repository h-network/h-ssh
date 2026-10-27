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

# Patterns for redaction of sensitive credentials/tokens. Order matters: the
# Junos "## SECRET-DATA" rule goes first, it knows the value is the last token
# whatever the keyword.
_REDACT_PATTERNS = [
    # Junos marks every secret line in text/display-set output: the last token
    # before the marker is the secret, whatever stanza it sits in.
    (re.compile(r'^([^\n]*?)("[^"\n]*"|[^\s\n;]+)(;?\s*## SECRET-DATA)', re.MULTILINE),
     r'\1[REDACTED]\3'),
    # keyword [type words] value — Junos set/text, EOS and IOS alike:
    # `plain-text-password-value hunter2`, `authentication md5 1 key X`,
    # `ntp authentication-key 1 value "$9$.."`, `secret sha512 $6$..`,
    # `tacacs-server key 7 X`, `key-string 7 X`, `privacy-key "$9$.."`.
    (re.compile(r'((?:encrypted-password|plain-text-password(?:-value)?|password(?:-value)?|secret|'
                r'authentication-key|message-digest-key|md5-key|privacy-key|key-string)\s+'
                r'(?:(?:\d+|md5|sha512|sha256|sha1|sha|value|type\s+\S+|hmac-\S+)\s+)*)'
                r'(?:("[^"]*"|\'[^\']*\'|[^\s\n;]+))', re.IGNORECASE),
     r'\1[REDACTED]'),
    # A bare `key` only where a protocol puts a secret after it, so a
    # description with the word "key" in it is left alone: `md5 1 key X`
    # (OSPF/IS-IS/BGP), `key 7 X` (IOS type 7), `tacacs-server … key X`,
    # `radius-server … key X`, `crypto isakmp key X`.
    (re.compile(r'((?:(?<![\w-])(?:md5|sha\d*|hmac-\S+)\s+\d+\s+key\s+|(?<![\w-])key\s+\d+\s+|\bisakmp\s+key\s+|'
                r'\b(?:tacacs-server|radius-server)\b[^\n]*?\bkey\s+(?:\d+\s+)?))'
                r'(?:("[^"]*"|\'[^\']*\'|[^\s\n;]+))', re.IGNORECASE),
     r'\1[REDACTED]'),
    # XML, as --format xml returns it: <encrypted-password>$6$..</encrypted-password>
    (re.compile(r'(<(?:[\w.-]+:)?(?:encrypted-password|plain-text-password-value|secret|password|passwd|'
                r'authentication-key|md5-key|key|key-string|privacy-key|pre-shared-key|ascii-text|'
                r'hexadecimal|hex-key|key-hex|token|api-key)>)[^<]*(?=</)', re.IGNORECASE),
     r'\1[REDACTED]'),
    (re.compile(r'(<community>\s*<name>)[^<]*(?=</name>)', re.IGNORECASE), r'\1[REDACTED]'),
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
    "encrypted-password", "plain-text-password-value", "secret", "password", "passwd",
    "authentication-key", "md5-key", "key", "key-string", "privacy-key", "community",
    "pre-shared-key", "ascii-text", "hexadecimal", "hex-key", "key-hex", "token",
    "api-key", "api_key",
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


def probe_append(path: str) -> None:
    """Prove that secure_append() will be able to write `path` before a run
    depends on it: the directory is created, the file is opened the way
    secure_append opens it (created 0600, no symlink, a regular file, not a
    FIFO) and nothing is written. Raises OSError naming the reason. An
    audit log that cannot be written is found out here, not after the
    commits it was supposed to record."""
    log_path = Path(path)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise OSError(f"{path}: cannot create its directory ({e.strerror})") from e
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(log_path), flags, 0o600)
    except OSError as e:
        raise OSError(f"{path}: not a plain file that can be appended to ({e.strerror})") from e
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path}: not a regular file; refusing to write the log there")
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def secure_write(path: str, text: str) -> None:
    """Replace a 0600 regular file of our own with `text` (--save-output):
    the same open rules as secure_append, truncating instead of appending."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(out), flags, 0o600)
    except OSError as e:
        raise OSError(f"{path}: not a plain file that can be written ({e.strerror})") from e
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path}: not a regular file; refusing to write there")
        os.fchmod(fd, 0o600)
        data = text.encode("utf-8")
        while data:
            written = os.write(fd, data)
            if written <= 0:
                raise OSError(f"{path}: short write, {len(data)} bytes not written")
            data = data[written:]
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
