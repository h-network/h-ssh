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

# A value as a config line writes it: quoted, with escaped quotes inside it
# ("abc\"def" is one value), or one word; never a quote on its own, and
# never the next line's first word (blanks between the words, not `\s`).
_VALUE = r'("(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|[^\s;"\']+)'

# Patterns for redaction of sensitive credentials/tokens. Order matters: the
# Junos "## SECRET-DATA" rule goes first, it knows the value is the last token
# whatever the keyword.
_REDACT_PATTERNS = [
    # Junos marks every secret line in text/display-set output: the last token
    # before the marker is the secret, whatever stanza it sits in.
    (re.compile(r'^([^\n]*?)' + _VALUE + r'(;?[ \t]*## SECRET-DATA)', re.MULTILINE),
     r'\1[REDACTED]\3'),
    # keyword [type words] value — Junos set/text, EOS and IOS alike:
    # `plain-text-password-value hunter2`, `authentication md5 1 key X`,
    # `ntp authentication-key 1 value "$9$.."`, `secret sha512 $6$..`,
    # `tacacs-server key 7 X`, `key-string 7 X`, `privacy-key "$9$.."`,
    # and a quoted command an error repeats (`'password X' was refused`).
    (re.compile(r'((?:encrypted-password|plain-text-password(?:-value)?|password(?:-value)?|secret|'
                r'authentication-key|message-digest-key|md5-key|privacy-key|key-string)[ \t]+'
                r'(?:(?:\d+|md5|sha512|sha256|sha1|sha|value|type[ \t]+\S+|hmac-\S+)[ \t]+)*)' + _VALUE,
                re.IGNORECASE),
     r'\1[REDACTED]'),
    # A bare `key` only where a protocol puts a secret after it, so a
    # description with the word "key" in it is left alone: `md5 1 key X`
    # (OSPF/IS-IS/BGP), `key 7 X` (IOS type 7), `tacacs-server … key X`,
    # `radius-server … key X`, `crypto isakmp key X`. A key chain's `key 1`
    # line ends there: the key-string below it is not its value.
    (re.compile(r'((?:(?<![\w-])(?:md5|sha\d*|hmac-\S+)[ \t]+\d+[ \t]+key[ \t]+|(?<![\w-])key[ \t]+\d+[ \t]+|'
                r'\bisakmp[ \t]+key[ \t]+|'
                r'\b(?:tacacs-server|radius-server)\b[^\n]*?\bkey[ \t]+(?:\d+[ \t]+)?))' + _VALUE, re.IGNORECASE),
     r'\1[REDACTED]'),
    # XML, as --format xml returns it, the tag known by its last word:
    # <encrypted-password>, <hello-authentication-key>, <chap-secret>, <key>.
    (re.compile(r'(<(?:[\w.-]+:)?(?:[\w.-]+-)?(?:password(?:-value)?|passwd|secret|key|key-string|'
                r'ascii-text|hexadecimal|key-hex|token|api_key)>)[^<]*(?=</)', re.IGNORECASE),
     r'\1[REDACTED]'),
    (re.compile(r'(<community>\s*<name>)[^<]*(?=</name>)', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'((?:password|secret|token|api[_-]?key|passwd)[ \t]*[:=][ \t]*)'
                r'(?:("(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|[^\s,;"\']+))', re.IGNORECASE),
     r'\1[REDACTED]'),
    # A `community` is SNMP's wherever it is written (`set snmp community
    # public …`, `snmp-server community C0MM RO`, a stanza's or a diff's own
    # `community public {` line, an error's `community public rejected`),
    # but for a BGP community's definition: `policy-options community CUST
    # members …` names no secret.
    (re.compile(r'(\bcommunity[ \t]+)' + _VALUE + r'(?=[\s;{}]|$)(?![ \t]+members\b)', re.IGNORECASE),
     r'\1[REDACTED]'),
    # IOS: the community a trap or inform host is told, an SNMPv3 user's auth
    # and priv passwords, a wireless pre-shared key; Junos: a trap group's
    # name is its community.
    (re.compile(r'(\bsnmp-server[ \t]+host[ \t]+\S+(?:[ \t]+(?:informs|traps|vrf[ \t]+\S+|'
                r'version[ \t]+(?:1|2c|3(?:[ \t]+(?:auth|noauth|priv))?)))*[ \t]+)' + _VALUE, re.IGNORECASE),
     r'\1[REDACTED]'),
    (re.compile(r'(\bsnmp-server[ \t]+user\b[^\n]*?\bauth[ \t]+(?:md5|sha)[ \t]+)' + _VALUE, re.IGNORECASE),
     r'\1[REDACTED]'),
    (re.compile(r'(\bsnmp-server[ \t]+user\b[^\n]*?\bpriv[ \t]+(?:des|3des|aes[ \t]+\d+)[ \t]+)' + _VALUE,
                re.IGNORECASE),
     r'\1[REDACTED]'),
    (re.compile(r'(\bwpa-psk[ \t]+(?:ascii|hex)[ \t]+(?:\d+[ \t]+)?)' + _VALUE, re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(\btrap-group[ \t]+)' + _VALUE, re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(\b(?:pre-shared-key|ascii-text|hexadecimal|hex-key|key-hex)[ \t]+'
                r'(?:(?:ascii-text|hexadecimal|hex-key|key-hex)[ \t]+)?)' + _VALUE, re.IGNORECASE),
     r'\1[REDACTED]'),
]


# What a description says is no secret, whatever words it uses
# (`description "customer password reset portal"`): its value, quoted or
# one word, and a <description> element's text are kept out of the
# patterns' reach; redact_values() keeps a JSON "description" as it is.
_DESCRIPTION = re.compile(r'(\bdescription[ \t]+|<description>)'
                          r'((?<=>)[^<]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|[^\s;<"\']+)', re.IGNORECASE)
_KEPT_KEY = re.compile(r'(?:^|[-_])description$')


def redact_secrets(text: Optional[str]) -> Optional[str]:
    """Redact passwords and secrets from text."""
    if not text:
        return text
    parts = _DESCRIPTION.split(text)      # text, a description's keyword, its value, text, …
    for i in range(0, len(parts), 3):
        for pattern, repl in _REDACT_PATTERNS:
            parts[i] = pattern.sub(repl, parts[i])
    return "".join(parts)


# A JSON key whose whole value is a secret, known by its last word. A reply
# carried as data (--format json) puts "encrypted-password" (or
# "hello-authentication-key", "chap-secret") in the key and the hash in the
# value, out of reach of the text patterns above.
_SECRET_KEY = re.compile(r'(?:^|[-_])(?:password(?:-value)?|passwd|secret|key|key-string|key-hex|hexadecimal|'
                         r'ascii-text|token|community)$')


def redact_values(data):
    """redact_secrets() over a JSON-shaped value: every string in it, and the
    whole value under a key that names a secret. Lists and dicts keep their
    shape, so a --log record stays data."""
    if isinstance(data, str):
        return redact_secrets(data)
    if isinstance(data, list):
        return [redact_values(v) for v in data]
    if isinstance(data, dict):
        return {k: ("[REDACTED]" if _SECRET_KEY.search(str(k).lower()) else
                    v if _KEPT_KEY.search(str(k).lower()) else redact_values(v))
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
            entry["comment"] = redact_secrets(comment)
        if diff:
            entry["diff"] = redact_secrets(diff)
        if error:
            entry["error"] = redact_secrets(error)

        secure_append(path, json.dumps(entry) + "\n")
        return True
    except Exception as e:
        logger.warning("Failed to write audit entry to %s: %s", path, e)
        return False
