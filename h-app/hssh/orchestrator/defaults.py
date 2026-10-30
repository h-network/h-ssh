"""The default of every RunSpec setting; front ends and the model take theirs from here (section 3.2)."""

from __future__ import annotations

import dataclasses
import getpass
import sys
import unicodedata

from hssh.model import Credentials, EditSettings, HostKeyPolicy, PolicySettings, RunSpec, SafetySettings, Timeouts

DEFAULT_TIMEOUTS = Timeouts(connect=3, setup=30, command=20, commit=60)
DEFAULT_POLICY = PolicySettings(retries=2, retry_pause=2)
CONNECT_BACKOFF = (0.5, 1.0)
GRACE_SECONDS = 10
DEFAULT_WORKERS = 8
DEFAULT_HOST_KEY_POLICY: HostKeyPolicy = "off"
DEFAULT_PROBE = True
DEFAULT_SKIP_UNREACHABLE = False
DEFAULT_EDIT = EditSettings(apply=False)
DEFAULT_CONFIRMED_MINUTES = 10
DEFAULT_SAFETY = SafetySettings(cooldown_seconds=300, rate_limit=6)
DEFAULT_TRANSPORT = "ssh"
DEFAULT_VENDOR = "generic"
DEFAULT_STORE = "h-ssh.db"
MAX_CONFIRMED_MINUTES = 65535
MAX_COMMENT_BYTES = 512
ALIVE_SECONDS = 5
FDS_PER_WORKER = 6
FDS_PER_SESSION = 4
FDS_BASE = 32


def open_file_limit() -> int | None:
    """The process's soft open-file limit, raised towards the hard one first (no privilege needed); None when unlimited or unknown."""
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ImportError, ValueError, OSError):
        return None
    if soft != resource.RLIM_INFINITY and soft < hard:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
            soft = hard
        except (ValueError, OSError):
            pass
    return None if soft == resource.RLIM_INFINITY else soft


def fit_workers(workers: int) -> int:
    """`workers`, lowered to what the open-file limit carries at FDS_PER_WORKER each beside FDS_BASE, said once on stderr when lowered."""
    limit = open_file_limit()
    if limit is None:
        return workers
    fitted = max(1, min(workers, (limit - FDS_BASE) // FDS_PER_WORKER))
    if fitted < workers:
        print(f"workers lowered from {workers} to {fitted}: the open-file limit is {limit}", file=sys.stderr)
    return fitted


def default_username() -> str:
    return getpass.getuser()


def default_credentials() -> Credentials:
    return Credentials(username=default_username())


def check_confirmed_minutes(minutes: int) -> str | None:
    """Why `minutes` cannot arm a commit-confirmed, or None: a whole number from 1 to MAX_CONFIRMED_MINUTES."""
    if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= MAX_CONFIRMED_MINUTES:
        return f"commit-confirmed minutes must be a whole number from 1 to {MAX_CONFIRMED_MINUTES}, not {minutes!r}"
    return None


def check_comment(comment: str) -> str | None:
    """Why `comment` cannot go on a commit, or None: one non-empty line of at most MAX_COMMENT_BYTES UTF-8 bytes with no control characters."""
    if not comment.strip():
        return "the commit comment is empty"
    if len(comment.encode("utf-8", "surrogatepass")) > MAX_COMMENT_BYTES:
        return f"the commit comment is over {MAX_COMMENT_BYTES} bytes"
    for ch in comment:
        if unicodedata.category(ch) in ("Cc", "Cs"):
            return f"the commit comment has a control character (U+{ord(ch):04X}); it must be one line of plain text"
    return None


def check_edit(edit: EditSettings) -> str | None:
    """The first of the two checks above that the settings fail, or None."""
    if edit.confirmed_minutes is not None and (why := check_confirmed_minutes(edit.confirmed_minutes)):
        return why
    if edit.comment is not None and (why := check_comment(edit.comment)):
        return why
    return None


def complete(spec: RunSpec) -> RunSpec:
    """The spec with every field left None filled from the defaults above; safety and recording None stay None, meaning off."""
    return dataclasses.replace(
        spec,
        credentials=spec.credentials or default_credentials(),
        timeouts=spec.timeouts or DEFAULT_TIMEOUTS,
        workers=DEFAULT_WORKERS if spec.workers is None else spec.workers,
        host_key_policy=spec.host_key_policy or DEFAULT_HOST_KEY_POLICY,
        probe=DEFAULT_PROBE if spec.probe is None else spec.probe,
        skip_unreachable=DEFAULT_SKIP_UNREACHABLE if spec.skip_unreachable is None else spec.skip_unreachable,
        edit=spec.edit or DEFAULT_EDIT,
        policy=spec.policy or DEFAULT_POLICY,
    )
