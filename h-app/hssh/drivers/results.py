"""What a driver hands back, typed.

Until now every driver returned text, and the runner and the CLI read the
verdict back out of it ("COMMIT OK", "DIFF:", a JSON array for a batch). The
types here carry the verdict as fields. Each one is also still its old
value: EditResult is the text it renders, BatchResult and CommitStatus are
the lists they always were, so every caller that printed, compared or
indexed the old value keeps working, library scripts and test doubles
included. A module that still returns the plain value is wrapped by the
runner (`as_edit`, `as_batch`, `as_commits`), the one place that parses.
"""

import re
from typing import Any, Iterable, List, Optional

# status -> what an edit did
COMMITTED = "committed"          # COMMIT OK
CONFIRMED = "confirmed"          # COMMIT CONFIRMED (n minutes): a rollback timer is armed
CONFIRMED_OK = "confirmed-ok"    # a pending commit-confirmed was confirmed
DRY_RUN = "dry-run"              # the candidate was checked and discarded
NO_CHANGES = "no-changes"        # the candidate equalled the running config
APPLIED = "applied"              # lines applied as typed, no candidate (ssh, openssh, telnet-ios)

EDIT_STATUSES = (COMMITTED, CONFIRMED, CONFIRMED_OK, DRY_RUN, NO_CHANGES, APPLIED)

_LABEL = re.compile(r"(ROLLBACK \d+: )?(.*)", re.S)
_MINUTES = re.compile(r"COMMIT CONFIRMED \((\d+) minutes\)")


def _render(status, diff, minutes, label, note, message) -> str:
    if status == APPLIED:
        return message
    if status == NO_CHANGES:
        return f"{label}NO CHANGES"
    if status == CONFIRMED_OK:
        return "COMMIT CONFIRMED OK"
    if status == DRY_RUN:
        head = "DRY-RUN" + (f": {note}" if note else "")
    elif status == COMMITTED:
        head = "COMMIT OK"
    elif status == CONFIRMED:
        head = f"COMMIT CONFIRMED ({minutes} minutes)"
    else:
        raise ValueError(f"unknown edit status {status!r}")
    return f"{label}{head}\n\nDIFF:\n{diff}"


class EditResult(str):
    """The outcome of an edit, a rollback or a confirm. It is the text the
    operator sees, and it knows what it says: `status`, `diff`, `minutes`
    (of a commit confirmed), `label` ("ROLLBACK 3: " on a rollback), `note`
    (what a dry run checked), `message` (an APPLIED result's device text).
    Failures are exceptions, so an EditResult is always ok."""

    status: str
    diff: str
    minutes: Optional[int]
    label: str
    note: str
    message: str

    def __new__(cls, status: str, diff: str = "", minutes: Optional[int] = None, label: str = "",
                note: str = "", message: str = ""):
        if status not in EDIT_STATUSES:
            raise ValueError(f"unknown edit status {status!r}")
        if status == CONFIRMED and minutes is None:
            raise ValueError("a confirmed commit has minutes")
        self = super().__new__(cls, _render(status, diff, minutes, label, note, message))
        self.status, self.diff, self.minutes = status, diff, minutes
        self.label, self.note, self.message = label, note, message
        return self

    @property
    def ok(self) -> bool:
        return True

    @property
    def pending(self) -> bool:
        """A rollback timer is running on the device until someone confirms."""
        return self.status == CONFIRMED

    @classmethod
    def parse(cls, text: str) -> "EditResult":
        """An EditResult from the text a driver used to return. The result is
        always the same text: a verdict is recognised only when rendering it
        back gives the text byte for byte; anything else is APPLIED with the
        text as message."""
        parsed = cls._parse(text)
        return parsed if parsed is not None and parsed == text else cls(APPLIED, message=text)

    @classmethod
    def _parse(cls, text: str):
        label, rest = _LABEL.match(text).groups()
        label = label or ""
        head, found, diff = rest.partition("\n\nDIFF:\n")
        if head == "NO CHANGES" and not found:
            return cls(NO_CHANGES, label=label)
        if head == "COMMIT CONFIRMED OK" and not label and not found:
            return cls(CONFIRMED_OK)
        if not found:
            return None
        if head == "COMMIT OK":
            return cls(COMMITTED, diff=diff, label=label)
        m = _MINUTES.fullmatch(head)
        if m:
            return cls(CONFIRMED, diff=diff, minutes=int(m.group(1)), label=label)
        if head == "DRY-RUN":
            return cls(DRY_RUN, diff=diff, label=label)
        if head.startswith("DRY-RUN: ") and head[len("DRY-RUN: "):].strip() == head[len("DRY-RUN: "):]:
            return cls(DRY_RUN, diff=diff, label=label, note=head[len("DRY-RUN: "):])
        return None

    def __reduce__(self):
        # pickle and copy rebuild from the fields, not from the text
        return (EditResult, (self.status, self.diff, self.minutes, self.label, self.note, self.message))

    def __repr__(self) -> str:
        return f"EditResult({self.status!r}, diff={self.diff!r}, minutes={self.minutes!r}, label={self.label!r})"


class BatchResult(list):
    """The per-command results of a batch, in order: each a dict with
    `command`, `ok` and `output` (or `error`), as the JSON output shows them."""

    @property
    def ok(self) -> bool:
        return all(r.get("ok") for r in self)

    @property
    def first_error(self) -> Optional[str]:
        for r in self:
            if not r.get("ok"):
                return r.get("error", "unknown error")
        return None

    def to_list(self) -> List[dict]:
        """A copy the caller may edit (the CLI strips echoes for display) without touching the result."""
        return [dict(r) for r in self]


class CommitStatus(list):
    """`show system commit` as data: entries newest first, each with seq, user,
    client, time, epoch, comment, note and pending_rollback_minutes (set on
    the latest entry while a commit confirmed waits)."""

    @property
    def pending(self) -> Optional[dict]:
        for e in self:
            if e.get("pending_rollback_minutes") is not None:
                return e
        return None

    def to_list(self) -> List[dict]:
        return [dict(r) for r in self]


def as_edit(value: Any) -> EditResult:
    """The driver's edit result, typed: as returned, or parsed from the text
    a module that predates the types (or a test double) still returns."""
    if isinstance(value, EditResult):
        return value
    if not isinstance(value, str):
        raise TypeError(f"the driver returned {type(value).__name__}, not an edit result")
    return EditResult.parse(value)


def as_batch(value: Iterable) -> BatchResult:
    return value if isinstance(value, BatchResult) else BatchResult(value)


def as_commits(value: Iterable) -> CommitStatus:
    return value if isinstance(value, CommitStatus) else CommitStatus(value)
