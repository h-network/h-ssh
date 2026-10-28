"""Junos: set syntax, a candidate configuration, commit confirmed."""

import re
from typing import Tuple

from .base import CliSyntax, Dialect

# --- the edit guard -----------------------------------------------------------

SET_PREFIX_VERBS = (
    "set ",
    "delete ",
    "activate ",
    "deactivate ",
    "insert ",
    "rename ",
    "copy ",
    "annotate ",
    "protect ",
    "unprotect ",
)
SET_EXACT_VERBS = ("commit", "commit;")


def check_edit(payload: str, allow_commit: bool = True) -> Tuple[bool, str]:
    """Every non-empty, non-comment line must start with a set verb.

    Comments (#) and blank lines pass. A single standalone `commit` or
    `commit;` passes when allow_commit is True (it confirms a pending
    commit-confirmed) and never mixes with set lines; with allow_commit False
    (-eD/-eB config files) it is refused. Returns (is_valid, why_not).
    """
    meaningful = []
    for idx, raw_line in enumerate(payload.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        meaningful.append((idx, line))

    if not meaningful:
        return False, "configuration payload contains no commands"

    if len(meaningful) == 1:
        idx, line = meaningful[0]
        if line in SET_EXACT_VERBS:
            if not allow_commit:
                return False, f"line {idx}: 'commit' is not permitted in configuration files (-eD/-eB)"
            return True, ""

    for idx, line in meaningful:
        if line in SET_EXACT_VERBS:
            return False, f"line {idx}: 'commit' cannot be combined with set commands (standalone only)"
        # Junos CLI requires lowercase set verbs (reject uppercase like 'SET')
        if not any(line.startswith(verb) for verb in SET_PREFIX_VERBS):
            return False, (f"line {idx}: invalid Junos set command {line!r} "
                           "(must start with a valid set verb such as 'set', 'delete', 'activate', etc.)")

    return True, ""


# --- how the CLI answers --------------------------------------------------------

# A Junos CLI error, matched at line start on the reply without the echoed
# command: a description that says "error-disabled" is not one.
REFUSED = re.compile(
    r'^\s*(error:|syntax error|missing argument|unknown command|commit failed)',
    re.MULTILINE | re.IGNORECASE)

# The note `show system commit` puts on a commit confirmed that still waits:
# "commit confirmed, rollback in 5mins". Group 1 is the minutes left.
COMMIT_PENDING = re.compile(r"rollback in (\d+)\s*min", re.I)

CLI = CliSyntax(
    prompt=re.compile(r'[\w\-\.]+@[\w\-\.]+[>%#]\s*$'),
    prompt_name=re.compile(r'([\w\-\.]+@[\w\-\.]+)[>%#]\s*$'),
    prompt_tail=r'[>%#]\s*$',
    # Exclusive mode keeps the candidate to this session, as the NETCONF
    # driver's lock does: commit and rollback 0 never touch another user's
    # pending changes, and the device refuses entry while someone else holds
    # the lock.
    config_enter="configure exclusive",
    config_exit="exit",
    compare="show | compare",
    discard="rollback 0",
    commit="commit",
    # "[edit]" / "[edit system]" before the configuration-mode prompt belongs
    # to the prompt: without this, an empty `show | compare` read as a diff.
    # A router with two routing engines (a virtual chassis, a cluster) puts
    # the engine's role in front, "{master}[edit]", and while a commit
    # confirmed waits the CLI says so above it, "# commit confirmed will be
    # rolled back in 4 minutes": the engine waits after a reply with output
    # of its own, and neither is one (#141). Read as a diff, the note made an
    # empty compare commit, which confirms the pending timer.
    context=re.compile(r"^((\{[^{}]*\})?\[edit[^\]]*\]|# commit confirmed will be rolled back\b.*?)\s*$"),
)

DIALECT = Dialect("junos", "Junos", "Junos: set syntax, candidate configuration, commit confirmed",
                  shortcuts="junos", check_edit=check_edit, refused=REFUSED, cli=CLI,
                  commit_pending=COMMIT_PENDING)
