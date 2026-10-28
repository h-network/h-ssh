"""What a dialect is made of.

A dialect is what the device speaks: the shortcut library it ships, the guard
an edit payload must pass, which commands are reads, how its CLI refuses a
line, how its CLI looks to a transport that types at it, and how it announces
a pending commit-confirmed. Dialects know nothing about connections; a
transport that needs one is handed it by the driver (today through the
vendor_hint, until #83 passes the object).

This package imports nothing from hssh.drivers, hssh.core, hssh.cli or
hssh.runner. The registry in hssh.drivers imports it.
"""

import re
from dataclasses import dataclass
from typing import Callable, Optional, Tuple


def is_read(command: str) -> bool:
    """The default rule: a `show …` command or a `get-*` RPC name reads;
    anything else (`request …`, `clear …`, `restart …`, a request-* RPC) acts
    on the device and is sent once, never re-sent by a retry."""
    text = command.strip().lower()
    return text.startswith("show ") or text.startswith("get") or text == "show"


@dataclass(frozen=True)
class CliSyntax:
    """How the dialect's CLI looks to a transport that types at it.

    `prompt` matches a line that is the device waiting for input; after login
    the transport narrows it to this device's own prompt: `prompt_name` finds
    the name in the first prompt seen (group 1, where the prompt line
    starts), `prompt_tail` is what may follow it, and the narrowed prompt is
    the whole line from its start. A prompt `prompt_name` cannot name leaves
    `prompt`, which need only end the line.
    `config_enter`/`config_exit` bracket an edit. A dialect with a
    candidate configuration also has `compare` (the diff), `discard` and
    `commit`; one without applies each line as typed. `context` matches a
    line the CLI prints with its prompt rather than as part of a reply
    (Junos's `[edit system]` banner in configuration mode, `{master}[edit]`
    with two routing engines, and the `# commit confirmed will be rolled
    back in 4 minutes` above it while a timer runs): every such line at the
    end of a reply is the prompt's, and a reply of nothing but the echo,
    those lines and the prompt (a line of an edit) is not waited on for
    more."""
    prompt: re.Pattern
    prompt_name: re.Pattern
    prompt_tail: str
    config_enter: str
    config_exit: str
    compare: Optional[str] = None
    discard: Optional[str] = None
    commit: Optional[str] = None
    context: Optional[re.Pattern] = None

    @property
    def has_candidate(self) -> bool:
        return self.commit is not None

    def __post_init__(self):
        if self.commit is not None and (self.compare is None or self.discard is None):
            raise ValueError("a CLI that commits needs compare and discard too")


@dataclass(frozen=True)
class Dialect:
    name: str                 # the half of a driver name before the @
    title: str                # as printed to the operator ("Junos", "IOS")
    description: str
    shortcuts: Optional[str] = None      # the shipped library: a stem (hssh/dialects/<stem>.json) or a path to a .json
    check_edit: Optional[Callable[[str, bool], Tuple[bool, str]]] = None
    is_read: Callable[[str], bool] = is_read
    refused: Optional[re.Pattern] = None   # a line in which the CLI refused the command (MULTILINE)
    # A line in which the CLI took the command and warned about it, though
    # `refused` may match it (MULTILINE): no refusal, and a lines edit goes
    # on and reports it with its result. None: every line `refused` matches
    # is one.
    informational: Optional[re.Pattern] = None
    cli: Optional[CliSyntax] = None
    commit_pending: Optional[re.Pattern] = None   # group 1: minutes left on a pending commit-confirmed
