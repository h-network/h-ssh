"""The dialect interface: one vendor's CLI behaviour as data and small parsing hooks (section 3.5)."""

from __future__ import annotations

import re
from typing import Protocol

from hssh.model import CommitStatus


class Dialect(Protocol):
    """Vendor behaviour read by the CLI engine; a communicator receives its dialect when it is constructed, and the Driver holds both."""

    prompt_pattern: re.Pattern[str]
    prompt_name_pattern: re.Pattern[str]
    prompt_tail_pattern: re.Pattern[str]
    context_pattern: re.Pattern[str] | None
    paging_off_command: str | None
    pager_pattern: re.Pattern[str] | None
    pager_reply: bytes
    refusal_patterns: tuple[re.Pattern[str], ...]
    warning_patterns: tuple[re.Pattern[str], ...]
    config_enter_command: str | None
    config_exit_command: str | None
    commit_command: str | None
    diff_command: str | None
    history_command: str | None
    config_history_command: str | None
    discard_commands: tuple[str, ...]
    has_candidate: bool
    redaction_patterns: tuple[re.Pattern[str], ...]
    comment_prefixes: tuple[str, ...]

    def is_read(self, command: str) -> bool: ...

    def check_edit(self, lines: list[str]) -> str | None:
        """The refusal text for a payload the dialect will not send, or None when it is fine."""
        ...

    def build_commit(self, confirmed_minutes: int | None, comment: str | None) -> str: ...

    def parse_commit_history(self, output: str) -> CommitStatus: ...

    def encode_line(self, text: str) -> bytes:
        """The bytes to type for one validated line, newline included."""
        ...
