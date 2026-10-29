"""The dialect interface: one vendor's CLI behaviour as data and small parsing hooks (section 3.5)."""

from __future__ import annotations

import re
from typing import Protocol


class Dialect(Protocol):
    """Vendor behaviour read by the CLI engine; a communicator receives its dialect when it is constructed, and the Driver holds both."""

    prompt_pattern: re.Pattern[str]
    paging_off_command: str | None
    refusal_patterns: tuple[re.Pattern[str], ...]
    warning_patterns: tuple[re.Pattern[str], ...]
    config_enter_command: str | None
    config_exit_command: str | None
    commit_command: str | None
    discard_commands: tuple[str, ...]
    has_candidate: bool
    redaction_patterns: tuple[re.Pattern[str], ...]

    def is_read(self, command: str) -> bool: ...
