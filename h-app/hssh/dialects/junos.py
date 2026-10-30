import re

from hssh.dialects.base import Dialect
from hssh.dialects.generic import GenericDialect


SET_PREFIX_VERBS = (
    "set ", "delete ", "activate ", "deactivate ", "insert ",
    "rename ", "copy ", "annotate ", "protect ", "unprotect ",
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")


class JunosDialect(GenericDialect):
    prompt_pattern = re.compile(r'[\w\-\.]+@[\w\-\.]+[>%#]\s*$')
    refusal_patterns = (
        re.compile(
            r'^\s*(error:|syntax error|missing argument|unknown command|commit failed)',
            re.M | re.I,
        ),
    )
    config_enter_command = "configure exclusive"
    config_exit_command = "exit"
    commit_command = "commit"
    # Discard only this session's uncommitted candidate on close.
    discard_commands = ("rollback 0",)
    has_candidate = True

    def check_edit(self, lines: list[str]) -> str | None:
        refusal = super().check_edit(lines)
        if refusal:
            return refusal
        for number, raw in enumerate(lines, 1):
            line = raw.strip()
            if line.startswith(self.comment_prefixes):
                continue
            if _CONTROL.search(raw):
                return f"line {number}: control characters and Tab are not permitted: {raw!r}"
            if not line:
                continue
            word = line.split()[0].rstrip(";")
            if len(word) >= 3 and "commit".startswith(word):
                return f"line {number}: commit is not permitted in configuration: {line!r}"
            if not line.startswith(SET_PREFIX_VERBS):
                return f"line {number}: invalid Junos set command: {line!r}"
        return None


DIALECT: Dialect = JunosDialect()
