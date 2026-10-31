import re

from hssh.dialects.base import Dialect
from hssh.dialects.generic import GenericDialect, _CONTROL, _VALUE
from hssh.model import CommitStatus, Fault, FaultKind


SET_PREFIX_VERBS = (
    "set ", "delete ", "activate ", "deactivate ", "insert ",
    "rename ", "copy ", "annotate ", "protect ", "unprotect ",
)
_PENDING = re.compile(r"\bcommit confirmed, rollback in (\d+)\s*min(?:ute)?s?\b", re.I)


class JunosDialect(GenericDialect):
    prompt_pattern = re.compile(r'^[\w\-\.]+@[\w\-\.]+[>%#]\s*$')
    prompt_name_pattern = re.compile(r'^([\w\-\.]+@[\w\-\.]+)')
    prompt_tail_pattern = re.compile(r'[>%#]\s*$')
    pager_pattern = re.compile(r'^\s*---?\(more(?: \d+%)?\)---?\s*$', re.I)
    context_pattern = re.compile(r'^\s*(?:(?:\{\w+(?::\w+)?\})?\[edit[^\]]*\]|# commit confirmed will be rolled back in \d+ minutes?)\s*$')
    refusal_patterns = (
        re.compile(
            r'^\s*(error:|syntax error|missing argument|unknown command|commit failed)',
            re.M | re.I,
        ),
    )
    warning_patterns = (re.compile(r'^\s*warning:\s*statement not found\b', re.M | re.I),)
    config_enter_command = "configure exclusive"
    config_exit_command = "exit"
    commit_command = "commit"
    diff_command = "show | compare"
    history_command = "show system commit"
    config_history_command = "run show system commit"
    discard_commands = ("rollback 0",)
    has_candidate = True
    redaction_patterns = (
        re.compile(r'^([^\n]*?)' + _VALUE + r'(;?[ \t]*## SECRET-DATA)', re.MULTILINE),
    ) + GenericDialect.redaction_patterns + (
        re.compile(r'(\btrap-group[ \t]+)' + _VALUE, re.IGNORECASE),
    )

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

    def build_commit(self, confirmed_minutes: int | None, comment: str | None) -> str:
        line = "commit"
        if confirmed_minutes is not None:
            if type(confirmed_minutes) is not int or not 1 <= confirmed_minutes <= 65535:
                raise Fault(FaultKind.LOCAL, "commit-confirmed minutes must be an integer from 1 to 65535", False)
            line += f" confirmed {confirmed_minutes}"
        if comment is not None:
            if not comment.strip() or _CONTROL.search(comment) or '"' in comment:
                raise Fault(FaultKind.LOCAL, "a CLI commit comment must be nonempty text without controls, Tab or double quotes", False)
            if len(comment.encode("utf-8")) > 512:
                raise Fault(FaultKind.LOCAL, "the commit comment is over 512 UTF-8 bytes", False)
            comment = comment.replace("\\", "\\\\")
            line += f' comment "{comment}"'
        return line

    def parse_commit_history(self, output: str) -> CommitStatus:
        newest = next((line.strip() for line in output.splitlines() if re.match(r"^\s*0\s+", line)), "")
        pending = _PENDING.search(newest)
        return CommitStatus(pending is not None, int(pending.group(1)) if pending else None, newest)

    def encode_line(self, text: str) -> bytes:
        return text.replace("?", "\x16?").encode("utf-8") + b"\n"


DIALECT: Dialect = JunosDialect()
