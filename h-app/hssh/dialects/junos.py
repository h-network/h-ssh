import re

from hssh.dialects.base import Dialect
from hssh.dialects.generic import GenericDialect, _VALUE
from hssh.model import CommitStatus


SET_PREFIX_VERBS = (
    "set ", "delete ", "activate ", "deactivate ", "insert ",
    "rename ", "copy ", "annotate ", "protect ", "unprotect ",
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")
_PENDING = re.compile(r"commit confirmed, rollback in (\d+) minutes?", re.I)


class JunosDialect(GenericDialect):
    prompt_pattern = re.compile(r'[\w\-\.]+@[\w\-\.]+[>%#]\s*$')
    prompt_name_pattern = re.compile(r'^([\w\-\.]+@[\w\-\.]+)')
    prompt_tail_pattern = re.compile(r'[>%#]\s*$')
    context_pattern = re.compile(r'^\s*(?:(?:\{\w+(?::\w+)?\})?\[edit[^\]]*\]|# commit confirmed will be rolled back in \d+ minutes?)\s*$')
    refusal_patterns = (
        re.compile(
            r'^\s*(error:|syntax error|missing argument|unknown command|commit failed)',
            re.M | re.I,
        ),
    )
    config_enter_command = "configure exclusive"
    config_exit_command = "exit"
    commit_command = "commit"
    diff_command = "show | compare"
    history_command = "show system commit"
    # Discard only this session's uncommitted candidate on close.
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
        if confirmed_minutes:
            line += f" confirmed {confirmed_minutes}"
        if comment:
            line += f' comment "{comment}"'
        return line

    def parse_commit_history(self, output: str) -> CommitStatus:
        lines = [ln for ln in output.splitlines() if ln.strip()]
        newest = lines[0].strip() if lines else ""
        pending = _PENDING.search(newest) or (_PENDING.search(lines[1]) if len(lines) > 1 else None)
        return CommitStatus(pending is not None, int(pending.group(1)) if pending else None, newest)

    def encode_line(self, text: str) -> bytes:
        return text.replace("?", "\x16?").encode("utf-8") + b"\n"


DIALECT: Dialect = JunosDialect()
