import re

from hssh.dialects.base import Dialect


class GenericDialect(Dialect):
    prompt_pattern: re.Pattern[str] = re.compile(r'[\w\-\.]+(\([^\s()]+\))?[>#]\s*$')
    paging_off_command: str | None = None
    refusal_patterns: tuple[re.Pattern[str], ...] = (re.compile(r"^\s*(error:|% )", re.M),)
    warning_patterns: tuple[re.Pattern[str], ...] = ()
    config_enter_command: str | None = "configure terminal"
    config_exit_command: str | None = "end"
    commit_command: str | None = None
    discard_commands: tuple[str, ...] = ()
    has_candidate: bool = False
    redaction_patterns: tuple[re.Pattern[str], ...] = ()
    comment_prefixes: tuple[str, ...] = ("#",)

    def check_edit(self, lines: list[str]) -> str | None:
        if not any(line.strip() and not line.lstrip().startswith(self.comment_prefixes) for line in lines):
            return "configuration payload contains no commands"
        return None

    def is_read(self, command: str) -> bool:
        text = command.strip().lower()
        return text.startswith("show ") or text.startswith("get") or text == "show"


DIALECT: Dialect = GenericDialect()
