import re

from hssh.dialects.base import Dialect
from hssh.model import CommitStatus, Fault, FaultKind


_VALUE = r'("(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|[^\s;"\']+)'
_SECRET_WORDS = (r'password(?:-value)?|passwd|secret|key|key-string|key-hex|hexadecimal|'
                 r'ascii-text|token|community')


class GenericDialect(Dialect):
    prompt_pattern: re.Pattern[str] = re.compile(r'[\w\-\.]+(\([^\s()]+\))?[>#]\s*$')
    prompt_name_pattern: re.Pattern[str] = re.compile(r'^([\w\-\.]+)')
    prompt_tail_pattern: re.Pattern[str] = re.compile(r'(\([^\s()]+\))?[>#]\s*$')
    context_pattern: re.Pattern[str] | None = None
    paging_off_command: str | None = None
    pager_pattern: re.Pattern[str] | None = re.compile(r'^\s*(?:--More--|---?\(more(?: \d+%)?\)---?)\s*$', re.I)
    pager_reply: bytes = b" "
    refusal_patterns: tuple[re.Pattern[str], ...] = (re.compile(r"^\s*(error:|% )", re.M),)
    warning_patterns: tuple[re.Pattern[str], ...] = ()
    config_enter_command: str | None = "configure terminal"
    config_exit_command: str | None = "end"
    commit_command: str | None = None
    diff_command: str | None = None
    history_command: str | None = None
    discard_commands: tuple[str, ...] = ()
    has_candidate: bool = False
    redaction_patterns: tuple[re.Pattern[str], ...] = (
        re.compile(r'((?:encrypted-password|plain-text-password(?:-value)?|password(?:-value)?|secret|'
                   r'authentication-key|message-digest-key|md5-key|privacy-key|key-string)[ \t]+'
                   r'(?:(?:\d+|md5|sha512|sha256|sha1|sha|value|type[ \t]+\S+|hmac-\S+)[ \t]+)*)' + _VALUE,
                   re.IGNORECASE),
        re.compile(r'((?:(?<![\w-])(?:md5|sha\d*|hmac-\S+)[ \t]+\d+[ \t]+key[ \t]+|(?<![\w-])key[ \t]+\d+[ \t]+|'
                   r'\bisakmp[ \t]+key[ \t]+|'
                   r'\b(?:tacacs-server|radius-server)\b[^\n]*?\bkey[ \t]+(?:\d+[ \t]+)?))' + _VALUE, re.IGNORECASE),
        re.compile(r'(<(?:[\w.-]+:)?(?:[\w.-]+-)?(?:password(?:-value)?|passwd|secret|key|key-string|'
                   r'ascii-text|hexadecimal|key-hex|token|api_key)>)[^<]*(?=</)', re.IGNORECASE),
        re.compile(r'(<community>\s*<name>)[^<]*(?=</name>)', re.IGNORECASE),
        re.compile(r'("(?:[^"\\\n]*[-_])?(?:' + _SECRET_WORDS + r')"[ \t]*:[ \t]*)'
                   r'(?:"(?:\\.|[^"\\\n])*"|[^\s,{}\[\]"]+)', re.IGNORECASE),
        re.compile(r'((?:password|secret|token|api[_-]?key|passwd)[ \t]*[:=][ \t]*)'
                   r'(?:("(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|[^\s,;"\']+))', re.IGNORECASE),
        re.compile(r'(\bcommunity[ \t]+)' + _VALUE + r'(?=[\s;{}]|$)(?![ \t]+members\b)', re.IGNORECASE),
        re.compile(r'(\b(?:pre-shared-key|ascii-text|hexadecimal|hex-key|key-hex)[ \t]+'
                   r'(?:(?:ascii-text|hexadecimal|hex-key|key-hex)[ \t]+)?)' + _VALUE, re.IGNORECASE),
    )
    comment_prefixes: tuple[str, ...] = ("#",)

    def check_edit(self, lines: list[str]) -> str | None:
        if not any(line.strip() and not line.lstrip().startswith(self.comment_prefixes) for line in lines):
            return "configuration payload contains no commands"
        return None

    def is_read(self, command: str) -> bool:
        text = command.strip().lower()
        return text.startswith("show ") or text.startswith("get") or text == "show"

    def build_commit(self, confirmed_minutes: int | None, comment: str | None) -> str:
        if self.commit_command is None:
            raise Fault(FaultKind.UNSUPPORTED, "this dialect has no candidate configuration to commit", False)
        return self.commit_command

    def parse_commit_history(self, output: str) -> CommitStatus:
        return CommitStatus(False, None, output.strip().splitlines()[0] if output.strip() else "")

    def encode_line(self, text: str) -> bytes:
        return text.encode("utf-8") + b"\n"


DIALECT: Dialect = GenericDialect()
