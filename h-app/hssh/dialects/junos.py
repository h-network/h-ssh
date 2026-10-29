import re

from hssh.dialects.base import Dialect
from hssh.dialects.generic import GenericDialect


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


DIALECT: Dialect = JunosDialect()
