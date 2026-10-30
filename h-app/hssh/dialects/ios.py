import re

from hssh.dialects.base import Dialect
from hssh.dialects.generic import GenericDialect


class IosDialect(GenericDialect):
    comment_prefixes = ("#", "!")
    redaction_patterns: tuple[re.Pattern[str], ...] = ()
    refusal_patterns = (
        re.compile(r"^\s*(% |%(?![A-Z0-9_]+(?:-[A-Z0-9_]+)*-\d+-[A-Z0-9_]+:)\S|ERROR:)", re.M),
    )
    # Warnings take precedence over the broader refusal pattern.
    warning_patterns = (
        re.compile(
            r"^\s*%\s*(warning\b|portfast (has been|will be) configured\b"
            r"|default route without gateway\b|command accepted but obsolete\b"
            r"|the key modulus size is \d+ bits|generating \d+ bit rsa keys\b"
            r"|applying vlan changes\b"
            r"|interface \S+ .*\bremoved due to (en|dis)abling vrf\b)",
            re.M | re.I,
        ),
    )


DIALECT: Dialect = IosDialect()
