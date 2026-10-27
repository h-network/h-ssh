"""Cisco IOS and IOS-XE. Also the shape NX-OS, EOS and the `none` dialect
borrow for their CLI: `Router>`, `Router#`, `Router(config-if)#`, a refusal
that starts with `% `."""

import re

from .base import CliSyntax, Dialect

CLI = CliSyntax(
    prompt=re.compile(r'[\w\-\.]+(\([^\s()]+\))?[>#]\s*$'),
    prompt_name=re.compile(r'^([\w\-\.]+)(\([^\s()]+\))?[>#]\s*$'),
    prompt_tail=r'(\([^\s()]+\))?[>#]\s*$',
    config_enter="configure terminal",
    config_exit="end",
)

REFUSED = re.compile(r"^\s*% ", re.M)

DIALECT = Dialect("ios", "IOS", "Cisco IOS and IOS-XE", refused=REFUSED, cli=CLI)
