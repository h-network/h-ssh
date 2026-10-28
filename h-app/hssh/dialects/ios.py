"""Cisco IOS and IOS-XE. Also the shape NX-OS, EOS and the `none` dialect
borrow for their CLI: `Router>`, `Router#`, `Router(config-if)#`, a refusal
that starts with `% `. NX-OS and EOS take its warnings too."""

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

# What IOS says, a `%` first, of a line it took: a warning (`%Warning:
# portfast should only be enabled on ports connected to a single host`,
# `% Warning: use /31 mask on non point-to-point interface cautiously`),
# or the note that a VRF enabled on an interface removed its addresses
# (`% Interface Gi0/1 IPv4 disabled and address(es) removed due to
# enabling VRF CUST`), which the payload's next line puts back. Neither is
# a refusal: a lines edit goes on past it and reports it (#142).
INFORMATIONAL = re.compile(r"^\s*%\s*(warning\b|interface \S+ .*\bremoved due to (en|dis)abling vrf\b)",
                           re.M | re.I)

DIALECT = Dialect("ios", "IOS", "Cisco IOS and IOS-XE", refused=REFUSED, informational=INFORMATIONAL, cli=CLI)
