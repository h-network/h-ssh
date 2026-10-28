"""Cisco NX-OS: an IOS-shaped CLI."""

from .base import Dialect
from .ios import CLI, COMMENTS, INFORMATIONAL, REFUSED

DIALECT = Dialect("nxos", "NX-OS", "Cisco NX-OS", refused=REFUSED, informational=INFORMATIONAL, cli=CLI,
                  comments=COMMENTS)
