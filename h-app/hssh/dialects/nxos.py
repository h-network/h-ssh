"""Cisco NX-OS: an IOS-shaped CLI."""

from .base import Dialect
from .ios import CLI, REFUSED

DIALECT = Dialect("nxos", "NX-OS", "Cisco NX-OS", refused=REFUSED, cli=CLI)
