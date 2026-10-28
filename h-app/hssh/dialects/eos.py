"""Arista EOS: an IOS-shaped CLI with its own shortcut library (eos.json,
the former commands/arista.json). Structured reads via `| json` come with
the eos@ssh driver (#83)."""

from .base import Dialect
from .ios import CLI, INFORMATIONAL, REFUSED

DIALECT = Dialect("eos", "EOS", "Arista EOS", shortcuts="eos", refused=REFUSED, informational=INFORMATIONAL, cli=CLI)
