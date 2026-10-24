"""The dialects h-ssh speaks. Each module exports DIALECT; the shortcut
library a dialect ships sits next to it as <name>.json. The registry in
hssh.drivers pairs them with transports."""

from .base import CliSyntax, Dialect, is_read
from . import eos, ios, junos, none, nxos

ALL = (junos.DIALECT, ios.DIALECT, nxos.DIALECT, eos.DIALECT, none.DIALECT)

__all__ = ["CliSyntax", "Dialect", "is_read", "ALL", "junos", "ios", "nxos", "eos", "none"]
