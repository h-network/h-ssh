"""No vendor knowledge: a line in, its text out.

Two things it still knows, because the plain `ssh`, `openssh` and `telnet`
transports always behaved this way: a refusal is a line starting with
`error:` (Junos) or `% ` (IOS, EOS, NX-OS), and on a transport that types at
a CLI the prompt is IOS-shaped. Its comments are h-ssh's own `#` lines: a
`!` line is a line, sent as written, typed at that prompt too (#142)."""

import re

from .base import Dialect
from .ios import CLI

REFUSED = re.compile(r"^\s*(error:|% )", re.M)

DIALECT = Dialect("none", "generic", "no vendor knowledge: a line in, its text out",
                  shortcuts="none", refused=REFUSED, cli=CLI)
