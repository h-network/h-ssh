"""What a target name resolves to: a dialect on a transport, with a capability set.

A *dialect* is what the device speaks (Junos, IOS, NX-OS, EOS, or nothing in
particular). A *transport* is how h-ssh reaches it (NETCONF over SSH, the
paramiko SSH client, the OpenSSH client, telnet). A *driver* is one dialect on
one transport and says what it can be asked (`supports`); the runner consults
that set, never the module, before it touches a device.

Nothing here opens a connection. A transport's module (under hssh.transports)
does the work for every dialect on it; the registry in hssh.drivers resolves
a driver to that module. Dialects live in hssh.dialects; `Dialect` is
re-exported here for the registry.
"""

from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple

from ..dialects.base import CliSyntax, Dialect  # noqa: F401  (re-exported)

# A capability is a word the runner asks for. The first group names a function
# the module has: the contract (hssh.drivers.contract) checks it exists and
# takes what the runner passes. The second group is policy enforced by name,
# because a module that accepts `dry_run` may still only pretend: a transport
# that cannot diff a candidate cannot discard it, and must refuse rather than
# do something weaker.
METHOD_CAPABILITIES = frozenset({
    "show", "show_batch", "show_structured", "rpc",
    "edit", "rollback", "confirm", "commit_status",
})
POLICY_CAPABILITIES = frozenset({"dry_run", "commit_confirmed", "comment"})
CAPABILITIES = METHOD_CAPABILITIES | POLICY_CAPABILITIES


@dataclass(frozen=True)
class Transport:
    """How a device is reached."""
    name: str
    description: str
    module: str                  # dotted path of the module that does the work (show, edit, …)
    install: str                 # what is missing when that module says AVAILABLE = False
    default_port: int
    formats: Tuple[str, ...] = ("text",)   # device-side formats it can ask for (--format)
    banner: Optional[bytes] = b"SSH-"   # what the port must say to be a device (pre-flight); None: open is enough
    pooled: bool = False         # sessions can outlive one command (hssh.pool)
    frozen: bool = False         # kept working, gets nothing new


@dataclass(frozen=True)
class Driver:
    """One dialect on one transport."""
    dialect: Dialect
    transport: Transport
    supports: FrozenSet[str]
    # Other names a target may carry for this driver: the vendor names h-ssh
    # has always taken (`junos`, `ssh`, `telnet-ios`), kept for every file
    # and script that uses them.
    aliases: Tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return f"{self.dialect.name}@{self.transport.name}"

    def __post_init__(self):
        unknown = self.supports - CAPABILITIES
        if unknown:
            raise ValueError(f"{self.name}: unknown capabilities {sorted(unknown)}")
        if (self.supports & POLICY_CAPABILITIES) and "edit" not in self.supports:
            raise ValueError(f"{self.name}: dry_run/commit_confirmed/comment need edit")
        if "rpc" in self.supports and self.transport.formats == ("text",):
            raise ValueError(f"{self.name}: rpc needs a transport with a structured format")
