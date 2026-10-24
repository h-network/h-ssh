"""Vendor-specific implementations."""

from . import junos
from . import generic
from . import telnet
from . import openssh

VENDORS = {
    "junos": junos,
    "ssh": generic,
    "openssh": openssh,
    "telnet": telnet,
    "telnet-ios": telnet,
    "telnet-junos": telnet,
    "telnet-arista": telnet,
    "telnet-nxos": telnet,
}

__all__ = ['junos', 'generic', 'openssh', 'telnet', 'VENDORS', 'RETIRED']

# Vendors h-ssh used to speak to and no longer does, with the one line a target
# that still names them gets. h-ssh is SSH, NETCONF over SSH and telnet: no
# HTTP transports (2026-10-24).
RETIRED = {
    "arista": "vendor 'arista' (eAPI over HTTPS) is no longer supported; EOS devices use the "
              "ssh or openssh transport (eos@ssh once dialects land), or telnet-arista",
}


def get(name: str):
    """Get vendor module by name."""
    if name in RETIRED:
        raise ValueError(RETIRED[name])
    if name not in VENDORS:
        raise ValueError(f"Unknown vendor: {name}. Available: {', '.join(VENDORS.keys())}")
    return VENDORS[name]
