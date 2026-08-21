"""Vendor-specific implementations."""

from . import junos
from . import arista
from . import generic
from . import telnet
from . import openssh

VENDORS = {
    "junos": junos,
    "arista": arista,
    "ssh": generic,
    "openssh": openssh,
    "telnet": telnet,
    "telnet-ios": telnet,
    "telnet-junos": telnet,
    "telnet-arista": telnet,
    "telnet-nxos": telnet,
}

__all__ = ['junos', 'arista', 'generic', 'openssh', 'telnet', 'VENDORS']


def get(name: str):
    """Get vendor module by name."""
    if name not in VENDORS:
        raise ValueError(f"Unknown vendor: {name}. Available: {', '.join(VENDORS.keys())}")
    return VENDORS[name]
