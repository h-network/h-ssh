"""Vendor-specific implementations."""

from . import junos
from . import generic
from . import telnet
from . import openssh
from ..drivers import RETIRED

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


def get(name: str):
    """Get vendor module by today's vendor name (a driver's `shim`). A target
    name, alias or canonical, resolves through hssh.drivers.get() first."""
    if name in RETIRED:
        raise ValueError(RETIRED[name])
    if name not in VENDORS:
        raise ValueError(f"Unknown vendor: {name}. Available: {', '.join(VENDORS.keys())}")
    return VENDORS[name]
