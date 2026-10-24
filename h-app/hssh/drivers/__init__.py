"""The driver registry: every name a target may carry, and what it resolves to.

Canonical names are ``dialect@transport`` (``junos@netconf``, ``ios@telnet``).
Today's vendor names (``junos``, ``ssh``, ``telnet-ios``, …) are aliases and
stay valid. ``get()`` takes either.
"""

import importlib

from .base import (Dialect, Transport, Driver, CAPABILITIES, METHOD_CAPABILITIES,
                   POLICY_CAPABILITIES)

__all__ = ["Dialect", "Transport", "Driver", "CAPABILITIES", "METHOD_CAPABILITIES",
           "POLICY_CAPABILITIES", "DIALECTS", "TRANSPORTS", "DRIVERS", "ALIASES", "RETIRED",
           "get", "names", "module_of", "supports_of"]

# --- dialects -----------------------------------------------------------------

JUNOS = Dialect("junos", "Junos: set syntax, candidate configuration, commit confirmed")
IOS = Dialect("ios", "Cisco IOS and IOS-XE")
NXOS = Dialect("nxos", "Cisco NX-OS")
EOS = Dialect("eos", "Arista EOS")
NONE = Dialect("none", "no vendor knowledge: a line in, its text out")

DIALECTS = {d.name: d for d in (JUNOS, IOS, NXOS, EOS, NONE)}

# --- transports ---------------------------------------------------------------

NETCONF = Transport("netconf", "NETCONF over SSH (PyEZ)", module="hssh.vendors.junos",
                    install="junos-eznc", default_port=830, formats=("text", "xml", "json"),
                    pooled=True)
SSH = Transport("ssh", "SSH exec channel (paramiko)", module="hssh.vendors.generic",
                install="paramiko", default_port=22)
OPENSSH = Transport("openssh", "the OpenSSH client", module="hssh.vendors.openssh",
                    install="the OpenSSH client ('ssh' on PATH)", default_port=22)
# Legacy fallback (2026-10-24): it inherits dialects and fixes, nothing else.
TELNET = Transport("telnet", "telnet", module="hssh.vendors.telnet", install="(built-in)",
                   default_port=23, over_ssh=False, frozen=True)

TRANSPORTS = {t.name: t for t in (NETCONF, SSH, OPENSSH, TELNET)}

# --- drivers ------------------------------------------------------------------

_TEXT = frozenset({"show", "show_batch", "edit"})

DRIVERS = {d.name: d for d in (
    Driver(JUNOS, NETCONF, frozenset(CAPABILITIES), shim="junos"),
    Driver(NONE, SSH, _TEXT, shim="ssh"),
    Driver(NONE, OPENSSH, _TEXT, shim="openssh"),
    Driver(NONE, TELNET, _TEXT, shim="telnet"),
    Driver(IOS, TELNET, _TEXT, shim="telnet-ios"),
    # The telnet CLI can diff a Junos candidate and arm a commit-confirmed
    # timer; it cannot log a comment with the commit or return to a rollback.
    Driver(JUNOS, TELNET, _TEXT | {"confirm", "dry_run", "commit_confirmed"}, shim="telnet-junos"),
    Driver(EOS, TELNET, _TEXT, shim="telnet-arista"),
    Driver(NXOS, TELNET, _TEXT, shim="telnet-nxos"),
)}

ALIASES = {d.shim: d.name for d in DRIVERS.values()}

# Names h-ssh used to speak to and no longer does, with the one line a target
# that still carries them gets. h-ssh is SSH, NETCONF over SSH and telnet: no
# HTTP transports (2026-10-24).
RETIRED = {
    "arista": "vendor 'arista' (eAPI over HTTPS) is no longer supported; EOS devices use the "
              "ssh or openssh transport (eos@ssh once dialects land), or telnet-arista",
}


def names():
    """Every name a target may carry: today's names first, then the canonical ones."""
    return list(ALIASES) + list(DRIVERS)


def get(name: str) -> Driver:
    """The driver for a target's vendor name, alias or canonical."""
    if name in RETIRED:
        raise ValueError(RETIRED[name])
    driver = DRIVERS.get(ALIASES.get(name, name))
    if driver is None:
        raise ValueError(f"Unknown vendor: {name}. Available: {', '.join(names())}")
    return driver


def module_of(driver: Driver):
    """The module that does the driver's work. Resolved through hssh.vendors at
    call time, so a module put there in its place (a test double) is honoured."""
    from .. import vendors
    return vendors.get(driver.shim)


def _own_module(driver: Driver):
    return importlib.import_module(driver.transport.module)


def supports_of(driver: Driver, module) -> frozenset:
    """What `module` may be asked when it does the driver's work. For the
    driver's own module that is the declared set, which the contract verifies.
    A stand-in (a test double, a module not registered yet) is believed on
    the functions it has; the by-name policies stay the registry's, since a
    module that takes `dry_run` cannot be asked whether its dry run is real."""
    if module is _own_module(driver):
        return driver.supports
    have = {c for c in METHOD_CAPABILITIES if callable(getattr(module, c, None))}
    return frozenset(have | (driver.supports & POLICY_CAPABILITIES))
