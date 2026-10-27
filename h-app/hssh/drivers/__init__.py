"""The driver registry: every name a target may carry, and what it resolves to.

Canonical names are ``dialect@transport`` (``junos@netconf``, ``ios@telnet``).
The vendor names h-ssh has always taken (``junos``, ``ssh``, ``telnet-ios``, …)
are aliases and stay valid. ``get()`` takes either.

The built-in drivers are declared here. A package installed next to h-ssh
adds its own through the ``hssh.drivers`` entry-point group: the entry point
names a Driver, a list of them, or a callable returning either, built from
this module's Transport objects (or its own) and a Dialect. An entry point
that fails to load, or claims a name already taken, is reported by name in
``BROKEN`` and skipped; the rest load. ``load()`` rebuilds the registry.
"""

import importlib
from importlib import metadata
from typing import Dict, Iterable, List, Optional

from .base import (Dialect, Transport, Driver, CAPABILITIES, METHOD_CAPABILITIES,
                   POLICY_CAPABILITIES)
from .. import dialects as _dialects

__all__ = ["Dialect", "Transport", "Driver", "CAPABILITIES", "METHOD_CAPABILITIES",
           "POLICY_CAPABILITIES", "DIALECTS", "TRANSPORTS", "BUILTIN", "DRIVERS", "ALIASES",
           "SOURCES", "BROKEN", "MODULES", "RETIRED", "ENTRY_POINT_GROUP",
           "load", "get", "names", "module_of", "supports_of"]

ENTRY_POINT_GROUP = "hssh.drivers"
BUILTIN_SOURCE = "built-in"

# --- dialects -----------------------------------------------------------------

JUNOS = _dialects.junos.DIALECT
IOS = _dialects.ios.DIALECT
NXOS = _dialects.nxos.DIALECT
EOS = _dialects.eos.DIALECT
NONE = _dialects.none.DIALECT

DIALECTS = {d.name: d for d in _dialects.ALL}

# --- transports ---------------------------------------------------------------

NETCONF = Transport("netconf", "NETCONF over SSH (PyEZ)", module="hssh.transports.netconf",
                    install="junos-eznc", default_port=830, formats=("text", "xml", "json"),
                    pooled=True, ssh_config="paramiko")
SSH = Transport("ssh", "SSH exec channel (paramiko)", module="hssh.transports.ssh",
                install="paramiko", default_port=22)
OPENSSH = Transport("openssh", "the OpenSSH client", module="hssh.transports.openssh",
                    install="the OpenSSH client ('ssh' on PATH)", default_port=22, ssh_config="openssh")
# Legacy fallback (2026-10-24): it inherits dialects and fixes, nothing else.
TELNET = Transport("telnet", "telnet", module="hssh.transports.telnet", install="(built-in)",
                   default_port=23, banner=None, frozen=True)

TRANSPORTS = {t.name: t for t in (NETCONF, SSH, OPENSSH, TELNET)}

# --- drivers ------------------------------------------------------------------

_TEXT = frozenset({"show", "show_batch", "edit"})

# What a dialect's CLI can do over a transport that types at it: a candidate
# dialect (Junos) can diff and discard, arm a commit-confirmed timer and
# confirm one; a lines dialect applies what it is given. Comments and
# rollbacks stay NETCONF's.
_CANDIDATE_CLI = _TEXT | {"confirm", "dry_run", "commit_confirmed"}

BUILTIN = (
    Driver(JUNOS, NETCONF, frozenset(CAPABILITIES), aliases=("junos",)),
    Driver(NONE, SSH, _TEXT, aliases=("ssh",)),
    Driver(NONE, OPENSSH, _TEXT, aliases=("openssh",)),
    # Dialects over SSH (#83), on paramiko and on the OpenSSH client: shows on
    # an exec channel, edits through the CLI engine on a shell (a pty, for the
    # OpenSSH client).
    Driver(JUNOS, SSH, _CANDIDATE_CLI),
    Driver(IOS, SSH, _TEXT),
    Driver(NXOS, SSH, _TEXT),
    Driver(EOS, SSH, _TEXT | {"show_structured"}),    # structured reads via `| json`
    Driver(JUNOS, OPENSSH, _CANDIDATE_CLI),
    Driver(IOS, OPENSSH, _TEXT),
    Driver(NXOS, OPENSSH, _TEXT),
    Driver(EOS, OPENSSH, _TEXT | {"show_structured"}),
    Driver(NONE, TELNET, _TEXT, aliases=("telnet",)),
    Driver(IOS, TELNET, _TEXT, aliases=("telnet-ios",)),
    Driver(JUNOS, TELNET, _CANDIDATE_CLI, aliases=("telnet-junos",)),
    Driver(EOS, TELNET, _TEXT, aliases=("telnet-arista",)),
    Driver(NXOS, TELNET, _TEXT, aliases=("telnet-nxos",)),
)

# Names h-ssh used to speak to and no longer does, with the one line a target
# that still carries them gets. h-ssh is SSH, NETCONF over SSH and telnet: no
# HTTP transports (2026-10-24).
RETIRED = {
    "arista": "vendor 'arista' (eAPI over HTTPS) is no longer supported; EOS devices use the "
              "ssh or openssh transport (eos@ssh or eos@openssh for the EOS dialect), or telnet-arista",
}

# The registry proper, filled by load(): rebuilt in place, so a module that
# holds one of these dicts always sees the current registry.
DRIVERS: Dict[str, Driver] = {}      # canonical name -> driver
ALIASES: Dict[str, str] = {}         # alias -> canonical name
SOURCES: Dict[str, str] = {}         # canonical name -> where the driver came from
BROKEN: Dict[str, str] = {}          # entry point name -> why it was skipped
# A module standing in for a transport's, by driver name: what a test double
# or an embedding application puts here is what the driver's work runs on.
MODULES: Dict[str, object] = {}


def _check_free(driver: Driver) -> None:
    if driver.name in DRIVERS:
        raise ValueError(f"'{driver.name}' is already registered ({SOURCES[driver.name]})")
    for alias in driver.aliases:
        taken = alias in DRIVERS or alias in ALIASES or alias in RETIRED
        if taken or alias == driver.name:
            raise ValueError(f"alias '{alias}' of '{driver.name}' is already a name")


def _register(driver: Driver, source: str) -> None:
    DRIVERS[driver.name] = driver
    SOURCES[driver.name] = source
    for alias in driver.aliases:
        ALIASES[alias] = driver.name


def _drivers_in(obj) -> List[Driver]:
    """What an entry point hands over: a Driver, drivers, or a callable
    returning either. Anything else is the entry point's fault."""
    if callable(obj) and not isinstance(obj, Driver):
        obj = obj()
    if isinstance(obj, Driver):
        return [obj]
    found = list(obj)
    for d in found:
        if not isinstance(d, Driver):
            raise TypeError(f"{d!r} is not a Driver")
    return found


def _source_of(ep) -> str:
    dist = getattr(ep, "dist", None)
    name = getattr(dist, "name", None) if dist is not None else None
    return f"{name} (entry point {ep.name})" if name else f"entry point {ep.name} ({ep.value})"


def _installed_entry_points() -> Iterable:
    """Every `hssh.drivers` entry point of the installed packages, h-ssh's
    own (the built-ins, loaded already) left out."""
    own = __name__.split(".")[0]
    return [ep for ep in metadata.entry_points(group=ENTRY_POINT_GROUP)
            if ep.value.split(":")[0].split(".")[0] != own]


def load(entry_points: Optional[Iterable] = None) -> None:
    """(Re)build the registry: the built-ins, then every entry point given
    (default: the installed ones). An entry point is taken whole or not at
    all: one that fails to import, hands over something that is not a
    Driver, or claims a name or alias already registered is listed in
    BROKEN with the reason, and the rest still load."""
    DRIVERS.clear()
    ALIASES.clear()
    SOURCES.clear()
    BROKEN.clear()
    for driver in BUILTIN:
        _check_free(driver)
        _register(driver, BUILTIN_SOURCE)
    eps = list(_installed_entry_points() if entry_points is None else entry_points)
    for ep in eps:
        try:
            found = _drivers_in(ep.load())
            seen = set()
            for driver in found:
                _check_free(driver)
                if driver.name in seen:
                    raise ValueError(f"'{driver.name}' is listed twice")
                seen.add(driver.name)
            for driver in found:
                _register(driver, _source_of(ep))
        except Exception as e:              # noqa: BLE001 - reported by name, never a traceback
            BROKEN[ep.name] = f"{type(e).__name__}: {e}"


def names() -> List[str]:
    """Every name a target may carry: the aliases first, then the canonical ones."""
    return list(ALIASES) + list(DRIVERS)


def get(name: str) -> Driver:
    """The driver for a target's vendor name, alias or canonical."""
    if name in RETIRED:
        raise ValueError(RETIRED[name])
    driver = DRIVERS.get(ALIASES.get(name, name))
    if driver is None:
        raise ValueError(f"Unknown vendor: {name}. Available: {', '.join(names())}")
    return driver


def _own_module(driver: Driver):
    return importlib.import_module(driver.transport.module)


def module_of(driver: Driver):
    """The module that does the driver's work: a stand-in put in MODULES
    under the driver's name, else the transport's own module."""
    return MODULES.get(driver.name) or _own_module(driver)


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


load()
