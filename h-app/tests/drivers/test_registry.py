"""#80: the driver registry. A target names a driver, canonically
`dialect@transport`, or by one of today's vendor names, which stay valid as
aliases. The runner asks the driver's `supports`; the CLI and core take the
default port, the install hint and the module from the same place. #84: the
built-ins are one tuple, every driver says where it came from, and a module
standing in for a transport's (a test double) goes in MODULES under the
driver's canonical name, which is also the vendor_hint the module is called with."""
import asyncio
import importlib
import os
import sys
import types

import pytest

from hssh import cli, core, drivers, runner
from hssh.core import Target
from hssh.drivers.base import Driver, CAPABILITIES, POLICY_CAPABILITIES
from hssh.transports import netconf
from tests.test_cli_runfile import run as run_cli

TODAYS_NAMES = ["junos", "ssh", "openssh", "telnet", "telnet-ios", "telnet-junos", "telnet-arista",
                "telnet-nxos"]
# the ssh and openssh dialect drivers (#83) go by their own name only
OWN_NAME_ONLY = ["junos@ssh", "ios@ssh", "nxos@ssh", "eos@ssh",
                 "junos@openssh", "ios@openssh", "nxos@openssh", "eos@openssh"]


# --- names ---------------------------------------------------------------------

def test_todays_names_are_aliases_of_canonical_drivers():
    assert list(drivers.ALIASES) == TODAYS_NAMES
    for alias in TODAYS_NAMES:
        driver = drivers.get(alias)
        assert driver.aliases == (alias,)
        assert drivers.ALIASES[alias] == driver.name
        assert drivers.get(driver.name) is driver
    assert drivers.get("junos") is drivers.get("junos@netconf")
    assert drivers.get("telnet-ios").name == "ios@telnet"
    assert drivers.get("telnet-arista").name == "eos@telnet"
    assert drivers.get("ssh").name == "none@ssh"


def test_every_name_is_unique_and_listed(installed):
    names = drivers.names()
    assert len(names) == len(set(names))
    assert set(names) == set(drivers.ALIASES) | set(drivers.DRIVERS)
    # 16 built-in drivers, 24 names: a subset of the registry, not the total (#110)
    builtin = [a for d in drivers.BUILTIN for a in d.aliases] + [d.name for d in drivers.BUILTIN]
    assert len(drivers.BUILTIN) == 16 and len(builtin) == len(set(builtin)) == 24
    assert set(builtin) | installed <= set(names)
    # every alias is some driver's, and a driver's aliases are all listed
    assert sorted(drivers.ALIASES) == sorted(a for d in drivers.DRIVERS.values() for a in d.aliases)
    for name in OWN_NAME_ONLY:
        assert drivers.get(name).name == name and drivers.get(name).aliases == ()
        assert name not in drivers.ALIASES


def test_the_built_ins_lead_the_registry_and_say_so(installed):
    # first and in order; a driver package installed next to h-ssh comes after them (#110)
    assert list(drivers.DRIVERS.values())[:len(drivers.BUILTIN)] == list(drivers.BUILTIN)
    assert set(drivers.SOURCES) == set(drivers.DRIVERS)
    for driver in drivers.BUILTIN:
        assert drivers.DRIVERS[driver.name] is driver
        assert drivers.SOURCES[driver.name] == "built-in"
    assert installed <= set(drivers.DRIVERS)
    assert all(drivers.SOURCES[n] != "built-in" for n in list(drivers.DRIVERS)[len(drivers.BUILTIN):])
    assert "builtin" not in drivers.BROKEN          # h-ssh's own; another package may be broken (#110)


def test_a_retired_name_gets_its_line_and_an_unknown_one_the_list():
    with pytest.raises(ValueError, match="eAPI over HTTPS.*no longer supported"):
        drivers.get("arista")
    assert "arista" in drivers.RETIRED and "arista" not in drivers.names()
    with pytest.raises(ValueError, match="Unknown vendor: ios@netconf. Available: junos, ssh, "):
        drivers.get("ios@netconf")


# --- the three parts -----------------------------------------------------------

def test_transports_say_what_they_are():
    assert drivers.NETCONF.default_port == 830 and drivers.NETCONF.pooled
    assert drivers.NETCONF.formats == ("text", "xml", "json")
    for t in (drivers.NETCONF, drivers.SSH, drivers.OPENSSH):
        assert t.banner == b"SSH-"
    for t in (drivers.SSH, drivers.OPENSSH):
        assert t.default_port == 22 and t.formats == ("text",) and not t.pooled
    assert drivers.TELNET.default_port == 23 and drivers.TELNET.frozen and drivers.TELNET.banner is None
    assert [t for t in drivers.TRANSPORTS.values() if t.frozen] == [drivers.TELNET]
    assert [t for t in drivers.TRANSPORTS.values() if t.pooled] == [drivers.NETCONF]


def test_supports_match_what_the_runner_refused_by_name_before():
    """The frozensets the runner kept (dry-run and commit-confirmed on junos and
    telnet-junos, comments on junos only) are now the drivers' word."""
    def with_cap(cap):
        return sorted(a for a in drivers.ALIASES if cap in drivers.get(a).supports)
    assert with_cap("dry_run") == ["junos", "telnet-junos"]
    assert with_cap("commit_confirmed") == ["junos", "telnet-junos"]
    assert with_cap("comment") == ["junos"]
    assert with_cap("rollback") == with_cap("commit_status") == with_cap("rpc") == ["junos"]
    assert with_cap("confirm") == ["junos", "telnet-junos"]
    assert drivers.get("junos").supports == CAPABILITIES
    for alias in ("ssh", "openssh", "telnet", "telnet-ios", "telnet-arista", "telnet-nxos"):
        assert drivers.get(alias).supports == {"show", "show_batch", "edit"}
    # the ssh dialect drivers (#83): Junos with its candidate, the IOS-shaped ones as lines, EOS with | json
    assert drivers.get("junos@ssh").supports == drivers.get("telnet-junos").supports
    assert drivers.get("ios@ssh").supports == drivers.get("nxos@ssh").supports == {"show", "show_batch", "edit"}
    assert drivers.get("eos@ssh").supports == {"show", "show_batch", "edit", "show_structured"}
    # the same dialects on the OpenSSH client (#83) can do the same
    for dialect in ("junos", "ios", "nxos", "eos"):
        assert drivers.get(f"{dialect}@openssh").supports == drivers.get(f"{dialect}@ssh").supports


def test_a_driver_cannot_declare_nonsense():
    with pytest.raises(ValueError, match="unknown capabilities \\['fly'\\]"):
        Driver(drivers.NONE, drivers.SSH, frozenset({"show", "fly"}))
    with pytest.raises(ValueError, match="need edit"):
        Driver(drivers.NONE, drivers.SSH, frozenset({"show", "dry_run"}))
    with pytest.raises(ValueError, match="rpc needs a transport with a structured format"):
        Driver(drivers.NONE, drivers.SSH, frozenset({"show", "rpc"}))


# --- modules and stand-ins -----------------------------------------------------

def test_every_driver_resolves_to_its_transports_module():
    for driver in drivers.DRIVERS.values():
        assert drivers.module_of(driver) is importlib.import_module(driver.transport.module)
    assert drivers.module_of(drivers.get("junos")) is netconf
    assert {d.transport.module for d in drivers.DRIVERS.values()} == {
        "hssh.transports.netconf", "hssh.transports.ssh", "hssh.transports.openssh", "hssh.transports.telnet"}


def test_the_own_module_gets_the_declared_set_and_a_stand_in_what_it_has(monkeypatch):
    junos = drivers.get("junos@netconf")
    assert drivers.supports_of(junos, netconf) == CAPABILITIES
    stub = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "")
    assert drivers.supports_of(junos, stub) == {"show"} | POLICY_CAPABILITIES
    stub = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "", rollback=lambda *a, **kw: "")
    assert drivers.supports_of(drivers.get("none@ssh"), stub) == {"show", "rollback"}


def test_module_of_honours_a_stand_in_put_in_modules_under_the_drivers_name(monkeypatch):
    junos = drivers.get("junos@netconf")
    assert drivers.module_of(junos) is netconf
    stub = types.SimpleNamespace(AVAILABLE=True)
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", stub)
    assert drivers.module_of(junos) is stub
    assert drivers.module_of(drivers.get("junos")) is stub                # the alias names the same driver
    assert drivers.module_of(drivers.get("junos@telnet")) is not stub     # and no other driver is touched
    assert runner.bind("junos").mod is stub and runner.bind("junos").caps == POLICY_CAPABILITIES


# --- ports, install hints -----------------------------------------------------

def test_default_ports_come_from_the_transport_for_either_name():
    assert core.resolve_target_port(Target("R1", "h", vendor="junos@netconf")) == 830
    assert core.resolve_target_port(Target("R1", "h", vendor="ios@telnet")) == 23
    assert core.resolve_target_port(Target("R1", "h", vendor="none@openssh")) == 22
    assert core.resolve_target_port(Target("R1", "h", vendor="junos@netconf", port=2222)) == 2222
    assert core.resolve_target_port(Target("R1", "h", vendor="nope")) == 22


def test_the_cli_knows_what_to_install_for_every_name(monkeypatch, capsys, tmp_path):
    for name in drivers.names():
        assert drivers.get(name).transport.install
    assert drivers.get("junos").transport.install == drivers.get("junos@netconf").transport.install == "junos-eznc"
    assert drivers.get("telnet-ios").transport.install == "(built-in)"
    assert set(cli.TRANSPORT_CHOICES) <= set(drivers.names())
    # the CLI names it when the module says it is missing, before any device is touched
    rc, out, err, _ = run_cli(monkeypatch, capsys, tmp_path,
                              ["--user", "u", "--target", "R1:10.0.0.1:junos@netconf", "-sC", "show version"],
                              driver=types.SimpleNamespace(AVAILABLE=False))
    assert rc == 2 and "ERROR: junos-eznc not installed (required for vendor 'junos@netconf')." in err


# --- through the runner and the CLI -------------------------------------------

def _run(monkeypatch, vendor_name, mode="show", **kw):
    return runner.run_for_target(
        t=Target("R1", "10.0.0.1", vendor_name), transport=vendor_name, mode=mode,
        show_cmd="show version", edit_cmd=None, config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=False, commit_confirmed=None, save_dir=None, quiet=True, max_attempts=1, **kw)


def test_a_name_runs_on_its_drivers_module_with_the_canonical_hint(monkeypatch):
    seen = []

    def show(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        seen.append(vendor_hint)
        return "ok"
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(AVAILABLE=True, show=show))
    monkeypatch.setitem(drivers.MODULES, "junos@telnet", types.SimpleNamespace(AVAILABLE=True, show=show))
    name, ok, out, _ = _run(monkeypatch, "junos@netconf")
    assert ok and "VENDOR: junos@netconf" in out
    _, ok, _, _ = _run(monkeypatch, "junos@telnet")
    assert ok
    # an alias runs on the same module; the module hears the driver's name, the output the operator's
    _, ok, out, _ = _run(monkeypatch, "telnet-junos")
    assert ok and "VENDOR: telnet-junos" in out
    assert seen == ["junos@netconf", "junos@telnet", "junos@telnet"]


def test_a_refusal_names_the_driver_as_the_operator_wrote_it(monkeypatch):
    monkeypatch.setitem(drivers.MODULES, "none@ssh", types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: ""))
    _, ok, out, _ = _run(monkeypatch, "none@ssh", mode="rollback", rollback=1)
    assert not ok and "--rollback is not supported by the 'none@ssh' transport" in out
    _, ok, out, _ = _run(monkeypatch, "none@ssh", mode="commit-status")
    assert not ok and "--commit-status is not supported by the 'none@ssh' transport" in out


def test_the_cli_accepts_a_canonical_target_and_refuses_an_unregistered_pair(monkeypatch, capsys, tmp_path):
    rc, out, err, drv = run_cli(monkeypatch, capsys, tmp_path,
                                ["--user", "u", "--target", "R1:10.0.0.1:junos@netconf", "-sC", "show version", "--json"])
    assert rc == 0, err
    assert drv.shows == [("10.0.0.1", "show version", None)]   # the driver applies its own default port
    rc, out, err, _ = run_cli(monkeypatch, capsys, tmp_path,
                              ["--user", "u", "--target", "R1:10.0.0.1:ios@netconf", "-sC", "show version"])
    assert rc == 2 and "ERROR: Unknown vendor 'ios@netconf'." in err
