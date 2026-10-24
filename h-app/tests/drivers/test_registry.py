"""#80: the driver registry. A target names a driver, canonically
`dialect@transport`, or by one of today's vendor names, which stay valid as
aliases. The runner asks the driver's `supports`; the CLI and core take the
default port, the install hint and the module from the same place."""
import asyncio
import os
import sys
import types

import pytest

from hssh import cli, core, drivers, runner, vendors
from hssh.core import Target
from hssh.drivers.base import Driver, CAPABILITIES, POLICY_CAPABILITIES
from tests.test_cli_runfile import run as run_cli

TODAYS_NAMES = ["junos", "ssh", "openssh", "telnet", "telnet-ios", "telnet-junos", "telnet-arista",
                "telnet-nxos"]


# --- names ---------------------------------------------------------------------

def test_todays_names_are_aliases_of_canonical_drivers():
    assert list(drivers.ALIASES) == TODAYS_NAMES
    for alias in TODAYS_NAMES:
        driver = drivers.get(alias)
        assert driver.shim == alias
        assert drivers.get(driver.name) is driver
    assert drivers.get("junos") is drivers.get("junos@netconf")
    assert drivers.get("telnet-ios").name == "ios@telnet"
    assert drivers.get("telnet-arista").name == "eos@telnet"
    assert drivers.get("ssh").name == "none@ssh"


def test_every_name_is_unique_and_listed():
    names = drivers.names()
    assert len(names) == len(set(names)) == 16
    assert set(names) == set(drivers.ALIASES) | set(drivers.DRIVERS)
    assert set(vendors.VENDORS) == set(drivers.ALIASES)


def test_a_retired_name_gets_its_line_and_an_unknown_one_the_list():
    with pytest.raises(ValueError, match="eAPI over HTTPS.*no longer supported"):
        drivers.get("arista")
    assert vendors.RETIRED is drivers.RETIRED
    with pytest.raises(ValueError, match="Unknown vendor: junos@ssh. Available: junos, ssh, "):
        drivers.get("junos@ssh")


# --- the three parts -----------------------------------------------------------

def test_transports_say_what_they_are():
    assert drivers.NETCONF.default_port == 830 and drivers.NETCONF.pooled
    assert drivers.NETCONF.formats == ("text", "xml", "json")
    for t in (drivers.SSH, drivers.OPENSSH):
        assert t.default_port == 22 and t.formats == ("text",) and t.over_ssh and not t.pooled
    assert drivers.TELNET.default_port == 23 and drivers.TELNET.frozen and not drivers.TELNET.over_ssh
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


def test_a_driver_cannot_declare_nonsense():
    with pytest.raises(ValueError, match="unknown capabilities \\['fly'\\]"):
        Driver(drivers.NONE, drivers.SSH, frozenset({"show", "fly"}), shim="x")
    with pytest.raises(ValueError, match="need edit"):
        Driver(drivers.NONE, drivers.SSH, frozenset({"show", "dry_run"}), shim="x")
    with pytest.raises(ValueError, match="rpc needs a transport with a structured format"):
        Driver(drivers.NONE, drivers.SSH, frozenset({"show", "rpc"}), shim="x")


# --- stand-ins -----------------------------------------------------------------

def test_the_own_module_gets_the_declared_set_and_a_stand_in_what_it_has(monkeypatch):
    junos = drivers.get("junos@netconf")
    assert drivers.supports_of(junos, vendors.junos) == CAPABILITIES
    stub = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "")
    assert drivers.supports_of(junos, stub) == {"show"} | POLICY_CAPABILITIES
    stub = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "", rollback=lambda *a, **kw: "")
    assert drivers.supports_of(drivers.get("none@ssh"), stub) == {"show", "rollback"}


def test_module_of_honours_a_double_put_in_the_vendors_table(monkeypatch):
    junos = drivers.get("junos@netconf")
    assert drivers.module_of(junos) is vendors.junos
    stub = types.SimpleNamespace(AVAILABLE=True)
    monkeypatch.setitem(vendors.VENDORS, "junos", stub)
    assert drivers.module_of(junos) is stub


# --- ports, install hints -----------------------------------------------------

def test_default_ports_come_from_the_transport_for_either_name():
    assert core.resolve_target_port(Target("R1", "h", vendor="junos@netconf")) == 830
    assert core.resolve_target_port(Target("R1", "h", vendor="ios@telnet")) == 23
    assert core.resolve_target_port(Target("R1", "h", vendor="none@openssh")) == 22
    assert core.resolve_target_port(Target("R1", "h", vendor="junos@netconf", port=2222)) == 2222
    assert core.resolve_target_port(Target("R1", "h", vendor="nope")) == 22


def test_the_cli_knows_what_to_install_for_every_name():
    assert set(cli.VENDOR_INSTALL) == set(drivers.names())
    assert cli.VENDOR_INSTALL["junos"] == cli.VENDOR_INSTALL["junos@netconf"] == "junos-eznc"
    assert cli.VENDOR_INSTALL["telnet-ios"] == "(built-in)"
    assert set(cli.TRANSPORT_CHOICES) <= set(drivers.names())


# --- through the runner and the CLI -------------------------------------------

def _run(monkeypatch, vendor_name, mode="show", **kw):
    return runner.run_for_target(
        t=Target("R1", "10.0.0.1", vendor_name), transport=vendor_name, mode=mode,
        show_cmd="show version", edit_cmd=None, config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=False, commit_confirmed=None, save_dir=None, quiet=True, max_attempts=1, **kw)


def test_a_canonical_name_runs_on_todays_module_with_todays_hint(monkeypatch):
    seen = []

    def show(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        seen.append(vendor_hint)
        return "ok"
    monkeypatch.setitem(vendors.VENDORS, "junos", types.SimpleNamespace(AVAILABLE=True, show=show))
    monkeypatch.setitem(vendors.VENDORS, "telnet-junos", types.SimpleNamespace(AVAILABLE=True, show=show))
    name, ok, out, _ = _run(monkeypatch, "junos@netconf")
    assert ok and "VENDOR: junos@netconf" in out
    _, ok, _, _ = _run(monkeypatch, "junos@telnet")
    assert ok
    assert seen == ["junos", "telnet-junos"]


def test_a_refusal_names_the_driver_as_the_operator_wrote_it(monkeypatch):
    monkeypatch.setitem(vendors.VENDORS, "ssh", types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: ""))
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
                              ["--user", "u", "--target", "R1:10.0.0.1:junos@ssh", "-sC", "show version"])
    assert rc == 2 and "ERROR: Unknown vendor 'junos@ssh'." in err
