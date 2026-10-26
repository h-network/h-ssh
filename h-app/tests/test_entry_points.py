"""#84: drivers from outside the package. A package installed next to h-ssh
registers its drivers through the `hssh.drivers` entry-point group: the
registry loads them after the built-ins, takes each entry point whole or not
at all, reports a broken one by name and never as a traceback, and
`--list-vendors` says where every driver came from. The entry points here
are built in memory from the packages under tests/fixtures, so nothing has
to be installed."""
import asyncio
import os
import re
import sys
import types
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

from hssh import cli, drivers, runner
from hssh.core import Target
from hssh.drivers import contract

GROUP = drivers.ENTRY_POINT_GROUP
PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"
BUILTIN_NAMES = frozenset(d.name for d in drivers.BUILTIN)


def ep(name, value):
    """An entry point as importlib.metadata reads one from a dist-info."""
    return EntryPoint(name, value, GROUP)


DUMMY = ep("dummy", "tests.fixtures.hssh_dummy:DRIVERS")
BROKEN = ep("broken", "tests.fixtures.hssh_broken")
BROKEN_WHY = "ImportError: hssh_broken needs a library that is not installed"


@pytest.fixture
def registry():
    """The registry a test loads into, put back afterwards: load() with no
    argument is the built-ins and the installed entry points, which is what
    every other test module sees."""
    yield drivers
    drivers.load()


def run(vendor, mode="show", **kw):
    return runner.run_for_target(
        t=Target("R1", "10.0.0.1", vendor), transport=vendor, mode=mode,
        show_cmd="show version", edit_cmd=None, config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=False, commit_confirmed=None, save_dir=None, quiet=True, max_attempts=1, **kw)


# --- loading -------------------------------------------------------------------

def test_an_entry_point_adds_its_driver_after_the_builtins(registry, installed):
    drivers.load([])                 # the built-ins alone, whatever this machine has installed
    before = dict(drivers.DRIVERS)
    aliases = dict(drivers.ALIASES)
    drivers.load([DUMMY])
    assert drivers.BROKEN == {}
    assert len(drivers.DRIVERS) == len(before) + 1
    assert set(drivers.DRIVERS) - set(before) == {"dummy@ssh"}
    for name in before:
        assert drivers.DRIVERS[name] is before[name] and drivers.SOURCES[name] == "built-in"
    assert drivers.ALIASES == aliases
    assert drivers.get("junos") is drivers.get("junos@netconf")
    assert drivers.get("junos").transport is drivers.NETCONF
    dummy = drivers.get("dummy@ssh")
    assert dummy.dialect.name == "dummy" and dummy.transport is drivers.SSH
    assert dummy.supports == {"show", "show_batch"} and dummy.aliases == ()
    assert drivers.SOURCES["dummy@ssh"] == "entry point dummy (tests.fixtures.hssh_dummy:DRIVERS)"
    assert drivers.names()[-1] == "dummy@ssh"


def test_a_driver_from_an_installed_package_is_credited_to_its_distribution(registry):
    """What --list-vendors shows once the package is really installed: the
    distribution's name, then the entry point's."""
    installed = ep("dummy", "tests.fixtures.hssh_dummy:DRIVERS")
    # how importlib.metadata attaches the distribution when it reads a dist-info
    vars(installed).update(dist=types.SimpleNamespace(name="acme-hssh"))
    drivers.load([installed])
    assert drivers.SOURCES["dummy@ssh"] == "acme-hssh (entry point dummy)"


def test_the_callable_form_is_called_for_its_drivers(registry):
    drivers.load([ep("factory", "tests.fixtures.hssh_dummy:make")])
    assert drivers.BROKEN == {}
    assert drivers.get("dummy@ssh").supports == {"show", "show_batch"}
    assert drivers.SOURCES["dummy@ssh"] == "entry point factory (tests.fixtures.hssh_dummy:make)"


def test_a_broken_entry_point_is_reported_by_name_and_the_rest_still_load(registry):
    drivers.load([BROKEN, DUMMY])
    assert drivers.BROKEN == {"broken": BROKEN_WHY}
    assert "dummy@ssh" in drivers.DRIVERS
    assert set(drivers.DRIVERS) == BUILTIN_NAMES | {"dummy@ssh"}


@pytest.mark.parametrize("name, value, why", [
    ("broken", "tests.fixtures.hssh_broken", re.escape(BROKEN_WHY)),
    ("odd", "tests.fixtures.hssh_dummy:NOT_A_DRIVER", r"TypeError: Dialect\(name='dummy', .* is not a Driver"),
    ("twice", "tests.fixtures.hssh_dummy:TWICE", r"ValueError: 'dummy@ssh' is listed twice"),
    ("missing", "tests.fixtures.hssh_dummy:NOPE", r"AttributeError: module 'tests.fixtures.hssh_dummy' has no attribute 'NOPE'"),
])
def test_what_an_entry_point_may_not_hand_over_is_listed_with_the_reason(registry, name, value, why):
    """One line, `ExcType: message`, under the entry point's name; nothing of
    the entry point registered."""
    drivers.load([ep(name, value)])
    assert list(drivers.BROKEN) == [name]
    assert re.fullmatch(why, drivers.BROKEN[name], re.S), drivers.BROKEN[name]
    assert set(drivers.DRIVERS) == BUILTIN_NAMES


def test_an_entry_point_that_claims_a_taken_alias_registers_nothing(registry):
    """hssh_taken ships a clean `taken@ssh` and a `taken@openssh` that wants
    the alias `junos`: the entry point is refused whole, `junos` stays the
    NETCONF driver, and the other entry point of the batch still loads."""
    drivers.load([ep("taken", "tests.fixtures.hssh_taken:DRIVERS"), DUMMY])
    assert drivers.BROKEN == {"taken": "ValueError: alias 'junos' of 'taken@openssh' is already a name"}
    assert "taken@ssh" not in drivers.DRIVERS and "taken@openssh" not in drivers.DRIVERS
    assert drivers.ALIASES["junos"] == "junos@netconf"
    assert drivers.get("junos").transport is drivers.NETCONF
    assert "dummy@ssh" in drivers.DRIVERS


def test_an_entry_point_that_claims_a_builtin_name_registers_nothing(registry):
    drivers.load([ep("same", "tests.fixtures.hssh_taken:same_name")])
    assert drivers.BROKEN == {"same": "ValueError: 'none@ssh' is already registered (built-in)"}
    assert drivers.SOURCES["none@ssh"] == "built-in"
    assert drivers.get("ssh").supports == {"show", "show_batch", "edit"}


def test_two_packages_shipping_the_same_driver_name_the_first(registry):
    drivers.load([DUMMY, ep("again", "tests.fixtures.hssh_dummy:make")])
    assert drivers.BROKEN == {
        "again": "ValueError: 'dummy@ssh' is already registered (entry point dummy (tests.fixtures.hssh_dummy:DRIVERS))"}
    assert drivers.SOURCES["dummy@ssh"] == "entry point dummy (tests.fixtures.hssh_dummy:DRIVERS)"


# --- the installed ones ---------------------------------------------------------

def test_the_installed_entry_points_never_include_hsshs_own(registry, monkeypatch):
    """h-ssh declares its built-ins as an entry point too (pyproject.toml), so
    the installed h-ssh lists one in the group; loading it again would make
    every built-in a duplicate of itself."""
    assert all(e.value.split(":")[0].split(".")[0] != "hssh" for e in drivers._installed_entry_points())
    own = ep("builtin", "hssh.drivers:BUILTIN")
    with monkeypatch.context() as m:
        m.setattr(drivers.metadata, "entry_points",
                  lambda **kw: [own, DUMMY] if kw.get("group") == GROUP else [])
        assert list(drivers._installed_entry_points()) == [DUMMY]
        drivers.load()
        assert drivers.BROKEN == {}
        assert set(drivers.DRIVERS) == BUILTIN_NAMES | {"dummy@ssh"}
        assert drivers.SOURCES["dummy@ssh"] == "entry point dummy (tests.fixtures.hssh_dummy:DRIVERS)"


def test_load_with_no_argument_is_the_builtins_and_what_is_installed(registry, installed):
    drivers.load()
    assert drivers.BROKEN == {}
    assert BUILTIN_NAMES <= set(drivers.DRIVERS)                   # a subset, not the total
    assert installed <= set(drivers.DRIVERS) - BUILTIN_NAMES
    assert {drivers.SOURCES[n] for n in BUILTIN_NAMES} == {"built-in"}
    assert all(drivers.SOURCES[n] != "built-in" for n in set(drivers.DRIVERS) - BUILTIN_NAMES)


def test_pyproject_declares_the_builtins_as_the_first_entry_point():
    lines = PYPROJECT.read_text(encoding="utf-8").splitlines()
    header = f'[project.entry-points."{GROUP}"]'
    assert header in lines, f"{PYPROJECT} has no {header} table"
    table = []
    for line in lines[lines.index(header) + 1:]:
        if line.startswith("["):
            break
        table.append(line.strip())
    assert 'builtin = "hssh.drivers:BUILTIN"' in table
    assert GROUP == "hssh.drivers"
    assert ep("builtin", "hssh.drivers:BUILTIN").load() is drivers.BUILTIN


# --- what the operator sees -----------------------------------------------------

def test_list_vendors_shows_the_driver_with_its_source_and_the_broken_entry_point(registry, monkeypatch, capsys):
    drivers.load([DUMMY, BROKEN])
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--list-vendors"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 0 and err == ""
    lines = out.splitlines()
    assert lines[0].split() == ["name", "aliases", "transport", "dialect", "formats", "supports", "source"]
    assert lines[1].startswith("junos@netconf  junos ") and lines[1].endswith("  built-in")
    assert re.fullmatch(r"dummy@ssh\s+-\s+ssh\s+dummy\s+text\s+show show_batch\s+"
                        r"entry point dummy \(tests\.fixtures\.hssh_dummy:DRIVERS\)", lines[-2]), lines[-2]
    assert lines[-1] == f"broken entry point 'broken': {BROKEN_WHY}"
    assert len(lines) == 1 + len(drivers.DRIVERS) + 1          # the header, a row per driver, the broken line
    assert all(any(ln.startswith(f"{name}  ") for ln in lines[1:-1]) for name in BUILTIN_NAMES)
    assert "Traceback" not in out


# --- the contract and the runner ------------------------------------------------

def test_the_contract_holds_for_the_driver_from_outside(registry):
    """What tests/drivers/test_contract.py asserts for every registered driver,
    for this one: the paramiko module backs `show` and `show_batch` in the
    shape the runner calls them."""
    drivers.load([DUMMY])
    dummy = drivers.get("dummy@ssh")
    module = drivers.module_of(dummy)
    assert module.__name__ == "hssh.transports.ssh"
    assert contract.violations(dummy, module) == []


def test_the_runner_binds_the_driver_from_outside_to_its_transport(registry):
    drivers.load([DUMMY])
    bound = runner.bind("dummy@ssh")
    assert bound.caps == frozenset({"show", "show_batch"})
    assert bound.hint == "dummy@ssh" and bound.dialect.name == "dummy"
    assert bound.mod.__name__ == "hssh.transports.ssh"


def test_a_stand_in_module_does_the_drivers_work(registry, monkeypatch):
    """What an embedding application (or a test) puts in drivers.MODULES under
    the driver's name is what the runner calls, with the driver's own name
    as the vendor_hint; what the stand-in lacks is refused by name."""
    drivers.load([DUMMY])
    seen = []

    def show(host, user, passwd, cmd, session_timeout, command_timeout, port=None, vendor_hint=None):
        seen.append((host, cmd, port, vendor_hint))
        return "dummy says hello\n"
    monkeypatch.setitem(drivers.MODULES, "dummy@ssh", types.SimpleNamespace(AVAILABLE=True, show=show))
    assert runner.bind("dummy@ssh").caps == frozenset({"show"})
    name, ok, out, _ = run("dummy@ssh")
    assert ok is True, out
    assert "VENDOR: dummy@ssh" in out and "dummy says hello" in out
    assert seen == [("10.0.0.1", "show version", None, "dummy@ssh")]
    _, ok, out, _ = run("dummy@ssh", mode="rollback", rollback=1)
    assert ok is False and "--rollback is not supported by the 'dummy@ssh' transport" in out
    assert seen == [("10.0.0.1", "show version", None, "dummy@ssh")]


def test_a_dialect_from_another_package_ships_its_own_shortcuts(registry):
    """`shortcuts` names the built-in library by stem and another package's by
    path, so `-sC whoami` resolves through the fixture's own dummy.json; the
    operator's ~/.h-ssh/commands files still go on top."""
    from hssh.core import resolve_command, get_available_commands
    drivers.load([DUMMY])
    assert resolve_command("whoami", "dummy@ssh") == "show dummy identity"
    assert "whoami" in get_available_commands("dummy@ssh")
    assert resolve_command("show version", "dummy@ssh") == "show version"   # not a shortcut: as typed
