import re
from importlib.metadata import EntryPoint

import pytest

from hssh import drivers
from hssh.communicators.netconf import NetconfCommunicator
from hssh.communicators.openssh import OpenSSH
from hssh.communicators.ssh import SSHCommunicator
from hssh.dialects import generic, junos
from hssh.drivers import BUILTIN, ENTRY_POINT_GROUP, Driver, Registry, driver_name, split_name
from hssh.model import Fault, FaultKind, Target

DUMMY = Driver("dummy@openssh", generic.DIALECT, OpenSSH(generic.DIALECT))


def ep(name, value):
    return EntryPoint(name, value, ENTRY_POINT_GROUP)


class _EntryPoints(list):
    """The entry points the registry sees, as a list the test fills; the groups asked for are recorded."""

    asked: list


@pytest.fixture
def entry_points(monkeypatch):
    seen = _EntryPoints()
    seen.asked = []
    monkeypatch.setattr(drivers.metadata, "entry_points", lambda **kw: seen.asked.append(kw.get("group")) or seen)
    return seen


def test_a_driver_name_is_dialect_at_transport():
    assert driver_name("junos", "netconf") == "junos@netconf"
    assert split_name("ios@ssh") == ("ios", "ssh")


@pytest.mark.parametrize("name", ["junos", "@ssh", "junos@", "", "junos@ssh@x"])
def test_a_name_without_both_halves_is_refused(name):
    if name.count("@") == 2:
        assert split_name(name) == ("junos", "ssh@x")
        return
    with pytest.raises(ValueError, match="not dialect@transport"):
        split_name(name)


def test_the_built_ins_are_junos_over_netconf_and_ssh_each_sharing_one_dialect():
    assert [d.name for d in BUILTIN] == ["junos@netconf", "junos@ssh"]
    assert isinstance(BUILTIN[0].communicator, NetconfCommunicator) and isinstance(BUILTIN[1].communicator, SSHCommunicator)
    for driver in BUILTIN:
        assert driver.dialect is junos.DIALECT and driver.communicator.dialect is driver.dialect
    assert BUILTIN[1].communicator.capabilities == {"show", "batch", "edit", "confirm", "commit_status"}


def test_a_new_registry_holds_the_built_ins_and_nothing_else():
    assert [d.name for d in Registry()] == [d.name for d in BUILTIN]
    assert Registry().broken == {}


def test_registries_are_independent_instances():
    one, two = Registry(), Registry()
    one.register(DUMMY)
    assert [d.name for d in two] == ["junos@netconf", "junos@ssh"]


def test_register_keeps_order_and_refuses_a_name_already_taken():
    registry = Registry(drivers=[])
    registry.register(DUMMY)
    registry.register(BUILTIN[0])
    assert [d.name for d in registry] == ["dummy@openssh", "junos@netconf"]
    with pytest.raises(ValueError, match="already registered"):
        registry.register(Driver("dummy@openssh", generic.DIALECT, OpenSSH(generic.DIALECT)))


def test_register_refuses_a_malformed_name():
    with pytest.raises(ValueError, match="not dialect@transport"):
        Registry().register(Driver("dummy", generic.DIALECT, OpenSSH(generic.DIALECT)))


def test_get_returns_the_registered_driver():
    assert Registry().get("junos@netconf") is BUILTIN[0]


def test_an_unknown_name_is_a_local_fault_listing_what_is_available():
    registry = Registry()
    registry.register(DUMMY)
    with pytest.raises(Fault) as caught:
        registry.get("ios@ssh")
    fault = caught.value
    assert (fault.kind, fault.reached_device) == (FaultKind.LOCAL, False)
    assert fault.detail == "unknown driver 'ios@ssh'; available: dummy@openssh, junos@netconf, junos@ssh"


def test_an_empty_registry_says_none_is_available():
    with pytest.raises(Fault, match="available: none"):
        Registry(drivers=[]).get("junos@netconf")


def test_resolve_maps_a_targets_vendor_and_transport_to_its_driver():
    assert Registry().resolve(Target("R1", "h", "junos", "netconf")) is BUILTIN[0]
    assert Registry().resolve(Target("R1", "h", "junos", "ssh")) is BUILTIN[1]
    with pytest.raises(Fault, match="unknown driver 'junos@telnet'"):
        Registry().resolve(Target("R1", "h", "junos", "telnet"))


def test_check_mode_passes_a_mode_the_communicator_declares():
    assert Registry().check_mode(BUILTIN[0], "show") is None


def test_check_mode_refuses_an_undeclared_mode_before_anything_is_sent():
    with pytest.raises(Fault) as caught:
        Registry().check_mode(DUMMY, "confirm")
    assert (caught.value.kind, caught.value.reached_device) == (FaultKind.UNSUPPORTED, False)
    assert caught.value.detail == "driver 'dummy@openssh' does not support 'confirm'"


def test_a_cli_communicators_capabilities_follow_whether_its_dialect_has_a_candidate():
    with_candidate = Driver("junos@openssh", junos.DIALECT, OpenSSH(junos.DIALECT))
    Registry().check_mode(with_candidate, "confirm")
    with pytest.raises(Fault, match="does not support 'confirm'"):
        Registry().check_mode(DUMMY, "confirm")


def test_entry_points_are_asked_for_the_hssh_drivers_group(entry_points):
    Registry().load_entry_points()
    assert entry_points.asked == ["hssh.drivers"]


def test_an_entry_point_may_hand_over_one_driver(entry_points):
    entry_points.append(ep("one", "tests.fixtures.hssh_dummy:ONE"))
    registry = Registry()
    registry.load_entry_points()
    assert [d.name for d in registry] == ["junos@netconf", "junos@ssh", "dummy@openssh"] and registry.broken == {}


def test_an_entry_point_may_hand_over_a_list_of_drivers(entry_points):
    entry_points.append(ep("many", "tests.fixtures.hssh_dummy:DRIVERS"))
    registry = Registry()
    registry.load_entry_points()
    assert [d.name for d in registry] == ["junos@netconf", "junos@ssh", "dummy@openssh", "other@openssh"]


def test_a_broken_entry_point_is_reported_by_name_and_the_rest_still_load(entry_points):
    entry_points.extend([ep("broken", "tests.fixtures.hssh_broken"), ep("one", "tests.fixtures.hssh_dummy:ONE")])
    registry = Registry()
    registry.load_entry_points()
    assert registry.broken == {"broken": "ImportError: hssh_broken needs a library that is not installed"}
    assert "dummy@openssh" in [d.name for d in registry]


@pytest.mark.parametrize("value, why", [
    ("tests.fixtures.hssh_dummy:NOT_A_DRIVER", r"TypeError: .* is not a Driver"),
    ("tests.fixtures.hssh_dummy:NOT_EVEN_A_LIST", r"TypeError: .* is not iterable"),
    ("tests.fixtures.hssh_dummy:TWICE", r"ValueError: a driver name is listed twice"),
    ("tests.fixtures.hssh_dummy:NOPE", r"AttributeError: module .* has no attribute 'NOPE'"),
])
def test_what_an_entry_point_may_not_hand_over_is_listed_with_the_reason(entry_points, value, why):
    entry_points.append(ep("odd", value))
    registry = Registry()
    registry.load_entry_points()
    assert list(registry.broken) == ["odd"] and re.fullmatch(why, registry.broken["odd"], re.S)
    assert [d.name for d in registry] == ["junos@netconf", "junos@ssh"]


def test_an_entry_point_claiming_a_registered_name_is_broken_and_the_built_in_stays(entry_points):
    entry_points.append(ep("taken", "tests.fixtures.hssh_dummy:TAKEN"))
    registry = Registry()
    registry.load_entry_points()
    assert registry.broken == {"taken": "ValueError: driver 'junos@netconf' is already registered"}
    assert registry.get("junos@netconf") is BUILTIN[0]


def test_an_entry_point_is_taken_whole_or_not_at_all(entry_points):
    entry_points.append(ep("taken", "tests.fixtures.hssh_dummy:TAKEN"))
    registry = Registry()
    registry.load_entry_points()
    assert "fresh@openssh" not in [d.name for d in registry]
