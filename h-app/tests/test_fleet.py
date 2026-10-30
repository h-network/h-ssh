"""The Fleet library API and the target parsing it shares with the CLI."""

import logging

import pytest

from cli_helpers import report
from hssh.frontends import fleet
from hssh.model import EditSettings, Target, Timeouts
from hssh.orchestrator import DEFAULT_POLICY, DEFAULT_TIMEOUTS, DEFAULT_WORKERS


@pytest.fixture
def runner():
    seen = []

    def run(spec):
        seen.append(spec)
        return report(spec)

    run.seen = seen
    return run


def test_targets_in_every_form(tmp_path, runner):
    inventory = tmp_path / "inv.csv"
    inventory.write_text("name,ip,vendor,port\ncsv1,10.0.0.5,junos,830\n")
    f = fleet.Fleet(["10.0.0.1", "R2:10.0.0.2:junos:830", Target("R3", "10.0.0.3", "junos", "netconf"), inventory],
                    transport="netconf", vendor="junos", user="u", runner=runner)
    assert [(t.name, t.host, t.vendor, t.transport, t.port) for t in f.targets] == [
        ("10.0.0.1", "10.0.0.1", "junos", "netconf", None), ("R2", "10.0.0.2", "junos", "netconf", 830),
        ("R3", "10.0.0.3", "junos", "netconf", None), ("csv1", "10.0.0.5", "junos", "netconf", 830)]
    assert len(f) == 4


def test_one_string_that_is_a_file_is_the_inventory(tmp_path, runner):
    inventory = tmp_path / "inv.csv"
    inventory.write_text("r1\nr2\n")
    assert [t.name for t in fleet.Fleet(str(inventory), transport="netconf", vendor="junos", user="u", runner=runner).targets] == ["r1", "r2"]


def test_no_targets_is_refused(tmp_path, runner):
    empty = tmp_path / "empty.csv"
    empty.write_text("# nothing\n")
    with pytest.raises(ValueError, match="no targets"):
        fleet.Fleet(empty, transport="netconf", vendor="junos", user="u", runner=runner)


@pytest.mark.parametrize("spec, expected", [
    ("10.0.0.1", ("10.0.0.1", "10.0.0.1", "junos", None)),
    ("[2001:db8::1]", ("2001:db8::1", "2001:db8::1", "junos", None)),
    ("R1:10.0.0.1", ("R1", "10.0.0.1", "junos", None)),
    ("R1:10.0.0.1:ios", ("R1", "10.0.0.1", "ios", None)),
    ("R1:10.0.0.1:2222", ("R1", "10.0.0.1", "junos", 2222)),
    ("R1:10.0.0.1:ios:2222", ("R1", "10.0.0.1", "ios", 2222)),
    ("R1:10.0.0.1:2222:IOS", ("R1", "10.0.0.1", "ios", 2222)),
    ("R1:[2001:db8::1]:830:junos", ("R1", "2001:db8::1", "junos", 830)),
])
def test_parse_target_forms(spec, expected):
    t = fleet.parse_target(spec, "netconf", "junos")
    assert (t.name, t.host, t.vendor, t.port) == expected and t.transport == "netconf"


@pytest.mark.parametrize("spec", ["", "a:b:c:d:e"])
def test_parse_target_refuses_what_is_not_a_target(spec):
    with pytest.raises(ValueError, match="invalid target"):
        fleet.parse_target(spec, "netconf")


def test_the_inventory_takes_headers_or_none_comments_and_a_bom(tmp_path):
    csv = tmp_path / "inv.csv"
    csv.write_text("﻿# fleet\nname,ip\nr1,10.0.0.1 # core\n\nr2,10.0.0.2,ios,2222\n")
    targets = fleet.load_devices_csv(str(csv), "ssh", "junos")
    assert [(t.name, t.host, t.vendor, t.port) for t in targets] == [("r1", "10.0.0.1", "junos", None), ("r2", "10.0.0.2", "ios", 2222)]


def test_a_wide_inventory_row_is_named(tmp_path):
    csv = tmp_path / "inv.csv"
    csv.write_text("r1,10.0.0.1,junos,830,extra\n")
    with pytest.raises(ValueError, match="row 1: 5 columns"):
        fleet.load_devices_csv(str(csv), "ssh")


@pytest.mark.parametrize("specs, message", [
    (["R1:10.0.0.1", "R1:10.0.0.2"], "device name 'R1' is used for two hosts: 10.0.0.1 and 10.0.0.2"),
    (["R1:10.0.0.1", "R2:10.0.0.1"], "host 10.0.0.1 is listed under two names: 'R1' and 'R2'"),
    (["R1:10.0.0.1", "R1:10.0.0.1"], "device 'R1' \\(10.0.0.1\\) is listed twice"),
    (["R1:10.0.0.1", "R2:10.0.0.1:830"], "host 10.0.0.1:830 is listed under two names"),
])
def test_one_device_is_one_entry(specs, message):
    with pytest.raises(ValueError, match=message):
        fleet.as_targets(specs, "netconf", "junos")


def test_another_port_is_another_device():
    assert len(fleet.as_targets(["R1:10.0.0.1", "R2:10.0.0.1:22"], "netconf", "junos")) == 2


def test_the_fleets_settings_ride_every_spec(runner):
    f = fleet.Fleet(["R1:10.0.0.1"], transport="netconf", vendor="junos", user="u", password="p", workers=3,
                    timeouts=Timeouts(1, 2, 3, 4), host_key_policy="strict", probe=False, runner=runner)
    f.show("show version")
    spec = runner.seen[0]
    assert spec.mode == "show" and spec.commands == ("show version",)
    assert (spec.credentials.username, spec.credentials.password) == ("u", "p")
    assert (spec.workers, spec.timeouts, spec.host_key_policy, spec.probe) == (3, Timeouts(1, 2, 3, 4), "strict", False)
    assert spec.safety is None and spec.recording is None


def test_the_defaults_are_the_orchestrators(runner, monkeypatch):
    monkeypatch.setattr(fleet, "default_username", lambda: "login")
    f = fleet.Fleet(["R1:10.0.0.1"], transport="netconf", vendor="junos", runner=runner)
    f.show("x")
    spec = runner.seen[0]
    assert (spec.workers, spec.timeouts, spec.policy) == (DEFAULT_WORKERS, DEFAULT_TIMEOUTS, DEFAULT_POLICY)
    assert spec.credentials.username == "login" and spec.credentials.password is None


def test_each_method_is_one_mode(runner):
    f = fleet.Fleet(["R1:10.0.0.1"], transport="netconf", vendor="junos", user="u", runner=runner)
    f.batch(["show a", "show b"])
    f.structured("get-software-information", "xml")
    f.confirm()
    f.commit_status()
    modes = [(s.mode, s.commands, s.format) for s in runner.seen]
    assert modes == [("batch", ("show a", "show b"), None), ("structured", ("get-software-information",), "xml"),
                     ("confirm", (), None), ("commit_status", (), None)]


def test_edit_builds_the_edit_settings(runner):
    f = fleet.Fleet(["R1:10.0.0.1"], transport="netconf", vendor="junos", user="u", runner=runner)
    f.edit(["set x"])
    assert runner.seen[0].edit == EditSettings(apply=False) and runner.seen[0].skip_unreachable is False
    f.edit(["set x"], apply=True, confirmed_minutes=5, comment="c", skip_unreachable=True)
    assert runner.seen[1].edit == EditSettings(apply=True, confirmed_minutes=5, comment="c") and runner.seen[1].skip_unreachable is True


def test_the_fleet_adds_a_null_handler_and_leaves_the_level_alone(runner):
    for name in fleet.LIBRARY_LOGGERS:
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).setLevel(logging.NOTSET)
    fleet.Fleet(["R1:10.0.0.1"], transport="netconf", vendor="junos", user="u", runner=runner)
    for name in fleet.LIBRARY_LOGGERS:
        assert [type(h) for h in logging.getLogger(name).handlers] == [logging.NullHandler]
        assert logging.getLogger(name).level == logging.NOTSET


def test_repr_and_len(runner):
    f = fleet.Fleet(["a", "b"], transport="netconf", vendor="junos", user="u", runner=runner)
    assert repr(f) == "Fleet(2 targets, user='u')" and len(f) == 2
