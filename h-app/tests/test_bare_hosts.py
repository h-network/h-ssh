"""Targets typed bare on the command line: `h-ssh 10.0.0.1 10.0.0.2 -sC version`
reaches two devices named after their hosts on --transport, the --target
syntax works bare too, and with a target typed the inventory is not read."""

import asyncio
import os
import sys
import types

import pytest

from hssh import cli, drivers
from hssh.core import Target, parse_bare_target


def test_a_bare_word_is_a_device_named_after_its_host():
    assert parse_bare_target("10.0.0.1", "ssh") == Target(name="10.0.0.1", host="10.0.0.1", vendor="ssh")
    assert parse_bare_target("cr1.example.net", "junos") == Target(name="cr1.example.net", host="cr1.example.net", vendor="junos")
    assert parse_bare_target("[2001:db8::1]", "junos") == Target(name="2001:db8::1", host="2001:db8::1", vendor="junos")
    assert parse_bare_target("cr1:10.0.0.1:junos", "ssh") == Target(name="cr1", host="10.0.0.1", vendor="junos")
    assert parse_bare_target("sw1:10.0.0.2:5000:telnet-ios", "ssh") == Target(name="sw1", host="10.0.0.2", vendor="telnet-ios", port=5000)
    assert parse_bare_target("R1:[2001:db8::1]:junos", "ssh") == Target(name="R1", host="2001:db8::1", vendor="junos")
    with pytest.raises(ValueError):
        parse_bare_target("", "ssh")
    with pytest.raises(ValueError):
        parse_bare_target("cr1:10.0.0.1:junos:notaport", "ssh")


def run(monkeypatch, capsys, argv, driver_names=("none@ssh", "junos@netconf", "ios@telnet")):
    seen = []

    def show(host, user, passwd, cmd, *a, **kw):
        seen.append((host, kw.get("vendor_hint")))
        return f"reply from {host}"

    fake = types.SimpleNamespace(AVAILABLE=True, show=show)
    for name in driver_names:
        monkeypatch.setitem(drivers.MODULES, name, fake)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", *argv])
    try:
        rc = asyncio.run(cli.main())
    except SystemExit as e:
        rc = e.code
    out, err = capsys.readouterr()
    return rc, out, err, seen


def test_bare_hosts_reach_the_devices_on_the_default_transport(monkeypatch, capsys):
    rc, out, err, seen = run(monkeypatch, capsys, ["10.0.0.1", "10.0.0.2", "-sC", "show version"])
    assert rc == 0, err
    assert sorted(h for h, _ in seen) == ["10.0.0.1", "10.0.0.2"]
    assert all(v == "none@ssh" for _, v in seen)                  # --transport defaults to ssh
    assert "Targets: 2 (inline)" in out


def test_hosts_may_follow_the_flags_and_carry_the_target_syntax(monkeypatch, capsys):
    rc, out, err, seen = run(monkeypatch, capsys, ["-sC", "show version", "cr1:10.0.0.1:junos", "10.0.0.2", "--transport", "junos"])
    assert rc == 0, err
    assert sorted(seen) == [("10.0.0.1", "junos@netconf"), ("10.0.0.2", "junos@netconf")]


def test_bare_hosts_and_target_flags_add_up_and_the_inventory_is_not_read(monkeypatch, capsys, tmp_path):
    missing = tmp_path / "nowhere.csv"
    rc, out, err, seen = run(monkeypatch, capsys, ["10.0.0.1", "--target", "R2:10.0.0.2:junos", "--devices", str(missing),
                                                    "-sC", "show version"])
    assert rc == 0, err
    assert sorted(seen) == [("10.0.0.1", "none@ssh"), ("10.0.0.2", "junos@netconf")]


def test_the_target_flag_itself_stays_strict(monkeypatch, capsys):
    """`--target 10.0.0.1` is still the usage error it was: the host-only form
    is for the bare word, so a --target that forgot its host is not a guess."""
    rc, out, err, seen = run(monkeypatch, capsys, ["--target", "10.0.0.1", "-sC", "show version"])
    assert rc == 2 and "Invalid target" in err and "Traceback" not in err and seen == []


def test_the_same_device_twice_is_refused_bare_as_well(monkeypatch, capsys):
    rc, out, err, seen = run(monkeypatch, capsys, ["10.0.0.1", "10.0.0.1", "-sC", "show version"])
    assert rc == 2 and "inline targets" in err and seen == []
    rc, out, err, seen = run(monkeypatch, capsys, ["R1:10.0.0.1:junos", "R2:10.0.0.1:junos", "-sC", "show version"])
    assert rc == 2 and "inline targets" in err and seen == []


def test_a_bare_ipv6_host_goes_in_brackets(monkeypatch, capsys):
    rc, out, err, seen = run(monkeypatch, capsys, ["[2001:db8::1]", "-sC", "show version"])
    assert rc == 0, err
    assert seen == [("2001:db8::1", "none@ssh")]


def test_without_a_target_the_inventory_is_read_as_before(monkeypatch, capsys, tmp_path):
    csv = tmp_path / "devices.csv"
    csv.write_text("name,ip,vendor\nR1,10.0.0.9,junos\n")
    rc, out, err, seen = run(monkeypatch, capsys, ["--devices", str(csv), "-sC", "show version"])
    assert rc == 0, err
    assert seen == [("10.0.0.9", "junos@netconf")] and "(inline)" not in out


def test_the_help_shows_the_hosts(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--help"])
    with pytest.raises(SystemExit) as e:
        asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert e.value.code == 0 and "[HOST ...]" in out and "name:host[:vendor][:port]" in out


async def _reachable(target, timeout=2):
    return (target.name, True, "reachable")


def test_a_bare_host_edits_and_the_confirm_hint_keeps_it_bare(monkeypatch, capsys):
    edits = []

    def edit(host, user, passwd, payload, *a, **kw):
        edits.append(host)
        return "COMMIT CONFIRMED (2 minutes)\n\nDIFF:\n+ x\n"

    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(AVAILABLE=True, edit=edit))
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--transport", "junos", "10.0.0.1",
                                      "-y", "--commit-confirmed", "2", "-eC", "set system host-name x"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 0, err
    assert edits == ["10.0.0.1"]
    assert "DON'T FORGET TO CONFIRM THE COMMIT!" in out
    assert ' -eC "commit" --user u 10.0.0.1 --transport junos\n' in out and "--target" not in out
