"""#81: vendor knowledge lives with the dialect, not in core, cli, runner or
the telnet module. These tests pin what each dialect knows and that the
callers now ask it."""
import asyncio
import json
import re
import sys
import types
from pathlib import Path

import pytest

from hssh import cli, core, dialects, drivers, runner
from hssh.core import Target, refusal_line, resolve_command, get_available_commands
from hssh.dialects.base import CliSyntax, Dialect
from hssh.vendors import telnet
from tests.test_cli_runfile import run as run_cli

HERE = Path(__file__).resolve().parent.parent.parent / "hssh" / "dialects"


# --- what each dialect knows -----------------------------------------------------

def test_the_registry_uses_the_dialect_modules():
    assert drivers.JUNOS is dialects.junos.DIALECT and drivers.NONE is dialects.none.DIALECT
    assert [d.name for d in dialects.ALL] == ["junos", "ios", "nxos", "eos", "none"]
    assert set(drivers.DIALECTS) == {d.name for d in dialects.ALL}
    assert {d.title for d in dialects.ALL} == {"Junos", "IOS", "NX-OS", "EOS", "generic"}


def test_only_junos_has_an_edit_guard_a_candidate_and_a_pending_note():
    for d in dialects.ALL:
        assert (d.check_edit is not None) == (d.name == "junos")
        assert d.cli.has_candidate == (d.name == "junos")
        assert (d.commit_pending is not None) == (d.name == "junos")
    j = dialects.junos.DIALECT
    assert j.check_edit("set system host-name R1") == (True, "")
    assert j.check_edit("commit", allow_commit=True) == (True, "")
    assert not j.check_edit("commit", allow_commit=False)[0]
    assert not j.check_edit("configure\nset x")[0]
    assert j.cli.config_enter == "configure exclusive" and j.cli.compare == "show | compare"
    assert j.cli.discard == "rollback 0" and j.cli.commit == "commit" and j.cli.config_exit == "exit"
    m = j.commit_pending.search("0 2026-10-22 08:00:00 UTC by lab via cli commit confirmed, rollback in 5mins")
    assert m and m.group(1) == "5"


def test_core_still_exports_the_junos_guard_for_importers():
    assert core.validate_junos_set_syntax is dialects.junos.check_edit
    assert core.JUNOS_SET_PREFIX_VERBS is dialects.junos.SET_PREFIX_VERBS


def test_ios_shaped_dialects_share_one_cli_and_refusal():
    ios, nxos, eos, none = (dialects.ios.DIALECT, dialects.nxos.DIALECT, dialects.eos.DIALECT, dialects.none.DIALECT)
    assert ios.cli is nxos.cli is eos.cli is none.cli
    assert ios.cli.config_enter == "configure terminal" and ios.cli.config_exit == "end"
    assert ios.refused is nxos.refused is eos.refused
    assert ios.refused.search("% Invalid input detected at '^' marker.")
    assert not ios.refused.search("error: syntax error")
    for prompt in ("Router>", "Router#", "Router(config)#", "Switch(config-if-Et1/1)# "):
        assert ios.cli.prompt.search(prompt)
    assert dialects.junos.DIALECT.cli.prompt.search("lab@r1> ") and not dialects.junos.DIALECT.cli.prompt.search("Router#")


def test_how_each_dialect_refuses_a_line():
    j, n = dialects.junos.DIALECT, dialects.none.DIALECT
    for text in ("error: syntax error", "  syntax error, expecting <command>", "commit failed: x", "unknown command"):
        assert j.refused.search(text), text
    assert not j.refused.search("description error-disabled")
    # `none` knows both ways a CLI says no, as the plain ssh/openssh transports always did.
    assert n.refused.search("error: syntax error") and n.refused.search("% Invalid input")
    assert refusal_line("ok\nerror: syntax error\nmore") == "error: syntax error"
    assert refusal_line("\n\n  % Bad command\n") == "% Bad command"
    assert refusal_line("fine", dialect=j) is None
    assert refusal_line("% Invalid input", dialect=j) is None            # not how Junos says no
    assert refusal_line("% Invalid input", dialect=dialects.eos.DIALECT) == "% Invalid input"
    assert refusal_line("commit failed: x", dialect=j) == "commit failed: x"


def test_a_cli_that_commits_needs_compare_and_discard():
    with pytest.raises(ValueError, match="compare and discard"):
        CliSyntax(prompt=re.compile("x"), prompt_name=re.compile("(x)"), prompt_tail="", config_enter="c",
                  config_exit="e", commit="commit")


# --- shortcut libraries next to the dialects ----------------------------------------

def test_shipped_libraries_sit_next_to_their_dialect():
    for d in dialects.ALL:
        if d.shortcuts:
            assert (HERE / f"{d.shortcuts}.json").is_file(), d.name
    assert sorted(p.name for p in HERE.glob("*.json")) == ["eos.json", "junos.json", "none.json"]
    assert "bgp" in json.loads((HERE / "eos.json").read_text())


def test_shortcuts_follow_the_dialect_for_every_driver_name():
    assert resolve_command("bgp", "junos") == resolve_command("bgp", "junos@netconf") == "show bgp summary | no-more"
    # New with #81: the telnet Junos driver gets the Junos library too.
    assert resolve_command("bgp", "telnet-junos") == resolve_command("bgp", "junos@telnet") == "show bgp summary | no-more"
    assert resolve_command("uptime", "ssh") == resolve_command("uptime", "none@openssh") == "uptime"
    assert get_available_commands("telnet-ios") == {} and get_available_commands("nope") == {}
    assert get_available_commands("arista") == {}


def test_operator_overrides_by_dialect_name_and_by_the_name_typed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    d = tmp_path / ".h-ssh" / "commands"
    d.mkdir(parents=True)
    (d / "junos.json").write_text(json.dumps({"mine": "show mine", "bgp": "show bgp summary"}))
    (d / "ssh.json").write_text(json.dumps({"uptime": "uptime -p"}))
    assert resolve_command("mine", "junos") == "show mine"
    assert resolve_command("bgp", "junos") == "show bgp summary"             # override wins over shipped
    assert resolve_command("mine", "junos@telnet") == "show mine"           # by dialect, for every driver
    assert resolve_command("uptime", "ssh") == "uptime -p"                   # the pre-#81 file name still counts
    assert resolve_command("uptime", "openssh") == "uptime"                  # ...for the name it was written for


# --- the callers ask the dialect -----------------------------------------------------

def test_the_runner_asks_the_dialect_which_commands_read(monkeypatch):
    calls = []

    def show(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        calls.append(cmd)
        raise RuntimeError("boom")
    monkeypatch.setattr(runner.time, "sleep", lambda s: None)
    fake = types.SimpleNamespace(AVAILABLE=True, show=show)
    import hssh.vendors as vendors
    monkeypatch.setitem(vendors.VENDORS, "junos", fake)
    strict = Dialect("strict", "Strict", "nothing is a read", is_read=lambda c: False)
    monkeypatch.setitem(drivers.DRIVERS, "junos@netconf",
                        drivers.Driver(strict, drivers.NETCONF, drivers.get("junos").supports, shim="junos"))
    runner.run_for_target(
        t=Target("R1", "10.0.0.1", "junos"), transport="junos", mode="show", show_cmd="show version",
        edit_cmd=None, config_dir=None, broadcast_file=None, user="u", passwd="p", session_timeout=5,
        command_timeout=30, dry_run=False, commit_confirmed=None, save_dir=None, quiet=True, max_attempts=3)
    assert calls == ["show version"]          # not a read for this dialect: sent once, never retried


def test_the_cli_guards_an_edit_by_the_targets_dialect(monkeypatch, capsys, tmp_path):
    rc, out, err, drv = run_cli(monkeypatch, capsys, tmp_path,
                                ["--user", "u", "--target", "R1:10.0.0.1:junos@netconf", "-eC", "configure", "-y"])
    assert rc == 2 and "ERROR: Junos -eC only accepts 'set ...' commands" in err and drv.edits == []
    rc, out, err, drv = run_cli(monkeypatch, capsys, tmp_path,
                                ["--user", "u", "--target", "R1:10.0.0.1:junos@netconf", "-eC", "set system host-name x", "-y"])
    assert rc == 0, err
    assert len(drv.edits) == 1


def test_edit_guard_is_none_for_guardless_or_unknown_vendors():
    assert cli.edit_guard("junos") is cli.edit_guard("telnet-junos") is dialects.junos.DIALECT
    assert cli.edit_guard("ssh") is None and cli.edit_guard("ios@telnet") is None
    assert cli.edit_guard("nope") is None and cli.edit_guard("arista") is None


def test_the_preflight_wants_a_banner_only_where_the_transport_has_one(monkeypatch):
    class Reader:
        def __init__(self, line):
            self.line = line

        async def readline(self):
            return self.line

    class Writer:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def open_connection(host, port):
        return Reader(b"220 telnet banner\r\n"), Writer()

    async def getaddrinfo(host, port):
        return []
    monkeypatch.setattr(cli.asyncio, "open_connection", open_connection)

    async def go():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "getaddrinfo", getaddrinfo)
        ssh = await cli.check_reachability(Target("R1", "10.0.0.1", "none@ssh"))
        tn = await cli.check_reachability(Target("R1", "10.0.0.1", "ios@telnet"))
        return ssh, tn
    ssh, tn = asyncio.run(go())
    assert ssh == ("R1", False, "port 22 open but no SSH banner")
    assert tn == ("R1", True, "reachable")


def test_telnet_maps_its_hints_to_dialects():
    assert telnet._dialect("telnet-junos") is dialects.junos.DIALECT
    assert telnet._dialect("junos@telnet") is dialects.junos.DIALECT
    assert telnet._dialect("telnet-ios") is dialects.ios.DIALECT
    assert telnet._dialect("telnet-arista") is dialects.eos.DIALECT
    assert telnet._dialect("telnet") is dialects.none.DIALECT
    assert telnet._dialect(None) is dialects.none.DIALECT
    assert telnet._dialect("made-up") is dialects.none.DIALECT
    assert telnet.PROMPT_PATTERNS["junos"] is dialects.junos.CLI.prompt


def test_telnet_learns_the_prompt_from_the_dialects_shape():
    j, i = dialects.junos.CLI, dialects.ios.CLI
    learned = telnet._learn_prompt("welcome\nlab@r1.example> ", j.prompt, j)
    assert learned.search("lab@r1.example# ") and not learned.search("other@r1.example# ")
    learned = telnet._learn_prompt("Router#", i.prompt, i)
    assert learned.search("Router(config-if)#") and not learned.search("Switch#")
