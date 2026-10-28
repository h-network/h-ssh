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
from hssh.transports import telnet
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


def test_an_ios_warning_is_no_refusal():
    """#142: IOS says `%` first of a line it took as well as of one it
    refused, so a lines edit that stops at a refused line stopped at a
    `% Warning: use /31 mask ...`, and at the note that `vrf forwarding`
    took the interface's addresses, the next line's to put back. The
    IOS-shaped dialects name what IOS says of a line it took
    (`informational`), and a line it matches is no refusal; a refusal after
    it still is. Junos and `none` have none: their rule stays."""
    ios, nxos, eos = dialects.ios.DIALECT, dialects.nxos.DIALECT, dialects.eos.DIALECT
    assert ios.informational is nxos.informational is eos.informational
    assert dialects.junos.DIALECT.informational is None and dialects.none.DIALECT.informational is None
    for line in ("%Warning: portfast should only be enabled on ports connected to a single",
                 "% Warning: use /31 mask on non point-to-point interface cautiously", "% WARNING: low memory",
                 "% Interface GigabitEthernet0/1 IPv4 disabled and address(es) removed due to enabling VRF CUST",
                 "% Interface FastEthernet0/0 IP address 10.0.0.1 removed due to enabling VRF CUST",
                 "  % Interface Gi0/2 IPv4 disabled and address(es) removed due to disabling VRF CUST"):
        assert ios.informational.search(line), line
        assert refusal_line(line, dialect=eos) is None, line
    for line in ("% Invalid input detected at '^' marker.", "% Incomplete command.", '% Ambiguous command:  "sh"',
                 "% Interface Gi0/9 not found", "% Warnings are disabled"):
        assert not ios.informational.search(line) and refusal_line(line, dialect=ios) == line, line
    assert refusal_line("\n% Warning: use /31 mask\n\n   ^\n% Invalid input detected\n", dialect=ios) == \
        "% Invalid input detected"
    assert refusal_line("% Warning: use /31 mask", dialect=dialects.none.DIALECT) == "% Warning: use /31 mask"


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
    strict = Dialect("strict", "Strict", "nothing is a read", is_read=lambda c: False)
    driver = drivers.Driver(strict, drivers.NETCONF, drivers.get("junos").supports, aliases=("junos",))
    monkeypatch.setitem(drivers.DRIVERS, "junos@netconf", driver)   # what "junos" now resolves to
    monkeypatch.setitem(drivers.MODULES, driver.name, fake)          # and the module that does its work
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


def test_edit_guard_is_none_for_guardless_or_unknown_vendor_names():
    assert cli.edit_guard("junos") is cli.edit_guard("telnet-junos") is dialects.junos.DIALECT
    assert cli.edit_guard("ssh") is None and cli.edit_guard("ios@telnet") is None
    assert cli.edit_guard("nope") is None and cli.edit_guard("arista") is None


def test_the_probe_wants_a_banner_only_where_the_transport_has_one(monkeypatch):
    """The SSH transports' banner is what the probe checks the first line
    against; telnet has none, and a TCP connect is all it asks. Neither
    has a junos box on port 23, which PyEZ reaches as a console over
    telnet (the transport's console_port); on 22 it is NETCONF over SSH."""
    from hssh import drivers, probe
    asked = {}

    async def attempt(host, port, banner, seconds):
        asked[host] = (port, banner)
        return probe.Answer(probe.LIVE, connect_ms=0.3)
    monkeypatch.setattr(probe, "attempt", attempt)
    asyncio.run(probe.probe([Target("R1", "10.0.0.1", "none@ssh"), Target("SW", "10.0.0.2", "ios@telnet"),
                             Target("R3", "10.0.0.3", "junos"), Target("CON", "10.0.0.4", "junos", 23),
                             Target("R5", "10.0.0.5", "junos", 22)], 3))
    assert asked == {"10.0.0.1": (22, b"SSH-"), "10.0.0.2": (23, None), "10.0.0.3": (830, b"SSH-"),
                     "10.0.0.4": (23, None), "10.0.0.5": (22, b"SSH-")}
    assert {name: t.console_port for name, t in drivers.TRANSPORTS.items()} == {
        "netconf": 23, "ssh": None, "openssh": None, "telnet": None}


def test_the_probe_reads_the_ssh_config_where_the_transport_reads_it():
    """The OpenSSH client and PyEZ (the junos transport) read the ssh
    client's configuration and connect where it says, so the probe reads it
    for them, each the way it does; paramiko as the ssh transport and
    telnet read none. Every dialect on a transport gets the same."""
    from hssh import drivers
    readers = {name: d.transport.ssh_config for name, d in drivers.DRIVERS.items()}
    assert {readers[n] for n in ("junos@netconf",)} == {"paramiko"}
    assert {readers[n] for n in ("none@openssh", "junos@openssh", "ios@openssh", "eos@openssh")} == {"openssh"}
    assert {readers[n] for n in ("none@ssh", "junos@ssh", "ios@telnet", "junos@telnet")} == {None}


def test_telnet_maps_its_hints_to_dialects():
    assert telnet._dialect("telnet-junos") is dialects.junos.DIALECT
    assert telnet._dialect("junos@telnet") is dialects.junos.DIALECT
    assert telnet._dialect("telnet-ios") is dialects.ios.DIALECT
    assert telnet._dialect("telnet-arista") is dialects.eos.DIALECT
    assert telnet._dialect("telnet") is dialects.none.DIALECT
    assert telnet._dialect(None) is dialects.none.DIALECT
    assert telnet._dialect("made-up") is dialects.none.DIALECT
    assert telnet.PROMPT_PATTERNS["junos"] is dialects.junos.CLI.prompt


def test_a_prompt_name_starts_the_line():
    """#141 review: a prompt's name is where its line starts. Junos's was
    not anchored, and named `noc@example.net` in a banner line `Contact
    NOC <noc@example.net>`; IOS's already was."""
    from hssh import dialects
    junos = dialects.junos.DIALECT.cli.prompt_name
    assert junos.search("lab@r1> ").group(1) == "lab@r1" and junos.search("lab@r1# ").group(1) == "lab@r1"
    for banner in ("Unauthorized access prohibited. Contact NOC <noc@example.net>", "mail noc@example.net>",
                   "\x1b[?2004hlab@r1> "):
        assert junos.search(banner) is None
    ios = dialects.ios.DIALECT.cli.prompt_name
    assert ios.search("R1>").group(1) == "R1" and ios.search("report misuse to NOC-DESK>") is None


def test_the_cli_engine_learns_the_prompt_from_the_dialects_shape():
    """The prompt learned is the whole line from its start (#141): a reply
    line that only ends in it, `uplink to BackupRouter#`, is not `Router#`.
    Junos's `[edit]` banner, `{master}[edit]` with two routing engines, and
    the note above it while a commit confirmed waits, are the prompt's; the
    commit's own word on its timer is the reply's."""
    from hssh.transports.cli import Cli
    learned = Cli(None, dialects.junos.DIALECT, 5)._learn_prompt("welcome\nlab@r1.example> ")
    assert learned.search("lab@r1.example# ") and not learned.search("other@r1.example# ")
    assert not learned.search("description lab@r1.example>")
    learned = Cli(None, dialects.ios.DIALECT, 5)._learn_prompt("Router#")
    assert learned.search("Router(config-if)#") and not learned.search("Switch#")
    assert not learned.search("uplink to BackupRouter#") and not learned.search("uplink to BackupRouter(config)#")
    context = dialects.junos.CLI.context
    assert all(context.match(line) for line in ("[edit]", "[edit system]", "{master}[edit]",
                                                 "{master:0}[edit interfaces ge-0/0/0]", "{primary:node0}[edit]",
                                                 "# commit confirmed will be rolled back in 4 minutes",
                                                 "# commit confirmed will be rolled back in 1 minute"))
    assert not any(context.match(line) for line in (
        "", "{master}", "[edit] x", "x [edit]",
        "commit confirmed will be automatically rolled back in 5 minutes unless confirmed",
        "+  # commit confirmed will be rolled back in 4 minutes"))
