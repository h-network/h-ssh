"""Per-vendor command resolution and structured binding lookup."""

import json
import tempfile
from pathlib import Path

from hssh.core import resolve_command, resolve_structured, parse_inline_target
from hssh import runner, vendors


def test_same_shortcut_resolves_per_vendor():
    """The point of per-target resolution: one name, two vendor commands."""
    assert resolve_command("bgp", "junos") == "show bgp summary | no-more"
    # The EOS library follows the dialect: every eos@… driver, by either name.
    assert resolve_command("bgp", "telnet-arista") == "show ip bgp summary"
    assert resolve_command("bgp", "eos@telnet") == "show ip bgp summary"
    # And the retired eAPI vendor name has none.
    assert resolve_command("bgp", "arista") == "bgp"


def test_unknown_shortcut_passes_through():
    assert resolve_command("show chassis fpc", "junos") == "show chassis fpc"
    assert resolve_command("nonesuch", "junos") == "nonesuch"


def test_junos_binding_is_an_rpc_definition():
    b = resolve_structured("bgp", "junos")
    assert b["rpc"] == "get-bgp-neighbor-information"
    assert b["item"] == "bgp-peer"
    assert b["key"] == "peer-address"
    assert "remote_as" in b["fields"]




def test_no_binding_where_none_declared():
    assert resolve_structured("alarms", "junos") is None
    assert resolve_structured("uptime", "ssh") is None
    assert resolve_structured("nonesuch", "junos") is None


def test_multi_word_command_has_no_binding():
    assert resolve_structured("show bgp summary", "junos") is None


def test_capability_is_the_registrys_not_module_attribute_presence():
    """The runner branches on the driver's `supports`, never on the module:
    the paramiko module serves none@ssh and eos@ssh alike and has
    show_structured for the latter (#83), so absence of the attribute is no
    longer the fallback signal; the registry withholds it from plain ssh."""
    assert "show_structured" in runner.bind("junos").caps
    assert "show_structured" in runner.bind("eos@ssh").caps
    assert "show_structured" in runner.bind("eos@openssh").caps
    assert "show_structured" not in runner.bind("ssh").caps
    assert "show_structured" not in runner.bind("openssh").caps
    assert "show_structured" not in runner.bind("telnet").caps
    assert "show_structured" not in runner.bind("telnet-ios").caps
    assert hasattr(vendors.get("ssh"), "show_structured")   # the shared module has it; ssh may not ask


def test_vendorless_target_is_ssh_not_junos():
    t = parse_inline_target("SW1:10.0.0.1")
    assert t.vendor == "ssh"
    assert "show_structured" not in runner.bind(t.vendor).caps


def test_every_declared_binding_is_well_formed():
    """A junos binding must carry what FactoryLoader needs."""
    for path in (Path(__file__).resolve().parent.parent / "hssh" / "dialects").glob("*.json"):
        entries = json.loads(path.read_text())
        for name, entry in entries.items():
            if not isinstance(entry, dict) or "structured" not in entry:
                continue
            binding = entry["structured"]
            if path.stem == "junos":
                assert set(binding) >= {"rpc", "item", "key", "fields"}, (
                    f"{path.stem}:{name} incomplete"
                )
                assert binding["fields"], f"{path.stem}:{name} has no fields"
            else:
                assert binding is True, f"{path.stem}:{name} expected a marker"
