"""transports.netconf.rpc(): CLI command or RPC name in, the router's JSON or XML out."""
import os
import sys

import pytest
from lxml import etree

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import pool
from hssh.transports import netconf
from tests.test_junos import FakeConfig, FakeDevice, rpc_timeout


class FakeRpcMeta:
    """Stands in for dev.rpc: only cli(... | display xml rpc) is needed."""

    translations = {
        "show chassis hardware": "<get-chassis-inventory/>",
        "show interfaces ge-0/0/0 terse": "<get-interface-information><interface-name>ge-0/0/0</interface-name><terse/></get-interface-information>",
        "show nonsense": None,
    }

    def __init__(self, dev):
        self.dev = dev

    def cli(self, command, format="text"):
        self.dev.cli_calls.append(command)
        base = command.replace(" | display xml rpc", "").strip()
        body = self.translations.get(base)
        if body is None:
            reply = etree.fromstring("<rpc-reply><output>syntax error</output></rpc-reply>")
        else:
            reply = etree.fromstring(f"<rpc-reply><rpc>{body}</rpc></rpc-reply>")
        return reply[0]


class RpcDevice(FakeDevice):
    executed = []
    execute_error = None
    json_reply = {"chassis-inventory": [{"chassis": [{"serial-number": [{"data": "VM1"}]}]}]}

    def __init__(self, **params):
        super().__init__(**params)
        self.rpc = FakeRpcMeta(self)

    def execute(self, element):
        RpcDevice.executed.append(element)
        if RpcDevice.execute_error:
            raise RpcDevice.execute_error
        if element.get("format") == "json":
            return dict(self.json_reply)
        return etree.fromstring("<chassis-inventory><chassis><name>Chassis</name></chassis></chassis-inventory>")


@pytest.fixture(autouse=True)
def fake_pyez(monkeypatch):
    FakeDevice.instances = []
    FakeDevice.open_error = None
    FakeDevice.cli_outputs = {}
    FakeConfig.instances = []
    RpcDevice.executed = []
    RpcDevice.execute_error = None
    monkeypatch.setattr(netconf, "AVAILABLE", True)
    monkeypatch.setattr(netconf, "JunosDevice", RpcDevice)
    monkeypatch.setattr(netconf, "JunosConfig", FakeConfig)
    yield
    pool.POOL.disable()
    for k in pool.POOL.stats:
        pool.POOL.stats[k] = 0


def rpc(command, **kw):
    return netconf.rpc("10.0.0.1", "u", None, command, 5, 30, **kw)


def sent():
    return RpcDevice.executed[-1]


# --- what gets sent --------------------------------------------------------

def test_cli_command_is_translated_by_the_router_and_sent_as_json():
    out = rpc("show chassis hardware")
    assert out == RpcDevice.json_reply
    assert sent().tag == "get-chassis-inventory"
    assert sent().get("format") == "json"
    assert FakeDevice.instances[0].cli_calls == ["show chassis hardware | display xml rpc"]


def test_cli_command_arguments_survive_translation():
    rpc("show interfaces ge-0/0/0 terse")
    assert sent().tag == "get-interface-information"
    assert sent().findtext("interface-name") == "ge-0/0/0"
    assert sent().find("terse") is not None


def test_rpc_name_with_args_is_built_locally():
    rpc("get-interface-information", args={"interface_name": "ge-0/0/1", "terse": True, "level": None})
    assert FakeDevice.instances[0].cli_calls == []  # no translation round trip
    el = sent()
    assert el.tag == "get-interface-information"
    assert el.findtext("interface-name") == "ge-0/0/1"
    assert el.find("terse") is not None and el.find("terse").text is None
    assert el.find("level") is not None and el.find("level").text is None


def test_rpc_name_underscores_are_dashes_on_the_wire():
    rpc("get_chassis_inventory")
    assert sent().tag == "get-chassis-inventory"


def test_xml_format_returns_the_reply_as_text():
    out = rpc("show chassis hardware", fmt="xml")
    assert isinstance(out, str)
    assert out.startswith("<chassis-inventory>")
    assert sent().get("format") is None


def test_bad_format_cli_without_rpc_and_args_with_cli_are_rejected():
    with pytest.raises(ValueError, match="fmt"):
        rpc("show chassis hardware", fmt="yaml")
    with pytest.raises(ValueError, match="no RPC equivalent"):
        rpc("show nonsense")
    with pytest.raises(ValueError, match="args go with an RPC name"):
        rpc("show chassis hardware", args={"x": 1})


def test_one_session_per_call_when_the_pool_is_off():
    rpc("show chassis hardware")
    assert FakeDevice.instances[0].closed


# --- on a pooled session -----------------------------------------------------

def test_rpc_and_show_share_the_pooled_session():
    pool.enable()
    rpc("show chassis hardware")
    netconf.show("10.0.0.1", "u", None, "show version", 5, 30)
    rpc("get-chassis-inventory")
    assert len(FakeDevice.instances) == 1
    assert pool.POOL.stats["opens"] == 1 and pool.POOL.stats["reuses"] == 2


def test_get_rpc_on_a_dead_reused_session_is_retried_once():
    pool.enable()
    rpc("show chassis hardware")
    dead = FakeDevice.instances[0]
    RpcDevice.execute_error = netconf.TransportError("closed")

    class Fresh(RpcDevice):
        def execute(self, element):
            return {"fresh": True}

    netconf.JunosDevice = Fresh
    assert rpc("get-chassis-inventory") == {"fresh": True}
    assert dead.closed and len(FakeDevice.instances) == 2


def test_request_rpc_is_never_resent():
    pool.enable()
    rpc("show chassis hardware")
    dead = FakeDevice.instances[0]
    RpcDevice.execute_error = netconf.TransportError("closed")
    with pytest.raises(netconf.TransportError):
        rpc("request-system-reboot")
    assert dead.closed
    assert len(FakeDevice.instances) == 1  # no second attempt
    assert pool.POOL.live() == 0


def test_rpc_timeout_drops_the_pooled_session():
    pool.enable()
    rpc("show chassis hardware")
    RpcDevice.execute_error = rpc_timeout("get-chassis-inventory")
    with pytest.raises(netconf.RpcTimeoutError):
        rpc("get-chassis-inventory")
    assert FakeDevice.instances[0].closed
    assert pool.POOL.live() == 0


def test_commit_status_reads_the_history_as_data():
    RpcDevice.json_reply = {"commit-information": [{"commit-history": [
        {"sequence-number": [{"data": "0"}], "user": [{"data": "h-lab"}], "client": [{"data": "netconf"}],
         "date-time": [{"data": "2026-10-20 19:19:11 CEST", "attributes": {"junos:seconds": "1792516751"}}],
         "comment": [{"data": "commit confirmed, rollback in 5mins"}], "log": [{"data": "C1 cutover"}]},
        {"sequence-number": [{"data": "1"}], "user": [{"data": "h-lab"}], "client": [{"data": "cli"}],
         "date-time": [{"data": "2026-10-19 02:33:16 CEST"}]},
    ]}]}
    entries = netconf.commit_status("10.0.0.1", "u", None, 5, 30)
    assert entries[0] == {"seq": 0, "user": "h-lab", "client": "netconf", "time": "2026-10-20 19:19:11 CEST",
                          "epoch": 1792516751.0, "comment": "C1 cutover",
                          "note": "commit confirmed, rollback in 5mins", "pending_rollback_minutes": 5}
    assert entries[1]["pending_rollback_minutes"] is None and entries[1]["comment"] is None
    assert netconf.pending_commit(entries)["seq"] == 0
    assert netconf.pending_commit(entries[1:]) is None
    assert sent().tag == "get-commit-information"


def test_a_confirmed_commit_keeps_its_note_but_is_not_pending():
    """Seen on a vMX: after the confirm, the history is the confirm at 0 and
    the commit confirmed, note and all, at 1. Only seq 0 can be waiting."""
    RpcDevice.json_reply = {"commit-information": [{"commit-history": [
        {"sequence-number": [{"data": "0"}], "user": [{"data": "h-lab"}], "client": [{"data": "netconf"}],
         "date-time": [{"data": "2026-10-21 02:48:02 UTC"}], "log": [{"data": "C1 (confirmed)"}]},
        {"sequence-number": [{"data": "1"}], "user": [{"data": "h-lab"}], "client": [{"data": "netconf"}],
         "date-time": [{"data": "2026-10-21 02:47:55 UTC"}],
         "comment": [{"data": "commit confirmed, rollback in 3mins"}], "log": [{"data": "C1"}]},
    ]}]}
    entries = netconf.commit_status("10.0.0.1", "u", None, 5, 30)
    assert entries[1]["note"] == "commit confirmed, rollback in 3mins"
    assert entries[1]["pending_rollback_minutes"] is None
    assert netconf.pending_commit(entries) is None


# --- rpc_batch: several commands on one session --------------------------------

def rpc_batch(cmds, **kw):
    return netconf.rpc_batch("10.0.0.1", "u", None, cmds, 5, 30, **kw)


def test_batch_answers_each_command_on_one_session():
    res = rpc_batch(["show chassis hardware", "get-chassis-inventory"])
    assert [r["ok"] for r in res] == [True, True]
    assert [r["output"] for r in res] == [RpcDevice.json_reply] * 2
    assert [e.tag for e in RpcDevice.executed] == ["get-chassis-inventory"] * 2
    assert len(FakeDevice.instances) == 1 and FakeDevice.instances[0].closed


def test_batch_records_a_command_without_an_rpc_and_goes_on():
    res = rpc_batch(["show nonsense", "show chassis hardware"], fmt="xml")
    assert [r["ok"] for r in res] == [False, True]
    assert res[0]["command"] == "show nonsense" and "no RPC equivalent" in res[0]["error"]
    assert res[1]["output"].startswith("<chassis-inventory>")


def test_batch_checks_the_format_before_opening_a_session():
    with pytest.raises(ValueError, match="fmt"):
        rpc_batch(["show chassis hardware"], fmt="yaml")
    assert FakeDevice.instances == []


def test_batch_of_reads_on_a_dead_reused_session_is_rerun_once():
    pool.enable()
    rpc("show chassis hardware")
    dead = FakeDevice.instances[0]
    RpcDevice.execute_error = netconf.TransportError("closed")

    class Fresh(RpcDevice):
        def execute(self, element):
            return {"fresh": element.tag}

    netconf.JunosDevice = Fresh
    res = rpc_batch(["show chassis hardware", "get-chassis-inventory"])
    assert [r["output"] for r in res] == [{"fresh": "get-chassis-inventory"}] * 2
    assert dead.closed and len(FakeDevice.instances) == 2


def test_batch_with_a_request_rpc_is_never_resent():
    pool.enable()
    rpc("show chassis hardware")
    RpcDevice.execute_error = netconf.TransportError("closed")
    with pytest.raises(netconf.TransportError):
        rpc_batch(["show chassis hardware", "request-system-reboot"])
    assert len(FakeDevice.instances) == 1 and pool.POOL.live() == 0


def test_batch_timeout_is_recorded_and_drops_the_pooled_session():
    pool.enable()
    RpcDevice.execute_error = rpc_timeout("get-chassis-inventory")
    res = rpc_batch(["show chassis hardware", "get-chassis-inventory"])
    assert [r["ok"] for r in res] == [False, False]
    assert FakeDevice.instances[0].closed and pool.POOL.live() == 0
