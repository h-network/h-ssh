import json

import pytest

from hssh.audit import write_audit_entry
from hssh.dialects.junos import DIALECT
from hssh.model import EditSettings, Fault, FaultKind, OperationResult, Result, Target


def entry(tmp_path, **overrides):
    path = tmp_path / "audit.jsonl"
    arguments = dict(
        path=str(path), run_id=7, user="operator", target=Target("R1", "192.0.2.1", "junos", "netconf"),
        driver="junos@netconf", dialect=DIALECT, action="load",
        operation=OperationResult("load", Result("loaded"), "2026-10-30T00:00:00+00:00", 1),
        edit=EditSettings(False),
    )
    arguments.update(overrides)
    write_audit_entry(**arguments)
    return json.loads(path.read_text().splitlines()[-1])


def test_load_payload_keeps_submitted_lines_in_order(tmp_path):
    lines = ("set system host-name R1", 'set system login announcement "maintenance"')
    record = entry(tmp_path, lines=lines)
    assert record["payload"] == 'set system host-name R1\nset system login announcement "maintenance"'
    assert record["action"] == "load"
    assert record["target"] == "R1"


def test_payload_masks_secret_value_and_keeps_statement(tmp_path):
    lines = ['set system root-authentication encrypted-password "$6$PRIVATE"', "set system host-name R1"]
    record = entry(tmp_path, lines=lines)
    assert record["payload"] == 'set system root-authentication encrypted-password [REDACTED]\nset system host-name R1'
    assert "$6$PRIVATE" not in (tmp_path / "audit.jsonl").read_text()
    assert "$6$PRIVATE" in lines[0]


def test_json_payload_masks_whole_wrapped_secret_value(tmp_path):
    lines = ('{"encrypted-password": [{"data": "PRIVATE"}], "name": "keep"}',)
    record = entry(tmp_path, lines=lines)
    assert json.loads(record["payload"]) == {"encrypted-password": "[REDACTED]", "name": "keep"}
    assert "PRIVATE" not in (tmp_path / "audit.jsonl").read_text()


def test_load_without_lines_has_no_payload_text(tmp_path):
    assert entry(tmp_path)["payload"] == ""


@pytest.mark.parametrize("action", ["diff", "commit", "confirm", "probe"])
def test_other_actions_do_not_repeat_payload(tmp_path, action):
    record = entry(tmp_path, action=action, lines=("set system host-name PRIVATE",))
    assert record["payload"] == ""
    assert "PRIVATE" not in (tmp_path / "audit.jsonl").read_text()


def test_failed_load_keeps_submitted_payload(tmp_path):
    fault = Fault(FaultKind.REFUSED, "syntax error", True)
    record = entry(tmp_path, lines=("set invalid statement",),
                   operation=OperationResult("load", fault, "2026-10-30T00:00:00+00:00", 1))
    assert record["payload"] == "set invalid statement"
    assert record["ok"] is False
    assert record["fault"]["kind"] == "REFUSED"
