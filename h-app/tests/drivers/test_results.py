"""#82: drivers return typed results, the runner returns a RunResult, and the
CLI reads the verdict from fields instead of parsing text. Each type is still
its old value (text or list), so nothing that printed or indexed it changes."""
import json
import types

import pytest

from hssh import runner, drivers
from hssh.core import Target
from hssh.drivers import results as R
from hssh.drivers.results import EditResult, BatchResult, CommitStatus, as_edit, as_batch, as_commits
from hssh.transports import netconf
from tests.test_junos import FakeDevice, FakeConfig, fake_pyez  # noqa: F401  (fixture)

DIFF = "[edit system]\n+   host-name r1;\n"


# --- EditResult -----------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "COMMIT OK\n\nDIFF:\n" + DIFF,
    "COMMIT CONFIRMED (5 minutes)\n\nDIFF:\n" + DIFF,
    "ROLLBACK 3: COMMIT OK\n\nDIFF:\n" + DIFF,
    "ROLLBACK 3: COMMIT CONFIRMED (2 minutes)\n\nDIFF:\n" + DIFF,
    "DRY-RUN: commit check passed, nothing committed\n\nDIFF:\n" + DIFF,
    "DRY-RUN\n\nDIFF:\n" + DIFF,
    "NO CHANGES", "ROLLBACK 1: NO CHANGES", "COMMIT CONFIRMED OK", "(config applied)",
    "$ set a b\n\n$ commit\ncommit complete\n",
])
def test_an_edit_result_is_the_text_it_always_was(text):
    r = as_edit(text)
    assert isinstance(r, EditResult) and isinstance(r, str)
    assert r == text and str(r) == text and r.rstrip() == text.rstrip()
    assert as_edit(r) is r
    assert json.dumps({"output": r}) == json.dumps({"output": text})
    assert r.ok


def test_an_edit_result_knows_what_it_says():
    r = as_edit("ROLLBACK 3: COMMIT CONFIRMED (2 minutes)\n\nDIFF:\n" + DIFF)
    assert (r.status, r.diff, r.minutes, r.label) == (R.CONFIRMED, DIFF, 2, "ROLLBACK 3: ")
    assert r.pending
    r = as_edit("DRY-RUN: commit check passed, nothing committed\n\nDIFF:\n" + DIFF)
    assert (r.status, r.note, r.diff) == (R.DRY_RUN, "commit check passed, nothing committed", DIFF)
    assert not r.pending
    assert as_edit("DRY-RUN\n\nDIFF:\n" + DIFF).note == ""
    assert as_edit("NO CHANGES").status == R.NO_CHANGES
    assert as_edit("COMMIT CONFIRMED OK").status == R.CONFIRMED_OK
    r = as_edit("(config applied)")
    assert r.status == R.APPLIED and r.message == "(config applied)"
    # a bare verdict without a diff is a test double's shorthand: kept as it is
    assert as_edit("COMMIT OK").status == R.APPLIED and as_edit("COMMIT OK") == "COMMIT OK"


def test_an_edit_result_renders_exactly_what_the_drivers_printed():
    assert EditResult(R.COMMITTED, diff=DIFF) == "COMMIT OK\n\nDIFF:\n" + DIFF
    assert EditResult(R.CONFIRMED, diff=DIFF, minutes=5, label="ROLLBACK 1: ") == \
        "ROLLBACK 1: COMMIT CONFIRMED (5 minutes)\n\nDIFF:\n" + DIFF
    assert EditResult(R.DRY_RUN, diff=DIFF, note="commit check passed, nothing committed") == \
        "DRY-RUN: commit check passed, nothing committed\n\nDIFF:\n" + DIFF
    assert EditResult(R.NO_CHANGES, label="ROLLBACK 1: ") == "ROLLBACK 1: NO CHANGES"
    assert EditResult(R.CONFIRMED_OK) == "COMMIT CONFIRMED OK"
    with pytest.raises(ValueError, match="unknown edit status"):
        EditResult("done")
    with pytest.raises(ValueError, match="has minutes"):
        EditResult(R.CONFIRMED, diff=DIFF)


# --- BatchResult, CommitStatus ----------------------------------------------------

def test_a_batch_result_is_the_list_with_a_verdict():
    rows = [{"command": "show a", "ok": True, "output": "A"}, {"command": "bad", "ok": False, "error": "no"}]
    b = as_batch(rows)
    assert isinstance(b, BatchResult) and list(b) == rows and json.dumps(b) == json.dumps(rows)
    assert not b.ok and b.first_error == "no" and b[1]["error"] == "no"
    assert as_batch(b) is b and as_batch(rows[:1]).ok and as_batch(rows[:1]).first_error is None


def test_commit_status_is_the_list_with_the_pending_entry():
    rows = [{"seq": 0, "user": "lab", "pending_rollback_minutes": 5}, {"seq": 1, "user": "lab", "pending_rollback_minutes": None}]
    c = as_commits(rows)
    assert isinstance(c, CommitStatus) and list(c) == rows and c.pending == rows[0]
    assert as_commits(rows[1:]).pending is None and as_commits(c) is c


# --- the real drivers return them --------------------------------------------------

def test_the_netconf_module_returns_typed_results(monkeypatch):
    r = netconf.edit("10.0.0.1", "u", "p", "set system host-name r1\n", 5, 30)
    assert isinstance(r, EditResult) and r.status == R.COMMITTED and r.diff == FakeConfig.diff_text
    r = netconf.edit("10.0.0.1", "u", "p", "set system host-name r1\n", 5, 30, commit_confirmed=5)
    assert r.status == R.CONFIRMED and r.minutes == 5 and r.pending
    r = netconf.edit("10.0.0.1", "u", "p", "set system host-name r1\n", 5, 30, dry_run=True)
    assert r.status == R.DRY_RUN and r.diff == FakeConfig.diff_text
    FakeConfig.diff_text = ""
    assert netconf.edit("10.0.0.1", "u", "p", "set system host-name r1\n", 5, 30).status == R.NO_CHANGES
    FakeConfig.diff_text = "[edit]\n+  x;"
    r = netconf.rollback("10.0.0.1", "u", "p", 2, 5, 30)
    assert r.status == R.COMMITTED and r.label == "ROLLBACK 2: " and r.startswith("ROLLBACK 2: COMMIT OK")
    assert netconf.confirm("10.0.0.1", "u", "p", 5, 30).status == R.CONFIRMED_OK
    FakeDevice.cli_outputs = {"show a": "A"}
    b = netconf.show_batch("10.0.0.1", "u", "p", ["show a"], 5, 30)
    assert isinstance(b, BatchResult) and b.ok and b[0]["output"] == "A"


# --- the runner's RunResult ---------------------------------------------------------

def _run(monkeypatch, mod, mode, **kw):
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", mod)
    return runner.run_for_target(
        t=Target("R1", "10.0.0.1", "junos"), transport="junos", mode=mode,
        show_cmd=kw.pop("show_cmd", "show version"), edit_cmd=kw.pop("edit_cmd", None), config_dir=None,
        broadcast_file=None, user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=kw.pop("dry_run", False), commit_confirmed=None, save_dir=None, quiet=True, max_attempts=1, **kw)


def test_a_run_result_unpacks_as_the_old_tuple_and_carries_the_typed_answer(monkeypatch):
    mod = types.SimpleNamespace(
        AVAILABLE=True,
        show=lambda *a, **k: "Junos: 1\n",
        edit=lambda *a, **k: "COMMIT OK\n\nDIFF:\n" + DIFF,      # a module that still returns text
        show_batch=lambda *a, **k: [{"command": "show a", "ok": True, "output": "A"},
                                    {"command": "bad", "ok": False, "error": "refused"}],
        commit_status=lambda *a, **k: [{"seq": 0, "user": "lab", "pending_rollback_minutes": 3}],
    )
    res = _run(monkeypatch, mod, "show")
    name, ok, text, ms = res
    assert (name, ok) == ("R1", True) and res[0] == "R1" and res[1] is True and len(res) == 4
    assert text.endswith("Junos: 1\n") and res.result == "Junos: 1\n" and res.error is None

    res = _run(monkeypatch, mod, "edit-cmd", edit_cmd="set a b")
    assert isinstance(res.result, EditResult) and res.result.status == R.COMMITTED and res.result.diff == DIFF
    assert res.text.endswith("COMMIT OK\n\nDIFF:\n" + DIFF.rstrip() + "\n")

    res = _run(monkeypatch, mod, "show-batch", batch_cmds=["show a", "bad"])
    assert not res.ok and isinstance(res.result, BatchResult) and res.error == "refused"
    assert json.loads(res.text) == res.result.to_list()

    res = _run(monkeypatch, mod, "commit-status")
    assert isinstance(res.result, CommitStatus) and res.result.pending["pending_rollback_minutes"] == 3
    assert res.text.strip().splitlines()[-1] == json.dumps(res.result.to_list())

    res = _run(monkeypatch, mod, "commit-status", dry_run=True)
    assert res.ok and isinstance(res.result, CommitStatus) and res.result == []


def test_a_failed_run_carries_its_error_as_a_field(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("'uptime' was refused by the device: error: unknown command: uptime")
    res = _run(monkeypatch, types.SimpleNamespace(AVAILABLE=True, show=boom), "show", show_cmd="uptime")
    assert not res.ok and res.result is None
    assert res.error == "'uptime' was refused by the device: error: unknown command: uptime"
    assert res.text.rstrip().endswith("ERROR: " + res.error)


# --- what the review of #82 found -----------------------------------------------------

@pytest.mark.parametrize("text", [
    "NO CHANGES\n\nDIFF:\n+ x;\n", "COMMIT CONFIRMED OK\n\nDIFF:\n+ x;\n", "COMMIT CONFIRMED (05 minutes)\n\nDIFF:\n+ x;\n",
    "DRY-RUN (telnet)\n\nDIFF:\n+ x;\n", "DRY-RUNNING\n\nDIFF:\n+ x;\n", "DRY-RUN:\n\nDIFF:\n+ x;\n",
    "DRY-RUN:  note\n\nDIFF:\n+ x;\n", "DRY-RUN: : note\n\nDIFF:\n+ x;\n", "COMMIT OK\r\n\r\nDIFF:\r\n+ x;",
    "COMMIT OK \n\nDIFF:\n+ x;\n", "ROLLBACK 10: COMMIT OK\n\nDIFF:\n" + DIFF, "COMMIT OK\n\nDIFF:\n", "",
    "COMMIT OK\n\nDIFF:\n+ a;\n\nDIFF:\n+ b;\n",
])
def test_parsing_never_changes_the_text(text):
    r = as_edit(text)
    assert r == text and type(r) is EditResult


def test_a_driver_returning_no_result_is_a_failure_not_a_verdict(monkeypatch):
    with pytest.raises(TypeError, match="returned NoneType, not an edit result"):
        as_edit(None)
    res = _run(monkeypatch, types.SimpleNamespace(AVAILABLE=True, edit=lambda *a, **k: None), "edit-cmd", edit_cmd="set a b")
    assert not res.ok and "not an edit result" in res.error


def test_results_survive_pickle_and_copy():
    import copy
    import pickle
    r = EditResult(R.CONFIRMED, diff=DIFF, minutes=5, label="ROLLBACK 1: ", note="", message="")
    for again in (pickle.loads(pickle.dumps(r)), copy.deepcopy(r), copy.copy(r)):
        assert again == r and again.status == R.CONFIRMED and again.minutes == 5 and again.label == "ROLLBACK 1: "
    run = runner.RunResult("R1", True, "text", 7, result=as_batch([{"command": "a", "ok": True, "output": "A"}]))
    again = pickle.loads(pickle.dumps(run))
    assert again == run and again.result == run.result and isinstance(again.result, BatchResult) and again.error is None


def test_a_run_result_is_the_old_tuple_in_every_way():
    res = runner.RunResult("R1", True, "text", 7, result=as_batch([{"command": "a", "ok": True, "output": "A"}]), error=None)
    assert res == ("R1", True, "text", 7) and isinstance(res, tuple) and len(res) == 4
    assert hash(res) == hash(("R1", True, "text", 7)) and res[-1] == 7 and res[1:3] == (True, "text")
    assert json.dumps(res) == json.dumps(["R1", True, "text", 7]) and tuple(res) == ("R1", True, "text", 7)
    i, name, ok, text, ms = (3, *res)
    assert (i, name, ok, text, ms) == (3, "R1", True, "text", 7) and res.name == "R1" and res.duration_ms == 7
    assert "RunResult(name='R1', ok=True" in repr(res)


def test_to_list_is_a_copy_the_caller_may_edit():
    b = as_batch([{"command": "show v", "ok": True, "output": "$ show v\nJunos"}])
    rows = b.to_list()
    rows[0]["output"] = "Junos"
    assert b[0]["output"] == "$ show v\nJunos" and b.to_list()[0]["output"] == "$ show v\nJunos"


def test_the_error_field_is_what_the_cli_always_read(monkeypatch):
    """The CLI took what followed the last "ERROR:" line of the text, stripped;
    the field is exactly that, so a multi-line or padded message reads as before."""
    def boom(*a, **k):
        raise RuntimeError("commit check failed\nERROR: inner line\nthird line")
    res = _run(monkeypatch, types.SimpleNamespace(AVAILABLE=True, show=boom), "show")
    assert res.error == "inner line"

    def padded(*a, **k):
        raise RuntimeError("boom \n\n")
    res = _run(monkeypatch, types.SimpleNamespace(AVAILABLE=True, show=padded), "show")
    assert res.error == "boom"

    def empty(*a, **k):
        raise RuntimeError("")
    res = _run(monkeypatch, types.SimpleNamespace(AVAILABLE=True, show=empty), "show")
    assert res.error == "" and res.text.rstrip().endswith("ERROR:")
