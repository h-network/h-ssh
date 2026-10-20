"""Junos driver over a fake PyEZ: ordering, dry-run, and the commit edge cases."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh.vendors import junos
from hssh.errors import AmbiguousCommitError, NotAppliedError


class FakeDevice:
    instances = []
    open_error = None
    cli_outputs = {}

    def __init__(self, **params):
        self.params = params
        self.timeout = None
        self.opened = False
        self.closed = False
        self.cli_calls = []
        FakeDevice.instances.append(self)

    def open(self):
        if FakeDevice.open_error:
            raise FakeDevice.open_error
        self.opened = True

    def close(self):
        self.closed = True

    def cli(self, cmd, warning=True):
        self.cli_calls.append(cmd)
        out = FakeDevice.cli_outputs.get(cmd, "output of " + cmd)
        if isinstance(out, Exception):
            raise out
        return out


class FakeHost:
    """The attributes PyEZ's exceptions format themselves with."""
    hostname = "10.0.0.1"
    user = "u"
    _port = 830


def connect_error(msg="boom"):
    return junos.ConnectError(FakeHost(), msg)


def rpc_timeout(cmd="commit", timeout=30):
    return junos.RpcTimeoutError(FakeHost(), cmd, timeout)


class FakeConfig:
    instances = []
    diff_text = "[edit]\n+  system host-name r1;"
    raise_on = {}

    def __init__(self, dev):
        self.dev = dev
        self.calls = []
        FakeConfig.instances.append(self)

    def _do(self, name, *a, **kw):
        self.calls.append((name, a, kw))
        exc = FakeConfig.raise_on.get(name)
        if exc:
            raise exc

    def lock(self):
        self._do("lock")

    def unlock(self):
        self._do("unlock")

    def load(self, body, format=None):
        self._do("load", body, format=format)

    def diff(self):
        self._do("diff")
        return FakeConfig.diff_text

    def commit_check(self, timeout=None):
        self._do("commit_check")

    def commit(self, confirm=None, timeout=None, comment=None):
        self._do("commit", confirm=confirm, comment=comment)

    def rollback(self, rb_id=0):
        self._do("rollback", rb_id)

    @property
    def names(self):
        return [c[0] for c in self.calls]


@pytest.fixture(autouse=True)
def fake_pyez(monkeypatch):
    FakeDevice.instances = []
    FakeDevice.open_error = None
    FakeDevice.cli_outputs = {}
    FakeConfig.instances = []
    FakeConfig.diff_text = "[edit]\n+  system host-name r1;"
    FakeConfig.raise_on = {}
    monkeypatch.setattr(junos, "AVAILABLE", True)
    monkeypatch.setattr(junos, "JunosDevice", FakeDevice)
    monkeypatch.setattr(junos, "JunosConfig", FakeConfig)


def edit(payload="set system host-name r1\n", **kw):
    return junos.edit("10.0.0.1", "u", "p", payload, 5, 30, **kw)


def cfg():
    return FakeConfig.instances[0]


# --- show -------------------------------------------------------------

def test_show_uses_netconf_on_830_and_strips_pager_hint():
    out = junos.show("10.0.0.1", "u", "p", "show version | no-more", 5, 30)
    dev = FakeDevice.instances[0]
    assert dev.params["port"] == 830
    assert dev.cli_calls == ["show version"]
    assert out == "output of show version"
    assert dev.closed


def test_explicit_port_is_honoured():
    junos.show("10.0.0.1", "u", "p", "show version", 5, 30, port=22)
    assert FakeDevice.instances[0].params["port"] == 22


def test_connect_failure_is_not_applied():
    FakeDevice.open_error = connect_error()
    with pytest.raises(NotAppliedError):
        junos.show("10.0.0.1", "u", "p", "show version", 5, 30)


def test_show_batch_one_session_and_failures_are_per_command():
    FakeDevice.cli_outputs = {"bad": RuntimeError("rpc error")}
    res = junos.show_batch("10.0.0.1", "u", "p", ["show a", "bad", "show c"], 5, 30)
    assert len(FakeDevice.instances) == 1
    assert [r["ok"] for r in res] == [True, False, True]
    assert res[1]["error"] == "rpc error"


# --- edit -------------------------------------------------------------

def test_commit_sequence_and_unlock():
    out = edit()
    assert out.startswith("COMMIT OK")
    assert cfg().names == ["lock", "load", "diff", "commit_check", "commit", "unlock"]
    assert FakeDevice.instances[0].closed


def test_no_changes_rolls_back_and_unlocks():
    FakeConfig.diff_text = ""
    assert edit() == "NO CHANGES"
    assert cfg().names == ["lock", "load", "diff", "rollback", "unlock"]


def test_dry_run_checks_but_never_commits():
    out = edit(dry_run=True)
    assert out.startswith("DRY-RUN")
    assert "+  system host-name r1;" in out
    names = cfg().names
    assert "commit_check" in names
    assert "commit" not in names
    assert names[-2:] == ["rollback", "unlock"]


def test_dry_run_reports_a_rejected_candidate():
    FakeConfig.raise_on = {"commit_check": junos.CommitError("bad")}
    with pytest.raises(RuntimeError, match="Config error"):
        edit(dry_run=True)
    assert "commit" not in cfg().names
    assert cfg().names[-2:] == ["rollback", "unlock"]


def test_commit_confirmed_passes_the_timer():
    out = edit(commit_confirmed=7)
    assert out.startswith("COMMIT CONFIRMED (7 minutes)")
    commit = [c for c in cfg().calls if c[0] == "commit"][0]
    assert commit[2]["confirm"] == 7


def test_unlock_failure_after_commit_does_not_fail_the_edit():
    FakeConfig.raise_on = {"unlock": RuntimeError("session gone")}
    out = edit()
    assert out.startswith("COMMIT OK")
    assert "rollback" not in cfg().names


def test_commit_timeout_is_ambiguous_and_not_rolled_back():
    FakeConfig.raise_on = {"commit": rpc_timeout()}
    with pytest.raises(AmbiguousCommitError, match="outcome unknown"):
        edit(commit_confirmed=5)
    assert "rollback" not in cfg().names


def test_commit_rejected_rolls_back():
    FakeConfig.raise_on = {"commit": junos.CommitError("conflict")}
    with pytest.raises(RuntimeError, match="Config error"):
        edit()
    assert "rollback" in cfg().names


def test_load_error_rolls_back_and_unlocks():
    FakeConfig.raise_on = {"load": junos.ConfigLoadError("syntax")}
    with pytest.raises(RuntimeError, match="Config error"):
        edit()
    assert cfg().names[-2:] == ["rollback", "unlock"]


def test_lock_failure_is_not_applied_and_does_not_unlock():
    FakeConfig.raise_on = {"lock": junos.LockError("held")}
    with pytest.raises(NotAppliedError):
        edit()
    assert "unlock" not in cfg().names
    assert FakeDevice.instances[0].closed


def test_the_word_commit_is_config_not_a_command():
    """-eD/-eB content "commit" must be loaded as config, never confirm anything."""
    FakeConfig.diff_text = ""
    edit(payload="commit\n")
    assert "commit" not in cfg().names
    load = [c for c in cfg().calls if c[0] == "load"][0]
    assert load[2]["format"] == "text"


def test_confirm_issues_a_plain_commit():
    assert junos.confirm("10.0.0.1", "u", "p", 5, 30) == "COMMIT CONFIRMED OK"
    assert cfg().names == ["commit"]
    assert cfg().calls[0][2]["confirm"] is None


def test_confirm_timeout_is_ambiguous():
    FakeConfig.raise_on = {"commit": rpc_timeout()}
    with pytest.raises(AmbiguousCommitError):
        junos.confirm("10.0.0.1", "u", "p", 5, 30)


# --- format detection -------------------------------------------------

@pytest.mark.parametrize("payload,fmt", [
    ("set system host-name r1\n", "set"),
    ("# change\nset a b\ndelete c d\n", "set"),
    ("set a b\ndeactivate c d\n", "set"),
    ("system {\n  host-name r1;\n}\n", "text"),
    ("set a b\nsystem {\n}\n", "text"),
    ("", "text"),
])
def test_config_format(payload, fmt):
    assert junos._config_format(payload) == fmt


def test_set_comments_are_not_sent_to_the_loader():
    edit(payload="# why\nset a b\n")
    load = [c for c in cfg().calls if c[0] == "load"][0]
    assert load[1][0] == "set a b"


# --- rollback ---------------------------------------------------------

def rollback(n=1, **kw):
    return junos.rollback("10.0.0.1", "u", "p", n, 5, 30, **kw)


def test_rollback_sequence_and_label():
    out = rollback(1)
    assert out.startswith("ROLLBACK 1: COMMIT OK")
    assert "+  system host-name r1;" in out
    assert cfg().names == ["lock", "rollback", "diff", "commit_check", "commit", "unlock"]
    assert cfg().calls[1][1] == (1,)          # rollback 1 went into the candidate
    assert FakeDevice.instances[0].closed


def test_rollback_dry_run_shows_the_diff_and_discards():
    out = rollback(2, dry_run=True)
    assert out.startswith("ROLLBACK 2: DRY-RUN")
    names = cfg().names
    assert names == ["lock", "rollback", "diff", "commit_check", "rollback", "unlock"]
    assert cfg().calls[1][1] == (2,) and cfg().calls[4][1] == (0,)   # stage rollback 2, then discard (rollback 0)


def test_rollback_commit_confirmed_and_no_changes():
    out = rollback(3, commit_confirmed=5)
    assert out.startswith("ROLLBACK 3: COMMIT CONFIRMED (5 minutes)")
    assert [c for c in cfg().calls if c[0] == "commit"][0][2]["confirm"] == 5
    FakeConfig.instances.clear()
    FakeConfig.diff_text = ""
    assert rollback(0) == "ROLLBACK 0: NO CHANGES"
    assert cfg().names == ["lock", "rollback", "diff", "rollback", "unlock"]


def test_rollback_number_is_checked_before_any_session():
    for bad in (-1, 50, "x", None):
        with pytest.raises(ValueError, match="rollback number"):
            rollback(bad)
    assert FakeDevice.instances == []


def test_rollback_keeps_the_edit_verdicts():
    FakeConfig.raise_on = {"lock": junos.LockError("held")}
    with pytest.raises(NotAppliedError):
        rollback(1)
    FakeConfig.raise_on = {"commit": rpc_timeout()}
    FakeConfig.instances.clear()
    with pytest.raises(AmbiguousCommitError):
        rollback(1)
    assert "unlock" not in cfg().names


# --- comments, transactions, guarded commit ---------------------------------

def commit_call():
    return [c for c in cfg().calls if c[0] == "commit"][0][2]


def test_comment_is_logged_with_edit_rollback_and_confirm():
    edit(comment="C1 cutover")
    assert commit_call()["comment"] == "C1 cutover"
    FakeConfig.instances.clear()
    rollback(1, comment="back")
    assert commit_call()["comment"] == "back"
    FakeConfig.instances.clear()
    junos.confirm("10.0.0.1", "u", "p", 5, 30, comment="done")
    assert commit_call()["comment"] == "done"
    FakeConfig.instances.clear()
    edit()
    assert commit_call()["comment"] is None


def begin(payload="set system host-name r1\n", **kw):
    return junos.begin("10.0.0.1", "u", "p", payload, 5, 30, **kw)


def test_begin_leaves_the_candidate_open_then_commit():
    tx = begin()
    assert tx.open and "+  system host-name r1;" in tx.diff
    assert cfg().names == ["lock", "load", "diff", "commit_check"]
    assert not FakeDevice.instances[0].closed            # session still borrowed
    out = tx.commit(confirmed=7, comment="gate said yes")
    assert out.startswith("COMMIT CONFIRMED (7 minutes)") and not tx.open
    assert cfg().names == ["lock", "load", "diff", "commit_check", "commit", "unlock"]
    assert commit_call() == {"confirm": 7, "comment": "gate said yes"}
    assert FakeDevice.instances[0].closed                # given back (pool off: closed)
    with pytest.raises(RuntimeError, match="no longer open"):
        tx.commit()


def test_begin_abort_and_leaving_the_block():
    tx = begin()
    tx.abort()
    assert cfg().names == ["lock", "load", "diff", "commit_check", "rollback", "unlock"]
    FakeConfig.instances.clear()
    with begin() as tx:
        assert tx.show("show version") == "output of show version"   # same session
    assert not tx.open and cfg().names[-2:] == ["rollback", "unlock"]


def test_begin_with_rollback_and_no_changes():
    tx = begin(None, rollback=2)
    assert tx.label == "ROLLBACK 2: " and cfg().calls[1] == ("rollback", (2,), {})
    tx.abort()
    FakeConfig.instances.clear()
    FakeConfig.diff_text = ""
    tx = begin()
    assert tx.diff == "" and cfg().names == ["lock", "load", "diff"]   # no commit check without a diff
    assert tx.commit() == "NO CHANGES" and not tx.open
    with pytest.raises(ValueError):
        begin(None)
    with pytest.raises(ValueError):
        begin("set a b", rollback=1)


def test_begin_cleans_up_when_the_load_is_rejected():
    FakeConfig.raise_on = {"load": junos.ConfigLoadError("syntax")}
    with pytest.raises(RuntimeError, match="Config error"):
        begin()
    assert cfg().names == ["lock", "load", "rollback", "unlock"]
    assert FakeDevice.instances[0].closed


def test_transaction_commit_verdicts_match_edit():
    FakeConfig.raise_on = {"commit": junos.CommitError("conflict")}
    tx = begin()
    with pytest.raises(RuntimeError, match="Config error"):
        tx.commit()
    assert cfg().names[-2:] == ["rollback", "unlock"] and not tx.open
    FakeConfig.instances.clear()
    FakeConfig.raise_on = {"commit": rpc_timeout()}
    tx = begin()
    with pytest.raises(AmbiguousCommitError):
        tx.commit()
    assert "rollback" not in cfg().names and "unlock" not in cfg().names and not tx.open


def test_guarded_commit_confirms_or_rolls_back():
    calls = []
    res = junos.guarded_commit("10.0.0.1", "u", "p", "set a b\n", 5, 30, minutes=5,
                               check=lambda: calls.append("checked") or True, comment="C1")
    assert res["final"] == "confirmed" and calls == ["checked"]
    commits = [c[2] for i in FakeConfig.instances for c in i.calls if c[0] == "commit"]
    assert commits == [{"confirm": 5, "comment": "C1"}, {"confirm": None, "comment": "C1 (confirmed)"}]
    FakeConfig.instances.clear()
    res = junos.guarded_commit("10.0.0.1", "u", "p", "set a b\n", 5, 30, minutes=5,
                               check=lambda: (_ for _ in ()).throw(RuntimeError("bgp down")), comment="C1")
    assert res["final"] == "rolled back" and "bgp down" in res["reason"]
    names = [c[0] for i in FakeConfig.instances for c in i.calls]
    assert names == ["lock", "load", "diff", "commit_check", "commit", "unlock",
                     "lock", "rollback", "diff", "commit_check", "commit", "unlock"]
    assert FakeConfig.instances[1].calls[1][1] == (1,)       # rollback 1
