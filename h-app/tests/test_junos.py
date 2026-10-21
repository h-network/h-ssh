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


def test_confirm_commits_plain_under_the_lock():
    assert junos.confirm("10.0.0.1", "u", "p", 5, 30) == "COMMIT CONFIRMED OK"
    assert cfg().names == ["lock", "commit", "unlock"]
    assert cfg().calls[1][2]["confirm"] is None


def test_confirm_refused_lock_is_not_applied_and_sends_nothing():
    """Another user's uncommitted edits refuse the lock; a commit would have
    taken them along with the confirmation."""
    FakeConfig.raise_on = {"lock": junos.LockError("configuration database modified")}
    with pytest.raises(NotAppliedError, match="Failed to lock"):
        junos.confirm("10.0.0.1", "u", "p", 5, 30)
    assert cfg().names == ["lock"]


def test_confirm_rejected_commit_unlocks():
    FakeConfig.raise_on = {"commit": junos.CommitError("conflict")}
    with pytest.raises(RuntimeError, match="Commit failed"):
        junos.confirm("10.0.0.1", "u", "p", 5, 30)
    assert cfg().names == ["lock", "commit", "unlock"]


def test_confirm_timeout_is_ambiguous():
    FakeConfig.raise_on = {"commit": rpc_timeout()}
    with pytest.raises(AmbiguousCommitError):
        junos.confirm("10.0.0.1", "u", "p", 5, 30)
    assert "unlock" not in cfg().names          # the session goes, and the lock with it


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


# --- expected_diff: --show-diff commits only what it showed -----------------

def test_expected_diff_must_match_or_nothing_is_committed():
    out = edit(expected_diff="\n[edit]\n+  system host-name r1;\n")      # the same, whitespace aside
    assert out.startswith("COMMIT OK")
    FakeConfig.instances.clear()
    with pytest.raises(RuntimeError, match="diff changed since preview; nothing committed"):
        edit(expected_diff="[edit]\n+  system host-name OTHER;")
    assert cfg().names == ["lock", "load", "diff", "commit_check", "rollback", "unlock"]
    FakeConfig.instances.clear()
    with pytest.raises(RuntimeError, match="diff changed since preview"):
        rollback(1, expected_diff="")                                    # previewed NO CHANGES, now a diff
    assert "commit" not in cfg().names and cfg().names[-2:] == ["rollback", "unlock"]


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


# commit_status() as guarded_commit() reads it: the entry its commit confirmed
# made, the commit before it, and what another user's commit looks like
OURS = {"seq": 0, "user": "u", "client": "netconf", "time": "2026-10-20 19:19:11 CEST", "epoch": 1792516751.0,
        "comment": "C1", "note": "commit confirmed, rollback in 5mins", "pending_rollback_minutes": 5}
PRE = {"seq": 1, "user": "u", "client": "cli", "time": "2026-10-19 02:33:16 CEST", "epoch": 1792369996.0,
       "comment": None, "note": None, "pending_rollback_minutes": None}
THEIRS = {"seq": 0, "user": "other", "client": "cli", "time": "2026-10-20 19:21:40 CEST", "epoch": 1792516900.0,
          "comment": "theirs", "note": None, "pending_rollback_minutes": None}


def history(monkeypatch, *reads):
    """Canned commit_status() replies, one per read, the last one repeating;
    returns the list that grows by one per read made."""
    reads, made = list(reads), []

    def commit_status(host, user, passwd, st, ct, port=None, vendor_hint=None):
        made.append(host)
        return reads.pop(0) if len(reads) > 1 else reads[0]

    monkeypatch.setattr(junos, "commit_status", commit_status)
    return made


def guarded(check):
    return junos.guarded_commit("10.0.0.1", "u", "p", "set a b\n", 5, 30, minutes=5, check=check, comment="C1")


def failing_check():
    raise RuntimeError("bgp down")


def all_names():
    return [c[0] for i in FakeConfig.instances for c in i.calls]


def test_guarded_commit_confirms_or_rolls_back(monkeypatch):
    reads = history(monkeypatch, [OURS, PRE])
    calls = []
    res = guarded(lambda: calls.append("checked") or True)
    assert res["final"] == "confirmed" and calls == ["checked"] and len(reads) == 2
    commits = [c[2] for i in FakeConfig.instances for c in i.calls if c[0] == "commit"]
    assert commits == [{"confirm": 5, "comment": "C1"}, {"confirm": None, "comment": "C1 (confirmed)"}]
    FakeConfig.instances.clear()
    res = guarded(failing_check)
    assert res["final"] == "rolled back" and "bgp down" in res["reason"]
    assert all_names() == ["lock", "load", "diff", "commit_check", "commit", "unlock",
                           "lock", "rollback", "diff", "commit_check", "commit", "unlock"]
    assert FakeConfig.instances[1].calls[1][1] == (1,)       # rollback 1


def test_guarded_commit_takes_the_timer_as_a_countdown_not_an_identity(monkeypatch):
    later = dict(OURS, note="commit confirmed, rollback in 3mins", pending_rollback_minutes=3)
    history(monkeypatch, [OURS, PRE], [later, PRE])
    assert guarded(lambda: True)["final"] == "confirmed"


def test_guarded_commit_sends_nothing_once_another_commit_landed(monkeypatch):
    """Their commit confirmed ours and is rollback 0 now: `rollback 1` would
    put back the change that just failed its checks."""
    entries = [THEIRS, dict(OURS, seq=1, note=None, pending_rollback_minutes=None), PRE]
    history(monkeypatch, [OURS, PRE], entries)
    res = guarded(failing_check)
    assert res["final"] == "not rolled back" and res["checks"] is False
    assert "history changed" in res["reason"] and "bgp down" in res["check_error"]
    assert res["status"] == entries
    assert all_names() == ["lock", "load", "diff", "commit_check", "commit", "unlock"]   # the edit, nothing after
    FakeConfig.instances.clear()
    history(monkeypatch, [OURS, PRE], entries)
    res = guarded(lambda: True)
    assert res["final"] == "not confirmed" and res["checks"] is True and res["status"] == entries
    assert [c[2] for c in cfg().calls if c[0] == "commit"] == [{"confirm": 5, "comment": "C1"}]
    assert len(FakeConfig.instances) == 1


def test_guarded_commit_does_not_roll_back_after_the_timer_ran_out(monkeypatch):
    """Checks that outlast the timer: the device's own rollback is a commit of
    its own and rollback 0 now, so there is nothing left to undo."""
    expired = [{"seq": 0, "user": "u", "client": "other", "time": "2026-10-20 19:24:11 CEST",
                "epoch": 1792517051.0, "comment": None, "note": None, "pending_rollback_minutes": None},
               dict(OURS, seq=1, note=None, pending_rollback_minutes=None), PRE]
    history(monkeypatch, [OURS, PRE], expired)
    res = guarded(lambda: False)
    assert res["final"] == "not rolled back" and res["check_error"] is None
    assert res["status"] == expired and all_names() == ["lock", "load", "diff", "commit_check", "commit", "unlock"]


def test_guarded_commit_needs_its_own_commit_in_the_history(monkeypatch):
    history(monkeypatch, [dict(OURS, note=None, pending_rollback_minutes=None), PRE])
    res = guarded(lambda: True)
    assert res["final"] == "not confirmed" and "no pending commit" in res["reason"]
    assert len(FakeConfig.instances) == 1


def test_guarded_commit_does_not_adopt_someone_elses_commit_confirmed(monkeypatch):
    # Another user's commit confirmed is the pending one right after our edit:
    # it is not ours, so neither their change nor ours is touched.
    foreign = dict(THEIRS, note="commit confirmed, rollback in 10mins", pending_rollback_minutes=10)
    history(monkeypatch, [foreign, dict(OURS, seq=1, note=None, pending_rollback_minutes=None), PRE])
    res = guarded(failing_check)
    assert res["final"] == "not rolled back" and "no pending commit" in res["reason"]
    assert "bgp down" in res["check_error"] and len(FakeConfig.instances) == 1


def test_guarded_commit_only_trusts_the_latest_commit(monkeypatch):
    # Our entry still carries the device's "rollback in" note but a later
    # commit sits at sequence 0: not ours to roll back any more.
    history(monkeypatch, [OURS, PRE], [THEIRS, dict(OURS, seq=1), PRE])
    res = guarded(failing_check)
    assert res["final"] == "not rolled back" and "history changed" in res["reason"]
    assert len(FakeConfig.instances) == 1


# --- #40: no timer means no commit, never a plain one ---------------------------

@pytest.mark.parametrize("minutes", [0, -5, 65536, True])
def test_edit_and_rollback_refuse_a_timer_they_cannot_arm_before_any_session(minutes):
    with pytest.raises(ValueError, match="commit_confirmed must be 1..65535"):
        edit(commit_confirmed=minutes)
    with pytest.raises(ValueError, match="commit_confirmed must be 1..65535"):
        junos.rollback("10.0.0.1", "u", "p", 1, 5, 30, commit_confirmed=minutes)
    with pytest.raises(ValueError, match="commit_confirmed must be 1..65535"):
        junos.guarded_commit("10.0.0.1", "u", "p", "set a b\n", 5, 30, minutes=minutes, check=lambda: True)
    assert FakeDevice.instances == [] and FakeConfig.instances == []


def test_transaction_commit_with_a_bad_timer_leaves_the_candidate_open():
    tx = junos.begin("10.0.0.1", "u", "p", "set system host-name r1\n", 5, 30)
    with pytest.raises(ValueError, match="commit_confirmed must be 1..65535"):
        tx.commit(confirmed=0)
    assert [c[0] for c in cfg().calls] == ["lock", "load", "diff", "commit_check"]   # nothing committed
    tx.abort()
    assert [c[0] for c in cfg().calls][-2:] == ["rollback", "unlock"]


def test_a_valid_timer_still_arms_the_commit():
    out = edit(commit_confirmed=1)
    assert out.startswith("COMMIT CONFIRMED (1 minutes)")
    assert [c for c in cfg().calls if c[0] == "commit"][0][2]["confirm"] == 1

# --- #47: how the NETCONF session is opened --------------------------------------

def test_open_asks_for_huge_replies_and_no_host_key_check_unless_told(monkeypatch):
    monkeypatch.delenv("HSSH_NETCONF_HOSTKEY", raising=False)
    junos.show("10.0.0.1", "u", None, "show version", 5, 30)
    params = FakeDevice.instances[0].params
    assert params["huge_tree"] is True and params["hostkey_verify"] is False
    assert "look_for_keys" not in params and "allow_agent" not in params     # key auth: keys and agent stay
    monkeypatch.setenv("HSSH_NETCONF_HOSTKEY", "yes")
    junos.show("10.0.0.2", "u", None, "show version", 5, 30)
    assert FakeDevice.instances[1].params["hostkey_verify"] is True


def test_a_password_is_the_credential_no_key_is_tried_first():
    junos.show("10.0.0.1", "u", "s3cret", "show version", 5, 30)
    params = FakeDevice.instances[0].params
    assert params["passwd"] == "s3cret" and params["look_for_keys"] is False and params["allow_agent"] is False
