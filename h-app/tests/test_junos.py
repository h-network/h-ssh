"""Junos driver over a fake PyEZ: ordering, dry-run, and the commit edge cases."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh.transports import netconf
from hssh.errors import AmbiguousCommitError, NotAppliedError


class FakeDevice:
    instances = []
    open_error = None
    cli_outputs = {}

    def __init__(self, **params):
        self.params = params
        self.user = params.get("user")      # as PyEZ's Device has it; this fake takes no $USER
        self.timeout = None
        self.opened = False
        self._closed = False
        self.cli_calls = []
        FakeDevice.instances.append(self)

    def open(self):
        if FakeDevice.open_error:
            raise FakeDevice.open_error
        self.opened = True

    def close(self):
        self._closed = True

    @property
    def closed(self):
        # The transport closes sessions beside the work (a helper thread per
        # close); looking at the flag first waits for the closes in flight,
        # so a test sees the state a run's end sees.
        netconf.wait_for_closes()
        return self._closed

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
    return netconf.ConnectError(FakeHost(), msg)


def rpc_timeout(cmd="commit", timeout=30):
    return netconf.RpcTimeoutError(FakeHost(), cmd, timeout)


class FakeConfig:
    instances = []
    diff_text = "[edit]\n+  system host-name r1;"
    raise_on = {}
    on_commit = None        # a Router logging the commit in its history
    on = {}                 # call name -> what happens on the device as it is asked, fn(config)

    def __init__(self, dev):
        self.dev = dev
        self.calls = []
        FakeConfig.instances.append(self)

    def _do(self, name, *a, **kw):
        if name in FakeConfig.on:
            FakeConfig.on[name](self)
        self.calls.append((name, a, kw))
        exc = FakeConfig.raise_on.get(name)
        if exc:
            raise exc

    def lock(self):
        self._do("lock")

    def unlock(self):
        self._do("unlock")

    def load(self, body, format=None, ignore_warning=False):
        self._do("load", body, format=format, ignore_warning=ignore_warning)

    def diff(self):
        self._do("diff")
        return FakeConfig.diff_text

    def commit_check(self, timeout=None):
        self._do("commit_check")

    def commit(self, confirm=None, timeout=None, comment=None):
        self._do("commit", confirm=confirm, comment=comment)
        if FakeConfig.on_commit:
            FakeConfig.on_commit(self, confirm, comment)

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
    FakeConfig.on_commit = None
    FakeConfig.on = {}
    monkeypatch.setattr(netconf, "AVAILABLE", True)
    monkeypatch.setattr(netconf, "JunosDevice", FakeDevice)
    monkeypatch.setattr(netconf, "JunosConfig", FakeConfig)
    # A confirm first asks the device whether anything is waiting (#63).
    monkeypatch.setattr(netconf, "_pending_on", lambda dev, t: {"seq": 0, "pending_rollback_minutes": 5})


def edit(payload="set system host-name r1\n", **kw):
    return netconf.edit("10.0.0.1", "u", "p", payload, 5, 30, **kw)


def cfg():
    return FakeConfig.instances[0]


# --- show -------------------------------------------------------------

def test_show_uses_netconf_on_830_and_strips_pager_hint():
    out = netconf.show("10.0.0.1", "u", "p", "show version | no-more", 5, 30)
    dev = FakeDevice.instances[0]
    assert dev.params["port"] == 830
    assert dev.cli_calls == ["show version"]
    assert out == "output of show version"
    assert dev.closed


def test_explicit_port_is_honoured():
    netconf.show("10.0.0.1", "u", "p", "show version", 5, 30, port=22)
    assert FakeDevice.instances[0].params["port"] == 22


def test_connect_failure_is_not_applied():
    FakeDevice.open_error = connect_error()
    with pytest.raises(NotAppliedError):
        netconf.show("10.0.0.1", "u", "p", "show version", 5, 30)


def test_show_batch_one_session_and_failures_are_per_command():
    FakeDevice.cli_outputs = {"bad": RuntimeError("rpc error")}
    res = netconf.show_batch("10.0.0.1", "u", "p", ["show a", "bad", "show c"], 5, 30)
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
    FakeConfig.raise_on = {"commit_check": netconf.CommitError("bad")}
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
    FakeConfig.raise_on = {"commit": netconf.CommitError("conflict")}
    with pytest.raises(RuntimeError, match="Config error"):
        edit()
    assert "rollback" in cfg().names


def test_load_error_rolls_back_and_unlocks():
    FakeConfig.raise_on = {"load": netconf.ConfigLoadError("syntax")}
    with pytest.raises(RuntimeError, match="Config error"):
        edit()
    assert cfg().names[-2:] == ["rollback", "unlock"]


def test_lock_failure_is_not_applied_and_does_not_unlock():
    FakeConfig.raise_on = {"lock": netconf.LockError("held")}
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
    assert netconf.confirm("10.0.0.1", "u", "p", 5, 30) == "COMMIT CONFIRMED OK"
    assert cfg().names == ["lock", "commit", "unlock"]
    assert cfg().calls[1][2]["confirm"] is None


def test_confirm_refused_lock_is_not_applied_and_sends_nothing():
    """Another user's uncommitted edits refuse the lock; a commit would have
    taken them along with the confirmation."""
    FakeConfig.raise_on = {"lock": netconf.LockError("configuration database modified")}
    with pytest.raises(NotAppliedError, match="Failed to lock"):
        netconf.confirm("10.0.0.1", "u", "p", 5, 30)
    assert cfg().names == ["lock"]


def test_confirm_rejected_commit_unlocks():
    FakeConfig.raise_on = {"commit": netconf.CommitError("conflict")}
    with pytest.raises(RuntimeError, match="Commit failed"):
        netconf.confirm("10.0.0.1", "u", "p", 5, 30)
    assert cfg().names == ["lock", "commit", "unlock"]


def test_confirm_timeout_is_ambiguous():
    FakeConfig.raise_on = {"commit": rpc_timeout()}
    with pytest.raises(AmbiguousCommitError):
        netconf.confirm("10.0.0.1", "u", "p", 5, 30)
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
    assert netconf._config_format(payload) == fmt


def test_set_comments_are_not_sent_to_the_loader():
    edit(payload="# why\nset a b\n")
    load = [c for c in cfg().calls if c[0] == "load"][0]
    assert load[1][0] == "set a b"


# --- rollback ---------------------------------------------------------

def rollback(n=1, **kw):
    return netconf.rollback("10.0.0.1", "u", "p", n, 5, 30, **kw)


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
    FakeConfig.raise_on = {"lock": netconf.LockError("held")}
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
    netconf.confirm("10.0.0.1", "u", "p", 5, 30, comment="done")
    assert commit_call()["comment"] == "done"
    FakeConfig.instances.clear()
    edit()
    assert commit_call()["comment"] is None


def begin(payload="set system host-name r1\n", **kw):
    return netconf.begin("10.0.0.1", "u", "p", payload, 5, 30, **kw)


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


def test_a_transactions_show_the_cli_refused_is_a_failure_not_output():
    """#143: tx.show(), the gate's look at the device on the transaction's
    session, handed back a refusal carried as the reply's text as the
    show's output, where netconf.show() fails it: a gate that looks for a
    word in the output (`'down' not in tx.show(...)`) went on to commit on
    a command the device refused. It raises as show() does, and leaving
    the block aborts with nothing committed."""
    FakeDevice.cli_outputs = {"show log nosuchfile": "\nerror: could not resolve file: nosuchfile\n"}
    with pytest.raises(RuntimeError) as failed:
        with begin() as tx:
            if "down" not in tx.show("show log nosuchfile"):
                tx.commit()
    assert str(failed.value) == ("'show log nosuchfile' was refused by the device: "
                                 "error: could not resolve file: nosuchfile")
    assert not tx.open and cfg().names == ["lock", "load", "diff", "commit_check", "rollback", "unlock"]


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
    FakeConfig.raise_on = {"load": netconf.ConfigLoadError("syntax")}
    with pytest.raises(RuntimeError, match="Config error"):
        begin()
    assert cfg().names == ["lock", "load", "rollback", "unlock"]
    assert FakeDevice.instances[0].closed


def test_transaction_commit_verdicts_match_edit():
    FakeConfig.raise_on = {"commit": netconf.CommitError("conflict")}
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


# The router's commit history as guarded_commit() reads it, kept by a Router:
# every commit made in a test is logged there as the device logs it.
PRE = {"seq": 0, "user": "u", "client": "cli", "time": "2026-10-19 02:33:16 CEST", "epoch": 1792369996.0,
       "comment": None, "note": None, "pending_rollback_minutes": None}


class Router:
    """A router's commit history, newest first, as commit_status() and a
    read on an open session (_history_on, _pending_on) give it. A commit
    FakeConfig makes is logged as the device logs one: under the name its
    session logged in as (the device's `user`), with the comment as the
    device keeps it (`keep`); a later commit ends the wait of the commit
    confirmed before it. `after_commit`, once set, runs right after the
    next commit, before anything reads the history: what lands on the
    device behind it."""

    def __init__(self, monkeypatch, keep=lambda comment: comment):
        self.entries = [dict(PRE)]
        self.keep = keep
        self.after_commit = None
        FakeConfig.on_commit = self._committed
        monkeypatch.setattr(netconf, "commit_status", lambda *a, **kw: self.read())
        monkeypatch.setattr(netconf, "_history_on", lambda dev, t: self.read())
        monkeypatch.setattr(netconf, "_pending_on", lambda dev, t: netconf.pending_commit(self.read()))

    def read(self):
        return [dict(e) for e in self.entries]

    def _committed(self, cfg, confirm, comment):
        self.log(cfg.dev.user, comment, confirm)
        after, self.after_commit = self.after_commit, None
        if after:
            after()

    def log(self, user, comment=None, confirm=None, client="netconf"):
        for e in self.entries:
            e["seq"] += 1
            e["pending_rollback_minutes"] = None
        at = 1792516751 + 60 * len(self.entries)
        self.entries.insert(0, {"seq": 0, "user": user, "client": client, "time": f"@{at}", "epoch": float(at),
                                "comment": self.keep(comment) if comment else None,
                                "note": f"commit confirmed, rollback in {confirm}mins" if confirm else None,
                                "pending_rollback_minutes": confirm})


def guarded(check, comment="C1"):
    return netconf.guarded_commit("10.0.0.1", "u", "p", "set a b\n", 5, 30, minutes=5, check=check, comment=comment)


def failing_check():
    raise RuntimeError("bgp down")


def all_names():
    return [c[0] for i in FakeConfig.instances for c in i.calls]


def committed():
    """Every commit sent, in order: (its timer, its comment)."""
    return [(c[2]["confirm"], c[2]["comment"]) for i in FakeConfig.instances for c in i.calls if c[0] == "commit"]


EDIT = ["lock", "load", "diff", "commit_check", "commit", "unlock"]
# The rollback that looked at the history under its lock and found it moved:
# `rollback 1` loaded and checked, then discarded, nothing committed.
LOOKED = ["lock", "rollback", "diff", "commit_check", "rollback", "unlock"]


def test_guarded_commit_confirms_or_rolls_back(monkeypatch):
    router = Router(monkeypatch)
    calls = []
    res = guarded(lambda: calls.append("checked") or True)
    assert res["final"] == "confirmed" and calls == ["checked"]
    assert committed() == [(5, "C1"), (None, "C1 (confirmed)")]
    FakeConfig.instances.clear()
    res = guarded(failing_check)
    assert res["final"] == "rolled back" and "bgp down" in res["reason"]
    assert all_names() == EDIT + ["lock", "rollback", "diff", "commit_check", "commit", "unlock"]
    assert FakeConfig.instances[1].calls[1][1] == (1,)       # rollback 1
    assert router.entries[0]["comment"] == "C1 (rolled back: checks failed)"


def test_guarded_commit_takes_the_timer_as_a_countdown_not_an_identity(monkeypatch):
    router = Router(monkeypatch)

    def check():
        router.entries[0].update(note="commit confirmed, rollback in 3mins", pending_rollback_minutes=3)
        return True
    assert guarded(check)["final"] == "confirmed"


def test_guarded_commit_commits_nothing_once_another_commit_landed(monkeypatch):
    """Their commit confirmed ours and is rollback 0 now: `rollback 1` would
    put back the change that just failed its checks."""
    router = Router(monkeypatch)

    def theirs_then(verdict):
        router.log("other", "theirs", client="cli")
        return verdict()
    res = guarded(lambda: theirs_then(failing_check))
    assert res["final"] == "not rolled back" and res["checks"] is False
    assert "history changed" in res["reason"] and "bgp down" in res["check_error"]
    assert res["status"] == router.entries and res["status"][0]["user"] == "other"
    assert all_names() == EDIT + LOOKED                        # the edit, nothing committed after
    FakeConfig.instances.clear()
    res = guarded(lambda: theirs_then(lambda: True))
    assert res["final"] == "not confirmed" and res["checks"] is True and res["status"] == router.entries
    assert committed() == [(5, "C1")]
    assert all_names() == EDIT + ["lock", "unlock"]


def test_guarded_commit_does_not_roll_back_after_the_timer_ran_out(monkeypatch):
    """Checks that outlast the timer: the device's own rollback is a commit of
    its own and rollback 0 now, so there is nothing left to undo."""
    router = Router(monkeypatch)

    def expired():
        router.log("u", client="other")
        return False
    res = guarded(expired)
    assert res["final"] == "not rolled back" and res["check_error"] is None
    assert res["status"] == router.entries and all_names() == EDIT + LOOKED


def test_guarded_commit_needs_its_own_commit_in_the_history(monkeypatch):
    router = Router(monkeypatch)
    router.after_commit = lambda: router.entries[0].update(note=None, pending_rollback_minutes=None)
    res = guarded(lambda: True)
    assert res["final"] == "not confirmed" and "no pending commit" in res["reason"]
    assert len(FakeConfig.instances) == 1


@pytest.mark.parametrize("who", ["other", "u"])
def test_guarded_commit_does_not_adopt_someone_elses_commit_confirmed(monkeypatch, who):
    """Another commit confirmed is the pending one right after our edit: it
    is not ours, so neither that change nor ours is touched. Nor is one made
    under our own login with our comment (#146), which only the comment told
    apart, and only where it differed: ours is the commit logged right after
    the latest one the history had under our lock, and here that is
    sequence 1."""
    router = Router(monkeypatch)
    router.after_commit = lambda: router.log(who, "C1", 10, client="cli")
    res = guarded(failing_check)
    assert res["final"] == "not rolled back" and "no pending commit" in res["reason"]
    assert "bgp down" in res["check_error"] and len(FakeConfig.instances) == 1


def test_guarded_commit_only_trusts_the_latest_commit(monkeypatch):
    # Our entry still carries the device's "rollback in" note but a later
    # commit sits at sequence 0: not ours to roll back any more.
    router = Router(monkeypatch)

    def later():
        router.log("other", "theirs", client="cli")
        router.entries[1].update(note="commit confirmed, rollback in 5mins", pending_rollback_minutes=5)
        raise RuntimeError("bgp down")
    res = guarded(later)
    assert res["final"] == "not rolled back" and "history changed" in res["reason"]
    assert committed() == [(5, "C1")]


# --- #146: the history looked at under the lock the confirmation or rollback holds ---

@pytest.mark.parametrize("check, final, after", [
    (failing_check, "not rolled back", LOOKED),
    (lambda: True, "not confirmed", ["lock", "unlock"]),
], ids=["rollback", "confirmation"])
def test_guarded_commit_sees_a_commit_that_lands_before_its_lock(monkeypatch, check, final, after):
    """#146: the history was read in a session of its own and the rollback
    (or the confirmation) made in another, which checked only that some
    commit confirmed was waiting. A commit that landed between that read
    and the rollback's lock was not seen: `rollback 1` reverted it, the
    change that failed its checks stayed committed, and the answer was
    `rolled back`. The history is read under the lock the rollback or the
    confirmation holds: nothing is committed after the edit, the lock is
    released, and the answer says the history changed."""
    router = Router(monkeypatch)
    locks = []

    def lands_before_the_lock(cfg):
        locks.append(cfg)
        if len(locks) == 2:                       # the confirmation's or the rollback's
            router.log("other", "theirs", client="cli")
    FakeConfig.on["lock"] = lands_before_the_lock
    res = guarded(check)
    assert res["final"] == final and "history changed" in res["reason"], res
    assert res["status"] == router.entries and res["status"][0]["user"] == "other"
    assert committed() == [(5, "C1")] and all_names() == EDIT + after


@pytest.mark.parametrize("check, after", [(failing_check, ["rollback", "unlock"]), (lambda: True, ["lock", "unlock"])],
                         ids=["rollback", "confirmation"])
def test_guarded_commit_gives_the_lock_back_when_the_history_cannot_be_read_under_it(monkeypatch, check, after):
    """#146: a history the router will not show under the lock (a login
    class without the right to see it) commits nothing, releases the lock
    and raises."""
    router = Router(monkeypatch)
    reads = []

    def history_on(dev, t):
        reads.append(dev)
        if len(reads) == 2:                       # the one under the confirmation's or the rollback's lock
            raise RuntimeError("permission denied")
        return router.read()
    monkeypatch.setattr(netconf, "_history_on", history_on)
    with pytest.raises(RuntimeError, match="permission denied"):
        guarded(check)
    assert committed() == [(5, "C1")] and all_names()[-len(after):] == after


# --- #146: the commit guarded_commit() made, found by the name it logged in as ---

class PyezUserDevice(FakeDevice):
    """A FakeDevice whose `user` is the one PyEZ's own Device works out for
    the same parameters, made and never opened: `user`, else the User
    ~/.ssh/config gives the host, else $USER."""

    def __init__(self, **params):
        super().__init__(**params)
        from jnpr.junos import Device
        self.user = Device(host=params["host"], user=params.get("user"), gather_facts=False).user


@pytest.fixture
def pyez_login(monkeypatch, tmp_path):
    """Sessions whose login is PyEZ's own: $USER set, and a home of the
    test's, where a ~/.ssh/config may give the router a User."""
    pytest.importorskip("jnpr.junos")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USER", "reviewer")
    monkeypatch.setattr(netconf, "JunosDevice", PyezUserDevice)
    return tmp_path


def ssh_config_user(home, name):
    (home / ".ssh").mkdir(exist_ok=True)
    (home / ".ssh" / "config").write_text(f"Host 10.0.0.1\n  User {name}\n")


@pytest.mark.parametrize("login, check, final", [
    ("reviewer", lambda: True, "confirmed"),
    ("reviewer", failing_check, "rolled back"),
    ("cfguser", failing_check, "rolled back"),
])
def test_guarded_commit_without_a_user_finds_the_commit_it_made(monkeypatch, pyez_login, login, check, final):
    """#146: with user=None the history logs the commit under the name PyEZ
    logged in as ($USER, or the User ~/.ssh/config gives the router), and
    guarded_commit() looked for None there: a failing check ended `not
    rolled back` with nothing sent, the change that failed its checks live
    until the timer, and a passing one `not confirmed`, the good change
    reverted when the timer ran out. Each is its own commit now."""
    if login == "cfguser":
        ssh_config_user(pyez_login, "cfguser")
    router = Router(monkeypatch)
    res = netconf.guarded_commit("10.0.0.1", None, None, "set a b\n", 5, 30, minutes=5, check=check, comment="C1")
    assert res["final"] == final, res.get("reason")
    commits = [c for i in FakeConfig.instances for c in i.calls if c[0] in ("rollback", "commit")]
    if final == "confirmed":
        assert commits == [("commit", (), {"confirm": 5, "comment": "C1"}),
                           ("commit", (), {"confirm": None, "comment": "C1 (confirmed)"})]
    else:
        assert "bgp down" in res["reason"]
        assert commits == [("commit", (), {"confirm": 5, "comment": "C1"}), ("rollback", (1,), {}),
                           ("commit", (), {"confirm": None, "comment": "C1 (rolled back: checks failed)"})]
    assert [e["user"] for e in router.entries[:2]] == [login, login]
    assert router.entries[0]["pending_rollback_minutes"] is None        # nothing left waiting


def test_a_refused_login_without_a_user_names_the_login_pyez_used(pyez_login):
    """#146: the reason read `authentication failed for None at ...`; it
    names the login the session tried, $USER or the ~/.ssh/config User."""
    from jnpr.junos.exception import ConnectAuthError
    FakeDevice.open_error = ConnectAuthError(FakeHost())
    with pytest.raises(NotAppliedError, match=r"authentication failed for reviewer at 10\.0\.0\.1:830$"):
        netconf.show("10.0.0.1", None, None, "show version", 5, 30)
    ssh_config_user(pyez_login, "cfguser")
    with pytest.raises(NotAppliedError, match=r"authentication failed for cfguser at 10\.0\.0\.1:830$"):
        netconf.show("10.0.0.1", None, None, "show version", 5, 30)
    with pytest.raises(NotAppliedError, match=r"authentication failed for named at 10\.0\.0\.1:830$"):
        netconf.show("10.0.0.1", "named", None, "show version", 5, 30)


# --- #146: a commit comment Junos logs as given, and never the way to our commit ---

@pytest.mark.parametrize("keep", [lambda comment: None, lambda comment: comment.split()[-1]],
                         ids=["none of it", "part of it"])
def test_guarded_commit_finds_its_commit_whatever_the_device_kept_of_the_comment(monkeypatch, keep):
    """#146: the commit was found by the comment's text, and the device keeps
    a comment as it keeps it (live, of one with a line break only the last
    line): a passing check ended `not confirmed`, the good change reverted
    at the timer, a failing one `not rolled back`. The commit is found by
    its place in the history and its login."""
    Router(monkeypatch, keep=keep)
    res = guarded(lambda: True, comment="C1 cutover")
    assert res["final"] == "confirmed", res.get("reason")
    assert committed() == [(5, "C1 cutover"), (None, "C1 cutover (confirmed)")]


BAD_COMMENTS = [("line one\nline two", "has a line break"), ("cutover \x1b[1m", "has an ESC"),
                ("   ", "has no text"), ("", "has no text"), ("é" * 257, "is 514 bytes"),
                ("C1\ufffe", "has a character XML cannot carry")]


@pytest.mark.parametrize("comment, fault", BAD_COMMENTS,
                         ids=["line break", "ESC", "blanks", "empty", "514 bytes", "U+FFFE"])
def test_a_comment_junos_would_not_log_as_given_is_refused_before_any_session(comment, fault):
    """#146: the comment went to the device as given: over 512 bytes, or only
    blanks, it went through lock, load, diff and commit check and then
    failed the commit; with a line break the device logged its last line
    alone; '' was dropped without a word; an ESC failed in PyEZ as `commit
    outcome unknown`. edit(), rollback(), confirm() and guarded_commit()
    refuse it before a session is opened."""
    for call in (lambda: edit(comment=comment), lambda: rollback(1, comment=comment),
                 lambda: netconf.confirm("10.0.0.1", "u", "p", 5, 30, comment=comment),
                 lambda: guarded(lambda: True, comment=comment)):
        with pytest.raises(ValueError, match=f"^the comment .* {fault}.*; nothing was sent to the device$"):
            call()
    assert FakeDevice.instances == [] and FakeConfig.instances == []


def test_a_comment_is_sent_stripped_and_512_bytes_go_through():
    edit(comment="  C1 cutover\n")                      # the line break a YAML block ends with
    assert commit_call()["comment"] == "C1 cutover"
    FakeConfig.instances.clear()
    rollback(1, comment="A" * 512)
    assert commit_call()["comment"] == "A" * 512


def test_guarded_commit_needs_room_for_the_comments_it_adds(monkeypatch):
    """#146: guarded_commit() logs its rollback as the comment and ` (rolled
    back: checks failed)`: a comment of 500 bytes committed, then failed
    the rollback at its commit check, the change that failed its checks
    left live. Refused before anything is sent; 483 bytes go through."""
    with pytest.raises(ValueError, match="is 484 bytes: .* which leaves 483 for the comment; nothing was sent"):
        guarded(failing_check, comment="A" * 484)
    assert FakeDevice.instances == [] and FakeConfig.instances == []
    router = Router(monkeypatch)
    assert guarded(failing_check, comment="A" * 483)["final"] == "rolled back"
    assert len(router.entries[0]["comment"].encode()) == 512


TX_REFUSED = "; nothing was committed: the candidate was discarded and the lock released$"


def test_a_transaction_refusing_its_comment_rolls_back_and_unlocks():
    """#146: an ESC reached PyEZ, which refused it before the commit RPC was
    built, and the except around the commit took that for a commit in
    flight: `commit outcome unknown`, the session dropped with the candidate
    loaded and the lock held. Nothing was committed: the candidate is
    discarded and the lock released, and the error says what was wrong and
    that much. It read `nothing was sent to the device`, with the lock, the
    load, the diff and the commit check sent before it and the rollback and
    the unlock after."""
    tx = begin()
    with pytest.raises(ValueError, match=r"^the comment 'cutover \\x1b\[1m' has an ESC; .*" + TX_REFUSED) as exc:
        tx.commit(confirmed=5, comment="cutover \x1b[1m")
    assert "nothing was sent" not in str(exc.value)
    assert cfg().names == ["lock", "load", "diff", "commit_check", "rollback", "unlock"] and not tx.open
    assert FakeDevice.instances[0].closed                # given back, not dropped as in doubt


def test_a_transaction_on_pyez_sends_no_commit_for_a_refused_comment(monkeypatch):
    """#146, as found: PyEZ's own Config on a device that answers every RPC.
    An ESC in the comment sent no commit RPC and ended `commit outcome
    unknown` with neither rollback nor unlock; now the candidate's rollback
    and the unlock are what goes out after the commit check, and the error
    says nothing was committed, not that nothing was sent."""
    pytest.importorskip("jnpr.junos")
    from lxml import etree
    from jnpr.junos.rpcmeta import _RpcMetaExec
    from jnpr.junos.utils.config import Config
    sent = []

    class Dev(FakeDevice):
        def __init__(self, **params):
            super().__init__(**params)
            self.connected = True
            self.rpc = _RpcMetaExec(self)

        def execute(self, rpc, **kw):
            sent.append(etree.tostring(rpc).decode())
            if rpc.tag == "get-configuration":
                return etree.fromstring("<configuration-information><configuration-output>"
                                        "[edit system]\n+  location x;</configuration-output>"
                                        "</configuration-information>")
            return etree.fromstring("<ok/>")

    monkeypatch.setattr(netconf, "JunosDevice", Dev)
    monkeypatch.setattr(netconf, "JunosConfig", Config)
    tx = netconf.begin("10.0.0.1", "u", "p", "set system location x\n", 5, 30)
    with pytest.raises(ValueError, match="has an ESC; .*" + TX_REFUSED):
        tx.commit(confirmed=5, comment="cutover \x1b[1m")
    tags = [etree.fromstring(r).tag for r in sent]
    assert tags == ["lock-configuration", "load-configuration", "get-configuration", "commit-configuration",
                    "load-configuration", "unlock-configuration"], sent
    assert "<check/>" in sent[3] and 'rollback="0"' in sent[4]      # the commit check; rollback 0


# --- #40: no timer means no commit, never a plain one ---------------------------

@pytest.mark.parametrize("minutes", [0, -5, 65536, True])
def test_edit_and_rollback_refuse_a_timer_they_cannot_arm_before_any_session(minutes):
    with pytest.raises(ValueError, match="commit_confirmed must be 1..65535"):
        edit(commit_confirmed=minutes)
    with pytest.raises(ValueError, match="commit_confirmed must be 1..65535"):
        netconf.rollback("10.0.0.1", "u", "p", 1, 5, 30, commit_confirmed=minutes)
    with pytest.raises(ValueError, match="commit_confirmed must be 1..65535"):
        netconf.guarded_commit("10.0.0.1", "u", "p", "set a b\n", 5, 30, minutes=minutes, check=lambda: True)
    assert FakeDevice.instances == [] and FakeConfig.instances == []


def test_transaction_commit_with_a_bad_timer_leaves_the_candidate_open():
    tx = netconf.begin("10.0.0.1", "u", "p", "set system host-name r1\n", 5, 30)
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

def test_open_asks_for_huge_replies_and_checks_the_host_key_unless_told_not_to(monkeypatch):
    """#150: the router's key is verified by default (accept-new, pinned in
    ~/.h-ssh/known_hosts as the ssh transport pins), `yes` is strict and
    `no` is the opt-out to the old behaviour; anything else is refused,
    read per call."""
    monkeypatch.delenv("HSSH_NETCONF_HOSTKEY", raising=False)
    netconf.show("10.0.0.1", "u", None, "show version", 5, 30)
    params = FakeDevice.instances[0].params
    assert params["huge_tree"] is True and params["hostkey_verify"] is True
    assert "look_for_keys" not in params and "allow_agent" not in params     # key auth: keys and agent stay
    monkeypatch.setenv("HSSH_NETCONF_HOSTKEY", "no")
    netconf.show("10.0.0.2", "u", None, "show version", 5, 30)
    assert FakeDevice.instances[1].params["hostkey_verify"] is False
    monkeypatch.setenv("HSSH_NETCONF_HOSTKEY", "yes")
    netconf.show("10.0.0.3", "u", None, "show version", 5, 30)
    assert FakeDevice.instances[2].params["hostkey_verify"] is True
    for value in ("ask", "1", "true", "off"):
        monkeypatch.setenv("HSSH_NETCONF_HOSTKEY", value)
        with pytest.raises(RuntimeError, match=f"invalid HSSH_NETCONF_HOSTKEY='{value}'"):
            netconf.show("10.0.0.4", "u", None, "show version", 5, 30)
    assert len(FakeDevice.instances) == 3                                    # nothing opened for those


def test_the_router_is_pinned_on_first_contact_and_refused_when_its_key_changes(tmp_path, monkeypatch):
    """What ncclient asks known_hosts (#150), on the store the ssh transport
    keeps: an unknown router is pinned under its port name on first contact
    (accept-new, the default), a pinned one is accepted again, one that
    shows another key is refused before the password goes, and `yes`
    refuses an unknown router. The bare name ncclient tries first never
    pins; a pin under it (the ssh transport's, port 22) speaks for the
    device as a whole. A key ~/.ssh/known_hosts marks @revoked is refused
    whatever the pin says."""
    import paramiko
    from hssh.transports import ssh as ssh_transport
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("HSSH_NETCONF_HOSTKEY", raising=False)
    pins = tmp_path / ".h-ssh" / "known_hosts"
    k1, k2 = paramiko.ECDSAKey.generate(), paramiko.ECDSAKey.generate()
    store = netconf._KnownHosts()
    assert store.check("10.0.0.1", k1) is False and pins.read_text() == ""   # the bare name decides nothing
    assert store.check("[10.0.0.1]:830", k1) is True
    assert pins.read_text() == f"[10.0.0.1]:830 {k1.get_name()} {k1.get_base64()}\n"
    again = netconf._KnownHosts()
    assert again.check("[10.0.0.1]:830", k1) is True
    assert list(again.lookup("[10.0.0.1]:830").keys()) == [k1.get_name()]  # the type ncclient will prefer
    with pytest.raises(paramiko.SSHException, match="not the one pinned"):
        again.check("[10.0.0.1]:830", k2)
    assert pins.read_text().count("\n") == 1                                 # nothing pinned over it
    assert netconf._KnownHosts().check("[10.0.0.1]:22", k1) is True          # port 22 pins the bare name
    assert f"\n10.0.0.1 {k1.get_name()} {k1.get_base64()}\n" in pins.read_text()
    with pytest.raises(paramiko.SSHException, match="not the one pinned"):
        netconf._KnownHosts().check("[10.0.0.1]:22000", k2)                 # the bare pin speaks for the device
    monkeypatch.setenv("HSSH_NETCONF_HOSTKEY", "yes")
    assert netconf._KnownHosts().check("[10.0.0.2]:830", k1) is False and "10.0.0.2" not in pins.read_text()
    assert netconf._KnownHosts().check("[10.0.0.1]:830", k1) is True
    monkeypatch.delenv("HSSH_NETCONF_HOSTKEY", raising=False)
    system = tmp_path / ".ssh" / "known_hosts"
    system.parent.mkdir()
    system.write_text(f"@revoked * {k1.get_name()} {k1.get_base64()}\n")
    revoked = netconf._KnownHosts()
    revoked.load(str(system))
    with pytest.raises(paramiko.SSHException, match="marked @revoked"):
        revoked.check("[10.0.0.1]:830", k1)
    ssh_transport._PINS.clear()


def test_a_password_is_the_credential_no_key_is_tried_first():
    netconf.show("10.0.0.1", "u", "s3cret", "show version", 5, 30)
    params = FakeDevice.instances[0].params
    assert params["passwd"] == "s3cret" and params["look_for_keys"] is False and params["allow_agent"] is False


# --- #67 (M2): a delete of what is not there is a no-op, not a failure ----------

def test_load_ignores_statement_not_found_and_nothing_else():
    edit("delete system services telnet\n")
    load = [c for c in cfg().calls if c[0] == "load"][0]
    assert load[2]["ignore_warning"] == "statement not found"
    assert netconf.IGNORED_LOAD_WARNINGS == "statement not found"


def test_the_session_close_is_not_on_the_callers_clock(monkeypatch):
    """<close-session> and its acknowledgement are ~100 ms of waiting on the
    device per session. A show returns as soon as the reply is in; the close
    runs beside the work, and wait_for_closes() joins what is in flight."""
    import threading
    import time as _time

    class SlowClose(FakeDevice):
        def close(self):
            _time.sleep(0.3)
            super().close()

    monkeypatch.setattr(netconf, "JunosDevice", SlowClose)
    FakeDevice.instances.clear()
    t = _time.perf_counter()
    assert netconf.show("10.0.0.1", "u", "p", "show version", session_timeout=5, command_timeout=5) == "output of show version"
    assert _time.perf_counter() - t < 0.25              # not held for the 0.3 s close
    dev = FakeDevice.instances[0]
    assert not dev._closed                              # still closing, in its helper thread
    assert netconf.wait_for_closes(timeout=2.0) == 0    # joined
    assert dev._closed
    assert not any(th.name == "hssh-netconf-close" and th.is_alive() for th in threading.enumerate())


def test_a_close_thread_the_system_refuses_closes_on_the_caller_instead(monkeypatch):
    """Thread.start() raises under `ulimit -u` or a container's pids.max.
    The never-started thread stayed in the set: the session was never
    closed, the RuntimeError came out of the pool's finally over the show's
    result, and every later wait_for_closes() raised instead of waiting."""
    import threading
    real_start = threading.Thread.start

    def start(self):
        if self.name == "hssh-netconf-close":
            raise RuntimeError("can't start new thread")
        real_start(self)
    monkeypatch.setattr(threading.Thread, "start", start)
    assert netconf.wait_for_closes() == 0
    assert netconf.show("10.0.0.1", "u", "p", "show version", 5, 30) == "output of show version"
    dev = FakeDevice.instances[0]
    assert dev._closed                                  # closed on the caller, before show() returned
    assert not netconf._CLOSES
    assert netconf.wait_for_closes() == 0


def test_wait_for_closes_skips_an_entry_that_was_never_started():
    """_close() adds its thread to the set before it starts it; a wait that
    looks in between must not trip over an entry it cannot join."""
    import threading
    t = threading.Thread(target=lambda: None, name="hssh-netconf-close", daemon=True)
    with netconf._CLOSES_LOCK:
        netconf._CLOSES.add(t)
    try:
        assert netconf.wait_for_closes(timeout=0.1) == 0
    finally:
        with netconf._CLOSES_LOCK:
            netconf._CLOSES.discard(t)
