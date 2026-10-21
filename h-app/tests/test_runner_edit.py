"""Runner policy for edits: dry-run, commit-confirmed, retry, and confirm."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import runner, vendors
from hssh.core import Target, read_set_file_for_device
from hssh.errors import AmbiguousCommitError, NotAppliedError
from hssh.vendors import junos


class FakeVendor:
    def __init__(self, effects=None, with_confirm=False):
        self.effects = list(effects or [])
        self.edit_calls = []
        self.confirm_calls = []
        if with_confirm:
            self.confirm = self._confirm

    def edit(self, host, user, passwd, payload, st, ct, commit_confirmed=None,
             port=None, vendor_hint=None, **kw):
        self.edit_calls.append({"payload": payload, "cc": commit_confirmed, **kw})
        if self.effects:
            eff = self.effects.pop(0)
            if isinstance(eff, Exception):
                raise eff
            return eff
        return "COMMIT OK"

    def _confirm(self, host, user, passwd, st, ct, port=None, vendor_hint=None):
        self.confirm_calls.append(host)
        return "COMMIT CONFIRMED OK"


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(runner.time, "sleep", lambda s: None)


def run(monkeypatch, vendor_name, mod, mode="edit-cmd", edit_cmd="set a b",
        dry_run=False, commit_confirmed=None, config_dir=None, broadcast_file=None, attempts=3,
        expected_diff=None):
    monkeypatch.setitem(vendors.VENDORS, vendor_name, mod)
    return runner.run_for_target(
        t=Target("R1", "10.0.0.1", vendor_name), transport=vendor_name, mode=mode,
        show_cmd=None, edit_cmd=edit_cmd, config_dir=config_dir, broadcast_file=broadcast_file,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=dry_run, commit_confirmed=commit_confirmed, save_dir=None,
        quiet=True, max_attempts=attempts, expected_diff=expected_diff)


def test_junos_dry_run_reaches_the_driver(monkeypatch):
    v = FakeVendor(["DRY-RUN: commit check passed"])
    name, ok, out, _ = run(monkeypatch, "junos", v, dry_run=True)
    assert ok and "commit check passed" in out
    assert v.edit_calls[0]["dry_run"] is True


@pytest.mark.parametrize("vendor", ["ssh", "arista", "openssh", "telnet-ios"])
def test_dry_run_is_refused_where_it_cannot_be_real(monkeypatch, vendor):
    v = FakeVendor()
    _, ok, out, _ = run(monkeypatch, vendor, v, dry_run=True)
    assert not ok and "not supported" in out
    assert v.edit_calls == []


@pytest.mark.parametrize("vendor", ["ssh", "arista", "telnet-ios"])
def test_commit_confirmed_is_refused_where_it_would_be_ignored(monkeypatch, vendor):
    v = FakeVendor()
    _, ok, out, _ = run(monkeypatch, vendor, v, commit_confirmed=5)
    assert not ok and "not supported" in out
    assert v.edit_calls == []


def test_junos_commit_confirmed_is_passed_through(monkeypatch):
    v = FakeVendor()
    run(monkeypatch, "junos", v, commit_confirmed=5)
    assert v.edit_calls[0]["cc"] == 5


def test_expected_diff_reaches_the_driver_and_is_refused_elsewhere(monkeypatch):
    """--show-diff's commit carries the previewed diff; a transport that
    cannot diff a candidate cannot check one, and says so before any I/O."""
    v = FakeVendor()
    run(monkeypatch, "junos", v, expected_diff="+ x")
    assert v.edit_calls[0]["expected_diff"] == "+ x"
    v = FakeVendor()
    run(monkeypatch, "junos", v)
    assert "expected_diff" not in v.edit_calls[0]
    v = FakeVendor()
    _, ok, out, _ = run(monkeypatch, "ssh", v, expected_diff="+ x")
    assert not ok and "not supported" in out and v.edit_calls == []


def test_edit_failure_is_not_retried(monkeypatch):
    v = FakeVendor([RuntimeError("weird"), "COMMIT OK"])
    _, ok, out, _ = run(monkeypatch, "junos", v)
    assert not ok and len(v.edit_calls) == 1


def test_ambiguous_commit_is_not_retried(monkeypatch):
    v = FakeVendor([AmbiguousCommitError("commit outcome unknown"), "COMMIT OK"])
    _, ok, out, _ = run(monkeypatch, "junos", v, commit_confirmed=5)
    assert not ok and "outcome unknown" in out and len(v.edit_calls) == 1


def test_not_applied_is_retried(monkeypatch):
    v = FakeVendor([NotAppliedError("lock held"), NotAppliedError("lock held"), "COMMIT OK"])
    _, ok, _, _ = run(monkeypatch, "junos", v)
    assert ok and len(v.edit_calls) == 3


def test_not_applied_still_respects_the_attempt_budget(monkeypatch):
    v = FakeVendor([NotAppliedError("lock held")] * 5)
    _, ok, _, _ = run(monkeypatch, "junos", v, attempts=2)
    assert not ok and len(v.edit_calls) == 2


def test_dash_eC_commit_confirms(monkeypatch):
    v = FakeVendor(with_confirm=True)
    _, ok, out, _ = run(monkeypatch, "junos", v, edit_cmd="commit")
    assert ok and "CONFIRMED" in out
    assert v.confirm_calls == ["10.0.0.1"] and v.edit_calls == []


def test_commit_in_a_config_file_is_config(monkeypatch, tmp_path):
    (tmp_path / "R1.set").write_text("commit\n")
    v = FakeVendor(with_confirm=True)
    run(monkeypatch, "junos", v, mode="edit-dir", edit_cmd=None, config_dir=str(tmp_path))
    assert v.confirm_calls == [] and len(v.edit_calls) == 1


# A '#' inside a set line is part of the value: the syntax guard passes the
# file as written, so that is what the device must get (issue #23).
SET_FILE = ("# full-line comment\n"
            "set snmp community ab#12 authorization read-only\n"
            'set interfaces ge-0/0/0 description "uplink #3"\n')
SET_LINES = ("set snmp community ab#12 authorization read-only\n"
             'set interfaces ge-0/0/0 description "uplink #3"\n')


def test_dash_eD_keeps_an_inline_hash(monkeypatch, tmp_path):
    (tmp_path / "R1.set").write_text(SET_FILE)
    v = FakeVendor()
    _, ok, _, _ = run(monkeypatch, "junos", v, mode="edit-dir", edit_cmd=None, config_dir=str(tmp_path))
    assert ok and v.edit_calls[0]["payload"] == SET_LINES
    assert v.edit_calls[0]["payload"] == read_set_file_for_device(str(tmp_path), "R1")


def test_dash_eD_and_dash_eB_load_the_same_lines(monkeypatch, tmp_path):
    (tmp_path / "R1.set").write_text(SET_FILE)
    by_dir, by_file = FakeVendor(), FakeVendor()
    run(monkeypatch, "junos", by_dir, mode="edit-dir", edit_cmd=None, config_dir=str(tmp_path))
    run(monkeypatch, "junos", by_file, mode="edit-broadcast", edit_cmd=None,
        broadcast_file=str(tmp_path / "R1.set"))
    assert by_file.edit_calls[0]["payload"] == SET_FILE      # -eB hands the driver the file as is
    assert junos._strip_comments(by_file.edit_calls[0]["payload"]) + "\n" == by_dir.edit_calls[0]["payload"]


def test_runner_leaves_name_resolution_to_the_transport(monkeypatch):
    """The runner once called gethostbyname before every attempt: result
    unused, errors swallowed, one blocking resolver round-trip per device."""
    import socket
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda host: calls.append(host))
    _, ok, _, _ = run(monkeypatch, "junos", FakeVendor())
    assert ok and calls == []


class FakeGate:
    def __init__(self):
        self.events = []

    def check_device(self, host):
        self.events.append("check")
        return True, "ok"

    def release_device(self, host):
        self.events.append("release")

    def set_cooldown(self, host):
        self.events.append("cooldown")


def run_gated(monkeypatch, vendor_name, mod, gate, **kw):
    monkeypatch.setitem(vendors.VENDORS, vendor_name, mod)
    return runner.run_for_target(
        t=Target("R1", "10.0.0.1", vendor_name), transport=vendor_name, mode="edit-cmd",
        show_cmd=None, edit_cmd="set a b", config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=kw.get("dry_run", False), commit_confirmed=kw.get("commit_confirmed"),
        save_dir=None, quiet=True, safety_gate=gate, max_attempts=1)


def test_refused_request_does_not_cool_the_device(monkeypatch):
    gate = FakeGate()
    _, ok, _, _ = run_gated(monkeypatch, "ssh", FakeVendor(), gate, dry_run=True)
    assert not ok
    assert gate.events == ["check", "release"]


def test_device_failure_does_cool_the_device(monkeypatch):
    gate = FakeGate()
    v = FakeVendor([RuntimeError("session reset")])
    _, ok, _, _ = run_gated(monkeypatch, "junos", v, gate)
    assert not ok
    assert gate.events == ["check", "cooldown"]


# --- rollback mode -----------------------------------------------------------

class RollbackVendor(FakeVendor):
    def __init__(self, effects=None):
        super().__init__(effects)
        self.rollback_calls = []

    def rollback(self, host, user, passwd, n, st, ct, port=None, vendor_hint=None,
                 dry_run=False, commit_confirmed=None, **kw):
        self.rollback_calls.append({"n": n, "dry_run": dry_run, "cc": commit_confirmed, **kw})
        if self.effects:
            eff = self.effects.pop(0)
            if isinstance(eff, Exception):
                raise eff
            return eff
        return f"ROLLBACK {n}: COMMIT OK"


def run_rollback(monkeypatch, vendor_name, mod, n=1, dry_run=False, commit_confirmed=None, attempts=3,
                 expected_diff=None):
    monkeypatch.setitem(vendors.VENDORS, vendor_name, mod)
    return runner.run_for_target(
        t=Target("R1", "10.0.0.1", vendor_name), transport=vendor_name, mode="rollback",
        show_cmd=None, edit_cmd=None, config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=dry_run, commit_confirmed=commit_confirmed, save_dir=None,
        quiet=True, max_attempts=attempts, rollback=n, expected_diff=expected_diff)


def test_rollback_reaches_the_driver_with_number_and_flags(monkeypatch):
    v = RollbackVendor()
    _, ok, out, _ = run_rollback(monkeypatch, "junos", v, n=3, dry_run=True, commit_confirmed=None)
    assert ok and "ROLLBACK 3" in out
    assert v.rollback_calls == [{"n": 3, "dry_run": True, "cc": None}]
    v = RollbackVendor()
    run_rollback(monkeypatch, "junos", v, n=3, expected_diff="- x")
    assert v.rollback_calls == [{"n": 3, "dry_run": False, "cc": None, "expected_diff": "- x"}]


def test_rollback_is_refused_where_the_transport_cannot(monkeypatch):
    v = FakeVendor()      # no rollback() at all
    _, ok, out, _ = run_rollback(monkeypatch, "ssh", v, n=1)
    assert not ok and "not supported" in out and v.edit_calls == []


def test_rollback_retries_only_when_nothing_was_applied(monkeypatch):
    v = RollbackVendor([NotAppliedError("lock"), "ROLLBACK 1: COMMIT OK"])
    _, ok, out, _ = run_rollback(monkeypatch, "junos", v)
    assert ok and len(v.rollback_calls) == 2
    v = RollbackVendor([AmbiguousCommitError("unknown")])
    _, ok, out, _ = run_rollback(monkeypatch, "junos", v)
    assert not ok and "unknown" in out and len(v.rollback_calls) == 1


# --- comments and commit status ----------------------------------------------

def test_comment_reaches_the_junos_driver_and_is_refused_elsewhere(monkeypatch):
    v = FakeVendor()
    monkeypatch.setitem(vendors.VENDORS, "junos", v)
    runner.run_for_target(
        t=Target("R1", "10.0.0.1", "junos"), transport="junos", mode="edit-cmd",
        show_cmd=None, edit_cmd="set a b", config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=False, commit_confirmed=None, save_dir=None, quiet=True, comment="C1 cutover")
    assert v.edit_calls[0]["comment"] == "C1 cutover"
    v = FakeVendor()
    monkeypatch.setitem(vendors.VENDORS, "telnet-junos", v)
    _, ok, out, _ = runner.run_for_target(
        t=Target("R1", "10.0.0.1", "telnet-junos"), transport="telnet-junos", mode="edit-cmd",
        show_cmd=None, edit_cmd="set a b", config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=False, commit_confirmed=None, save_dir=None, quiet=True, comment="x")
    assert not ok and "--comment is not supported" in out and v.edit_calls == []


def test_commit_status_mode_returns_json(monkeypatch):
    class V(FakeVendor):
        def commit_status(self, host, user, passwd, st, ct, port=None, vendor_hint=None):
            return [{"seq": 0, "user": "h-lab", "pending_rollback_minutes": 5}]
    monkeypatch.setitem(vendors.VENDORS, "junos", V())
    name, ok, out, _ = runner.run_for_target(
        t=Target("R1", "10.0.0.1", "junos"), transport="junos", mode="commit-status",
        show_cmd=None, edit_cmd=None, config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=False, commit_confirmed=None, save_dir=None, quiet=True)
    import json as _json
    assert ok and _json.loads(out.splitlines()[-1]) == [{"seq": 0, "user": "h-lab", "pending_rollback_minutes": 5}]
    monkeypatch.setitem(vendors.VENDORS, "ssh", FakeVendor())
    _, ok, out, _ = runner.run_for_target(
        t=Target("R1", "10.0.0.1", "ssh"), transport="ssh", mode="commit-status",
        show_cmd=None, edit_cmd=None, config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=False, commit_confirmed=None, save_dir=None, quiet=True)
    assert not ok and "not supported" in out


# --- #39 ------------------------------------------------------------------------

def test_commit_with_a_semicolon_is_a_confirm_too(monkeypatch):
    """The README lists `commit;` as a confirm form; it was loaded as config."""
    v = FakeVendor(with_confirm=True)
    _, ok, out, _ = run(monkeypatch, "junos", v, edit_cmd="commit;")
    assert ok and v.confirm_calls == ["10.0.0.1"] and v.edit_calls == []


def test_commit_status_dry_run_opens_no_session(monkeypatch):
    class Mod:
        AVAILABLE = True
        calls = []

        @staticmethod
        def commit_status(*a, **kw):
            Mod.calls.append(a)
            return [{"seq": 0}]

    monkeypatch.setitem(vendors.VENDORS, "junos", Mod)
    name, ok, out, _ = runner.run_for_target(
        t=Target("R1", "10.0.0.1", "junos"), transport="junos", mode="commit-status",
        show_cmd=None, edit_cmd=None, config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=True, commit_confirmed=None, save_dir=None, quiet=True, max_attempts=1)
    assert ok and Mod.calls == [] and "DRY-RUN" in out and out.strip().splitlines()[-1] == "[]"


def test_progress_lines_are_written_in_one_piece(monkeypatch):
    """print() writes the text and the newline separately, so two worker
    threads interleave; _say writes the line once."""
    writes = []
    monkeypatch.setattr(runner.sys, "stdout", type("S", (), {"write": lambda self, t: writes.append(t),
                                                               "flush": lambda self: None})())
    runner._say("R1               STARTED")
    assert len(writes) == 1 and writes[0].endswith("R1               STARTED\n") and writes[0].startswith("[")

def test_runner_refuses_a_timer_it_cannot_arm_before_the_driver(monkeypatch):
    v = FakeVendor()
    _, ok, out, _ = run(monkeypatch, "junos", v, commit_confirmed=0)
    assert not ok and "commit_confirmed must be 1..65535" in out and v.edit_calls == []
    r = RollbackVendor()
    _, ok, out, _ = run_rollback(monkeypatch, "junos", r, n=1, commit_confirmed=-1)
    assert not ok and "commit_confirmed must be 1..65535" in out and r.rollback_calls == []
