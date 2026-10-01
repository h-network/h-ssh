"""Runner policy for edits: dry-run, commit-confirmed, retry, and confirm."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import runner, vendors
from hssh.core import Target
from hssh.errors import AmbiguousCommitError, NotAppliedError


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
        dry_run=False, commit_confirmed=None, config_dir=None, attempts=3):
    monkeypatch.setitem(vendors.VENDORS, vendor_name, mod)
    return runner.run_for_target(
        t=Target("R1", "10.0.0.1", vendor_name), transport=vendor_name, mode=mode,
        show_cmd=None, edit_cmd=edit_cmd, config_dir=config_dir, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=dry_run, commit_confirmed=commit_confirmed, save_dir=None,
        quiet=True, max_attempts=attempts)


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
