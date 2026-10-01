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

    def commit(self, confirm=None, timeout=None):
        self._do("commit", confirm=confirm)

    def rollback(self):
        self._do("rollback")

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
    FakeDevice.open_error = junos.ConnectError("boom")
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
    FakeConfig.raise_on = {"commit": junos.RpcTimeoutError("timed out")}
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
    FakeConfig.raise_on = {"commit": junos.RpcTimeoutError("t")}
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
