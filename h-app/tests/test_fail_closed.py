"""#64: a run finds out before the first device that it cannot do its job —
an audit log or run log that cannot be written, a safety file that cannot
be kept, a device without its set file, a device listed twice or under two
names — instead of after the commits landed."""
import asyncio
import json
import os
import sys
import types
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, vendors
from hssh.audit import probe_append
from hssh.core import check_unique, Target
from hssh.safety import SafetyGate


async def _reachable(target, timeout=2):
    return (target.name, True, "reachable")


class Driver:
    AVAILABLE = True

    def __init__(self):
        self.calls = []

    def show(self, host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        self.calls.append(("show", host)); return "ok"

    def edit(self, host, user, passwd, payload, st, ct, commit_confirmed=None, port=None,
             dry_run=False, comment=None, expected_diff=None, vendor_hint=None):
        self.calls.append(("edit", host, payload.strip())); return "COMMIT OK\n"


def run(monkeypatch, capsys, argv):
    drv = Driver()
    monkeypatch.setitem(vendors.VENDORS, "junos", drv)
    monkeypatch.setitem(cli.VENDOR_MODULES, "junos", drv)
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--password", "p", "-y", *argv])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    return rc, out, err, drv


EDIT = ["--target", "R1:10.0.0.1:junos", "--target", "R2:10.0.0.2:junos", "-eC", "set system host-name x"]


# --- H2 / M4: files the run depends on ------------------------------------------

@pytest.mark.parametrize("flag", ["--audit-log", "--log"])
def test_an_unwritable_log_refuses_the_run_before_any_device(monkeypatch, capsys, tmp_path, flag):
    rc, out, err, drv = run(monkeypatch, capsys, [*EDIT, flag, "/proc/nope/x"])
    assert rc == 2 and drv.calls == []
    assert flag in err and "/proc/nope/x" in err and "refusing to start" in err


def test_a_log_that_is_a_fifo_or_symlink_is_refused(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(OSError, match="not a plain file that can be appended to|not a regular file"):
        probe_append(str(fifo))
    victim = tmp_path / "victim"
    victim.write_text("keep")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(victim)
    with pytest.raises(OSError):
        probe_append(str(link))
    assert victim.read_text() == "keep"


def test_a_writable_log_probe_creates_the_file_0600_and_writes_nothing(tmp_path):
    p = tmp_path / "logs" / "audit.jsonl"
    probe_append(str(p))
    assert p.is_file() and p.stat().st_size == 0 and oct(p.stat().st_mode & 0o777) == "0o600"


def test_an_unusable_safety_file_refuses_the_run(monkeypatch, capsys, tmp_path):
    rc, out, err, drv = run(monkeypatch, capsys, [*EDIT, "--safety-file", "/proc/nope/x"])
    assert rc == 2 and drv.calls == []
    assert "--safety-file requested but unusable" in err and "refusing to start" in err
    inside_a_file = tmp_path / "afile"
    inside_a_file.write_text("x")
    rc, out, err, drv = run(monkeypatch, capsys, [*EDIT, "--safety-file", str(inside_a_file / "gate.json")])
    assert rc == 2 and drv.calls == []


def test_a_usable_safety_file_is_created_0600_and_the_run_proceeds(monkeypatch, capsys, tmp_path):
    sf = tmp_path / "gate" / "safety.json"
    rc, out, err, drv = run(monkeypatch, capsys, [*EDIT, "--safety-file", str(sf)])
    assert rc == 0 and len(drv.calls) == 2
    assert sf.exists() and oct(sf.stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "gate" / "safety.json.lock").stat().st_mode & 0o777) == "0o600"


def test_a_safety_file_locked_by_another_run_is_still_usable(tmp_path):
    import fcntl
    sf = tmp_path / "safety.json"
    lock = open(tmp_path / "safety.json.lock", "w")
    fcntl.flock(lock, fcntl.LOCK_EX)
    SafetyGate(safety_file=str(sf))          # the lock works; someone else holds it


# --- M1: -eD and the device without a set file --------------------------------

def test_edit_dir_with_a_missing_set_file_refuses_the_whole_run(monkeypatch, capsys, tmp_path):
    d = tmp_path / "cfg"
    d.mkdir()
    (d / "R1.set").write_text("set system host-name R1\n")
    rc, out, err, drv = run(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "--target", "R2:10.0.0.2:junos", "-eD", str(d)])
    assert rc == 2 and drv.calls == []
    assert "no <NAME>.set for 1 of 2 device(s): R2" in err and "--allow-missing" in err


def test_allow_missing_skips_them_and_says_so(monkeypatch, capsys, tmp_path):
    d = tmp_path / "cfg"
    d.mkdir()
    (d / "R1.set").write_text("set system host-name R1\n")
    rc, out, err, drv = run(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "--target", "R2:10.0.0.2:junos",
                                                 "-eD", str(d), "--allow-missing"])
    assert rc == 3, err
    assert drv.calls == [("edit", "10.0.0.1", "set system host-name R1")]
    assert "Skipping 1 device(s) without a set file: R2" in err
    assert "Done. OK: 1, skipped for want of a set file: 1" in out
    summary = json.loads(err.split("[h-ssh] ", 1)[1].splitlines()[0])
    assert summary == {**summary, "targets": 2, "ok": 1, "fail": 0, "skipped": 1}


def test_allow_missing_with_no_set_file_at_all_is_nothing_to_do(monkeypatch, capsys, tmp_path):
    d = tmp_path / "cfg"
    d.mkdir()
    rc, out, err, drv = run(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-eD", str(d), "--allow-missing"])
    assert rc == 2 and drv.calls == [] and "nothing to do" in err


# --- M3: one name, one device -------------------------------------------------

def T(name, host, port=None):
    return Target(name=name, host=host, vendor="junos", port=port)


def test_check_unique_names_the_duplicate():
    with pytest.raises(ValueError, match="device 'R1' \\(10.0.0.1\\) is listed twice"):
        check_unique([T("R1", "10.0.0.1"), T("R1", "10.0.0.1")])
    with pytest.raises(ValueError, match="device name 'R1' is used for two hosts: 10.0.0.1 and 10.0.0.2"):
        check_unique([T("R1", "10.0.0.1"), T("R1", "10.0.0.2")])
    with pytest.raises(ValueError, match="host 10.0.0.1 is listed under two names: 'R1' and 'R1b'"):
        check_unique([T("R1", "10.0.0.1"), T("R1b", "10.0.0.1")])
    check_unique([T("R1", "10.0.0.1", 830), T("R1x", "10.0.0.1", 22)])     # two ports: two devices
    check_unique([T("R1", "10.0.0.1"), T("R1", "10.0.0.1")], allow_repeats=True)
    with pytest.raises(ValueError, match="used for two hosts"):
        check_unique([T("R1", "10.0.0.1"), T("R1", "10.0.0.2")], allow_repeats=True)


def test_duplicates_in_an_inventory_and_inline_targets_are_refused(monkeypatch, capsys, tmp_path):
    f = tmp_path / "d.csv"
    f.write_text("R1,10.0.0.1,junos\nR1,10.0.0.1,junos\n")
    rc, out, err, drv = run(monkeypatch, capsys, ["--devices", str(f), "-sC", "show version"])
    assert rc == 2 and drv.calls == [] and str(f) in err and "listed twice" in err
    f.write_text("R1,10.0.0.1,junos\nR1,10.0.0.2,junos\n")
    rc, out, err, drv = run(monkeypatch, capsys, ["--devices", str(f), "-sC", "show version"])
    assert rc == 2 and "used for two hosts" in err
    rc, out, err, drv = run(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "--target", "R2:10.0.0.1:junos", "-sC", "show version"])
    assert rc == 2 and "inline targets" in err and "under two names" in err


def test_a_job_may_repeat_a_device_but_not_contradict_it(monkeypatch, capsys, tmp_path):
    job = tmp_path / "job.json"
    job.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "show": "show version"},
                               {"target": "R1:10.0.0.1:junos", "show": "show version"}]))
    rc, out, err, drv = run(monkeypatch, capsys, ["--job", str(job)])
    assert rc == 0 and len(drv.calls) == 2
    job.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "show": "show version"},
                               {"target": "R1:10.0.0.2:junos", "show": "show version"}]))
    rc, out, err, drv = run(monkeypatch, capsys, ["--job", str(job)])
    assert rc == 2 and drv.calls == [] and "job file" in err and "used for two hosts" in err
