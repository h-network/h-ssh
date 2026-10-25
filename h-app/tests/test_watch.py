"""--every SECONDS: the same reads again and again, every tick a run in the
store, and per tick one line plus what changed since the tick before."""

import os
import re
import sqlite3
import sys
import types

import pytest

from hssh import cli, drivers


def run_watch(monkeypatch, capsys, argv, fake, sleeps=None):
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", fake)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER", "HSSH_STORE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    slept = []
    monkeypatch.setattr(cli, "_watch_sleep", sleeps or (lambda s: slept.append(s)))
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", *argv])
    with pytest.raises(SystemExit) as e:
        cli.main_sync()
    out, err = capsys.readouterr()
    return e.value.code, out, err, slept


def changing_fake():
    calls = {}

    def show(host, user, passwd, cmd, *a, **kw):
        n = calls[host] = calls.get(host, 0) + 1
        if host == "10.0.0.2" and n == 2:
            return "peer 10.9.9.9 Establ\npeer 10.9.9.8 Active\n"         # one peer dropped on tick 2
        return "peer 10.9.9.9 Establ\npeer 10.9.9.8 Establ\n"

    return types.SimpleNamespace(AVAILABLE=True, show=show), calls


def test_three_ticks_each_a_run_and_only_the_change_is_printed(tmp_path, monkeypatch, capsys):
    fake, calls = changing_fake()
    db = tmp_path / "w.db"
    rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(db), "--every", "30", "--times", "3",
                                                          "R1:10.0.0.1:junos", "R2:10.0.0.2:junos", "-sC", "show bgp summary"], fake)
    assert rc == 0, err
    assert calls == {"10.0.0.1": 3, "10.0.0.2": 3} and slept == [30.0, 30.0]      # 3 ticks, 2 pauses between them
    con = sqlite3.connect(db)
    assert con.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 3
    assert con.execute("SELECT COUNT(*) FROM results").fetchone()[0] == 6
    lines = out.splitlines()
    ticks = [ln for ln in lines if ln.startswith("tick ")]
    assert len(ticks) == 3
    assert ticks[0].startswith("tick 1 ") and "2 OK, 0 failed; baseline kept as run " in ticks[0]
    assert ticks[1].startswith("tick 2 ") and ticks[1].endswith("2 OK, 0 failed, 1 changed")
    assert ticks[2].startswith("tick 3 ") and ticks[2].endswith("2 OK, 0 failed, 1 changed")   # back to Establ: a change again
    assert "--- R2: show bgp summary" in out and "R1:" not in out
    assert "  -peer 10.9.9.8 Establ" in out and "  +peer 10.9.9.8 Active" in out
    assert "STARTED" not in out and "Done." not in out and "Targets:" not in out    # no per-device chatter per tick
    assert not re.search(r"R\d\s+OK$", out, re.M)                                      # nor a verdict line per device
    assert err.count("[h-ssh] {") == 3                                                # the summary line, once per tick


def test_a_tick_that_fails_a_device_says_so_in_the_change(tmp_path, monkeypatch, capsys):
    calls = {}

    def show(host, user, passwd, cmd, *a, **kw):
        n = calls[host] = calls.get(host, 0) + 1
        if n == 2:
            raise RuntimeError("connect timed out")
        return "up\n"

    fake = types.SimpleNamespace(AVAILABLE=True, show=show)
    rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", "5", "--times", "2",
                                                          "--retries", "0", "R1:10.0.0.1:junos", "-sC", "show version"], fake)
    assert rc == 1
    assert "tick 2 " in out and "0 OK, 1 failed, 1 changed" in out and "--- R1: show version: OK -> FAIL (" in out


def test_ctrl_c_between_ticks_stops_the_watch_and_says_how_many_are_kept(tmp_path, monkeypatch, capsys):
    fake, calls = changing_fake()

    def interrupt(seconds):
        raise KeyboardInterrupt

    rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", "60",
                                                          "R1:10.0.0.1:junos", "-sC", "show version"], fake, sleeps=interrupt)
    assert rc == 130 and "Interrupted. 1 tick(s) kept in the store." in err and calls == {"10.0.0.1": 1}


def test_the_watch_refuses_what_it_cannot_watch(tmp_path, monkeypatch, capsys):
    fake, _ = changing_fake()
    rc, out, err, _ = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--times", "2", "R1:10.0.0.1:junos", "-sC", "show version"], fake)
    assert rc == 2 and "--times goes with --every" in err
    rc, out, err, _ = run_watch(monkeypatch, capsys, ["--no-store", "--every", "5", "R1:10.0.0.1:junos", "-sC", "show version"], fake)
    assert rc == 2 and "drop --no-store" in err
    rc, out, err, _ = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", "5", "-y", "R1:10.0.0.1:junos", "-eC", "set system host-name x"], fake)
    assert rc == 2 and "watches reads" in err
    rc, out, err, _ = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", "0.5", "R1:10.0.0.1:junos", "-sC", "show version"], fake)
    assert rc == 2 and "1 second or more" in err
