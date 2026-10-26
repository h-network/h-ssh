"""--every SECONDS: the same reads again and again, every tick a run in the
store, and per tick one line plus what changed since the tick before."""

import os
import pty
import re
import select
import sqlite3
import subprocess
import sys
import time
import types

import pytest

from hssh import cli, drivers
from hssh.store import Store


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


PROMPT = b"Password (press Enter to skip):"


def test_a_terminal_is_asked_for_the_password_once_for_the_whole_watch(tmp_path):
    """main() runs per tick and prompted whenever stdin is a terminal, so at
    a terminal with HSSH_PASSWORD unset the README's own example sat at the
    prompt after every sleep. A real pty, three ticks, one prompt, and what
    was typed there reaches every tick."""
    db = tmp_path / "w.db"
    script = tmp_path / "watch.py"
    script.write_text(
        "import sys, types\n"
        "from hssh import cli, drivers\n"
        "drivers.MODULES['junos@netconf'] = types.SimpleNamespace(\n"
        "    AVAILABLE=True, show=lambda host, user, passwd, cmd, *a, **kw: f'passwd={passwd}\\n')\n"
        "cli._watch_sleep = lambda seconds: None\n"
        f"sys.argv = ['h-ssh', '--config', {os.devnull!r}, '--user', 'u', '--store', {str(db)!r}, '--every', '5',\n"
        "            '--times', '3', 'R1:10.0.0.1:junos', '-sC', 'show version']\n"
        "cli.main_sync()\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("HSSH_")}
    env["PYTHONPATH"] = os.path.dirname(os.path.dirname(cli.__file__))
    master, slave = pty.openpty()
    proc = subprocess.Popen([sys.executable, str(script)], env=env, stdin=slave, stdout=slave, stderr=slave,
                            start_new_session=True)       # its own session: the prompt cannot reach our terminal
    os.close(slave)
    seen, answered = b"", 0
    deadline = time.monotonic() + 120
    try:
        while time.monotonic() < deadline:
            if not select.select([master], [], [], 1.0)[0]:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError:                                # the child closed its end
                break
            if not chunk:
                break
            seen += chunk
            if seen.count(PROMPT) > answered:              # answer every prompt, then count them
                os.write(master, b"s3cret\n")
                answered += 1
        else:
            proc.kill()
            pytest.fail(f"the watch did not end in time; so far: {seen!r}")
    finally:
        os.close(master)
        rc = proc.wait(60)
    text = seen.decode(errors="replace")
    assert rc == 0, text
    assert text.count("Password (press Enter to skip):") == 1, text
    assert len(re.findall(r"^tick \d ", text, re.M)) == 3, text
    con = sqlite3.connect(db)
    assert [r[0] for r in con.execute("SELECT output FROM results")] == ["passwd=s3cret"] * 3


def test_the_exit_code_is_the_worst_tick_not_the_last(tmp_path, monkeypatch, capsys):
    """A device that failed on tick 1 and answered from tick 2 on exited 0:
    main_sync() kept the last tick's code. The watch exits with its worst."""
    calls = {}

    def show(host, user, passwd, cmd, *a, **kw):
        n = calls[host] = calls.get(host, 0) + 1
        if n == 1:
            raise RuntimeError("connect timed out")
        return "up\n"

    fake = types.SimpleNamespace(AVAILABLE=True, show=show)
    rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", "5", "--times", "3",
                                                          "--retries", "0", "R1:10.0.0.1:junos", "-sC", "show version"], fake)
    assert rc == 1 and calls == {"10.0.0.1": 3} and slept == [5.0, 5.0]
    ticks = [ln for ln in out.splitlines() if ln.startswith("tick ")]
    assert "0 OK, 1 failed" in ticks[0] and ticks[2].endswith("1 OK, 0 failed, 0 changed")


def test_a_baseline_the_store_lost_is_said_and_the_watch_exits_4(tmp_path, monkeypatch, capsys):
    """Results not kept on tick 1 only: the tick line said `baseline kept as
    run ...` and a clean tick 2 made the exit 0. The line now says what was
    lost, in the warning's words, and the 4 is kept to the end."""
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda host, user, passwd, cmd, *a, **kw: "up\n")
    real, tries = Store.add_entry, []

    def failing(self, *a, **kw):
        tries.append(1)
        if len(tries) == 1:
            raise sqlite3.OperationalError("database or disk is full")
        return real(self, *a, **kw)

    monkeypatch.setattr(Store, "add_entry", failing)
    rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", "5", "--times", "2",
                                                          "--workers", "1", "R1:10.0.0.1:junos", "R2:10.0.0.2:junos",
                                                          "-sC", "show version"], fake)
    assert rc == 4, err
    ticks = [ln for ln in out.splitlines() if ln.startswith("tick ")]
    assert ticks[0].endswith("2 OK, 0 failed; baseline not kept (1 of 2 results were not kept: database or disk is full)")
    assert "baseline kept" not in out
    assert ticks[1].endswith("2 OK, 0 failed, 1 changed") and out.count(": show version: new") == 1   # the lost one is new to the store
    assert err.count("1 of 2 results were not kept: database or disk is full") == 1                 # tick 2 kept everything


def test_json_and_raw_are_refused_with_every_before_anything_runs(tmp_path, monkeypatch, capsys):
    """The tick lines and the diffs went to stdout after the JSON array or
    the raw device output: `--json --every | jq` failed at the first tick.
    Neither is a watch's output, so both are refused: exit 2, nothing sent."""
    fake, calls = changing_fake()
    for flag in ("--json", "--raw"):
        rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", "5", "--times", "1",
                                                              flag, "R1:10.0.0.1:junos", "-sC", "show version"], fake)
        assert rc == 2 and "--every prints one line per tick and what changed, not --json or --raw output" in err, err
        assert out == "" and calls == {} and slept == [] and "Traceback" not in err


def test_every_takes_at_most_a_day_like_the_timeouts(tmp_path, monkeypatch, capsys):
    """`--every inf` passed the floor, tick 1 ran, and time.sleep(inf) was a
    traceback. The same ceiling as --session-timeout and --command-timeout."""
    fake, calls = changing_fake()
    for value in ("inf", "1e300", "86400.5"):
        rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", value, "--times", "1",
                                                              "R1:10.0.0.1:junos", "-sC", "show version"], fake)
        assert rc == 2 and f"--every takes at most 86400 seconds (a day), not {value}" in err and calls == {}, err
    assert cli._seconds_arg("86400") == 86400.0 and cli._seconds_arg("1.5") == 1.5
