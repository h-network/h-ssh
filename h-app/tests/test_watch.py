"""--every SECONDS: the same reads again and again, every tick a run in the
store, and per tick one line plus what changed since the tick before."""

import contextlib
import json
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
    with contextlib.closing(sqlite3.connect(db)) as con:
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


def test_a_change_shown_on_a_terminal_carries_no_control_sequence(tmp_path, monkeypatch, capsys):
    """A watch's diff is device output on the operator's terminal: a reply
    cannot clear or retitle it there (#47)."""
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    calls = {}

    def show(host, user, passwd, cmd, *a, **kw):
        n = calls[host] = calls.get(host, 0) + 1
        return "peer 10.9.9.8 Establ\n" if n == 1 else "peer 10.9.9.8 Active\x1b]0;owned\x07\x1b[2J\n"

    rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", "5", "--times", "2",
                                                          "R1:10.0.0.1:junos", "-sC", "show bgp summary"],
                                    types.SimpleNamespace(AVAILABLE=True, show=show))
    assert rc == 0, err
    assert "  +peer 10.9.9.8 Active" in out and "\x1b" not in out and "\x07" not in out, repr(out)


def test_ctrl_c_between_ticks_stops_the_watch_and_says_how_many_are_kept(tmp_path, monkeypatch, capsys):
    fake, calls = changing_fake()

    def interrupt(seconds):
        raise KeyboardInterrupt

    rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", "60",
                                                          "R1:10.0.0.1:junos", "-sC", "show version"], fake, sleeps=interrupt)
    assert rc == 130 and "Interrupted. 1 tick(s) kept in the store." in err and calls == {"10.0.0.1": 1}

    # A tick whose result the store lost is not counted as kept: tick 1 loses
    # it, tick 2 keeps it, Ctrl-C in the second sleep.
    real, sleeps = Store.add_entry, []

    def lose_tick_1(self, *a, **kw):
        if not sleeps:
            raise sqlite3.OperationalError("database or disk is full")
        return real(self, *a, **kw)

    def interrupt_the_second(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(Store, "add_entry", lose_tick_1)
    rc, out, err, _ = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w2.db"), "--every", "60",
                                                      "R1:10.0.0.1:junos", "-sC", "show version"], fake, sleeps=interrupt_the_second)
    assert rc == 130 and "Interrupted. 1 tick(s) kept in the store, 1 not kept in full." in err, err


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
    assert not (tmp_path / "w.db").exists()                 # refused before the store is opened: none is made


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
        "            '--times', '3', '--no-probe', 'R1:10.0.0.1:junos', '-sC', 'show version']\n"
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
    with contextlib.closing(sqlite3.connect(db)) as con:
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


def test_tick_exit_codes_rank_as_the_readme_says():
    """README: `130` > `4` > `2` > `1` > `3` > `0`. Only where 2 goes was
    pinned: 3 over 1 (a safety-gate skip on tick 1 outranking a device that
    failed on tick 2) or 4 over 130 passed every test."""
    order = (130, 4, 2, 1, 3, 0)
    for i, worse in enumerate(order):
        for better in order[i:]:
            assert cli._worst(worse, better) == cli._worst(better, worse) == worse, (worse, better)


def test_a_baseline_the_store_lost_is_said_and_the_watch_exits_4(tmp_path, monkeypatch, capsys):
    """Results not kept on tick 1 only: the tick line said `baseline kept as
    run ...` and a clean tick 2 made the exit 0. The line now says what was
    lost, in the warning's words, and the 4 is kept to the end. The lost
    reply is compared on tick 2 as tick 1 got it, not called new."""
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
    assert ticks[1].endswith("2 OK, 0 failed, 0 changed") and ": new" not in out      # the lost one, as tick 1 got it
    assert err.count("1 of 2 results were not kept: database or disk is full") == 1                 # tick 2 kept everything


def test_json_and_raw_are_refused_with_every_before_anything_runs(tmp_path, monkeypatch, capsys):
    """The tick lines and the diffs went to stdout after the JSON array or
    the raw device output: `--json --every | jq` failed at the first tick.
    Neither is a watch's output, so both are refused: exit 2, nothing sent,
    no store made. The help says so with the other watch refusals."""
    fake, calls = changing_fake()
    db = tmp_path / "new" / "w.db"
    for flag in ("--json", "--raw"):
        rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(db), "--every", "5", "--times", "1",
                                                              flag, "R1:10.0.0.1:junos", "-sC", "show version"], fake)
        assert rc == 2 and "--every prints one line per tick and what changed, not --json or --raw output" in err, err
        assert out == "" and calls == {} and slept == [] and "Traceback" not in err
        assert not db.parent.exists()                       # neither the store nor its directory
    rc, out, err, _ = run_watch(monkeypatch, capsys, ["--help"], fake)
    assert rc == 0 and "(reads only, the store on, not with --json or --raw; 1 to 86400 s)" in " ".join(out.split())


def test_every_takes_at_most_a_day_like_the_timeouts(tmp_path, monkeypatch, capsys):
    """`--every inf` passed the floor, tick 1 ran, and time.sleep(inf) was a
    traceback. The same ceiling as --session-timeout and --command-timeout."""
    fake, calls = changing_fake()
    for value in ("inf", "1e300", "86400.5"):
        rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", value, "--times", "1",
                                                              "R1:10.0.0.1:junos", "-sC", "show version"], fake)
        assert rc == 2 and f"--every takes at most 86400 seconds (a day), not {value}" in err and calls == {}, err
    assert cli._seconds_arg("86400") == 86400.0 and cli._seconds_arg("1.5") == 1.5


def test_a_reply_the_store_lost_on_a_later_tick_is_still_compared_and_the_line_says_so(tmp_path, monkeypatch, capsys):
    """Results the store did not keep after tick 1 were left out of the
    change report: R1 changed on tick 2, the line said `0 changed` and
    nothing of the loss, and tick 3 called R1 `new` with no diff. The
    replies are compared as the ticks got them, kept or not, and every
    tick's line says what the store did not keep."""
    calls = {}

    def show(host, user, passwd, cmd, *a, **kw):
        n = calls[host] = calls.get(host, 0) + 1
        return "peer 10.9.9.8 Active\n" if host == "10.0.0.1" and n > 1 else "peer 10.9.9.8 Establ\n"   # R1 drops on tick 2

    real = Store.add_entry

    def full_on_tick_2(self, run_id, entry, *a, **kw):
        if calls[entry["host"]] == 2:              # neither reply of tick 2 is kept: R1's changed, R2's did not
            raise sqlite3.OperationalError("database or disk is full")
        return real(self, run_id, entry, *a, **kw)

    monkeypatch.setattr(Store, "add_entry", full_on_tick_2)
    fake = types.SimpleNamespace(AVAILABLE=True, show=show)
    rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", "5", "--times", "3",
                                                          "R1:10.0.0.1:junos", "R2:10.0.0.2:junos", "-sC", "show version"], fake)
    assert rc == 4, err
    ticks = [ln for ln in out.splitlines() if ln.startswith("tick ")]
    assert ticks[1].endswith("2 OK, 0 failed, 1 changed; 2 of 2 results were not kept: database or disk is full"), out
    assert "--- R1: show version" in out and "  -peer 10.9.9.8 Establ" in out and "  +peer 10.9.9.8 Active" in out
    assert ticks[2].endswith("2 OK, 0 failed, 0 changed"), out      # against tick 2 as it was got, not `new`
    assert ": new" not in out and "--- R2" not in out


def test_a_result_the_store_lost_is_compared_in_the_rows_the_store_keeps(tmp_path):
    """A result the store could not keep is compared in rows _watch_rows
    shapes as Store.add_entry shapes the ones it keeps. Only a text show was
    checked: a --format json reply left as data made the next diff a
    traceback, a batch numbered from 1 called every command new, and every
    test passed. Each kind of result a watch reads gives the same rows both
    ways."""
    store = Store(str(tmp_path / "w.db"))
    r1 = {"device": "R1", "host": "10.0.0.1", "vendor": "junos", "ok": True, "duration_ms": 12}
    batch = json.dumps(["show version", "show chassis alarms"])
    kinds = {
        "show": ({**r1, "command": "show version", "output": "Junos: 24.2R1\n"}, "show version", "text"),
        "show --format json": ({**r1, "command": "show version",
                                "output": {"software-information": [{"junos-version": [{"data": "24.2R1"}]}]}},
                               "show version", "json"),
        "a show that failed": ({**r1, "ok": False, "error": "connect timed out"}, "show version", "text"),
        "batch": ({**r1, "ok": False, "error": "syntax error",
                   "commands": [{"command": "show version", "ok": True, "output": "Junos: 24.2R1"},
                                {"command": "show chassis alarms", "ok": False, "error": "syntax error"}]}, batch, "text"),
        "batch --format json": ({**r1, "commands": [{"command": "show version", "ok": True, "output": {"software-information": []}},
                                                    {"command": "show chassis alarms", "ok": True,
                                                     "output": {"alarm-information": []}}]}, batch, "json"),
        "a batch that never got a reply": ({**r1, "ok": False, "commands": [], "error": "connect timed out"}, batch, "text"),
    }
    fields = ("device", "seq", "command", "ok", "error", "output")
    for kind, (entry, sent, fmt) in kinds.items():
        run = store.begin_run("show", ["h-ssh"], "u", 1, "0")
        store.add_entry(run, entry, sent, fmt=fmt)
        kept = [tuple(r[f] for f in fields) for r in store.results(run_id=run)]
        assert [tuple(r[f] for f in fields) for r in cli._watch_rows(entry, sent)] == kept, kind
    store.close()


def watch_and_delete_the_store_after_tick_1(db, monkeypatch, capsys, fail=False, lose=False):
    """Three ticks of R1 asked for; in the sleep after tick 1 the store file
    goes, with its -wal and -shm. `fail`: R1 fails on tick 1; `lose`: the
    store does not keep R1's tick-1 result."""
    calls, gaps = {}, []

    def show(host, user, passwd, cmd, *a, **kw):
        n = calls[host] = calls.get(host, 0) + 1
        if fail and n == 1:
            raise RuntimeError("connect timed out")
        return "up\n"

    real = Store.add_entry

    def add_entry(self, run_id, entry, *a, **kw):
        if lose and calls[entry["host"]] == 1:
            raise sqlite3.OperationalError("database or disk is full")
        return real(self, run_id, entry, *a, **kw)

    def delete_the_store(seconds):
        gaps.append(seconds)
        for path in (db, db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")):
            path.unlink(missing_ok=True)

    with monkeypatch.context() as m:
        m.setattr(Store, "add_entry", add_entry)
        rc, out, err, _ = run_watch(monkeypatch, capsys, ["--store", str(db), "--every", "5", "--times", "3", "--retries", "0",
                                                          "R1:10.0.0.1:junos", "-sC", "show version"],
                                    types.SimpleNamespace(AVAILABLE=True, show=show), sleeps=delete_the_store)
    return rc, err, calls, gaps


def test_a_store_deleted_between_ticks_ends_the_watch_with_2_unless_a_tick_was_worse(tmp_path, monkeypatch, capsys):
    """The next tick made a deleted store again, empty, and the watch went
    on there with every device `new` and exit 0, while the README said a
    tick that cannot start ends the watch with 2. It does now, with nothing
    made again and no tick after it; and the worst code still wins: 2 over
    a device that failed on tick 1, a result lost on tick 1 (4) over the 2."""
    for name, fail, lose, want in (("clean", False, False, 2), ("failed", True, False, 2), ("lost", False, True, 4)):
        db = tmp_path / f"{name}.db"
        rc, err, calls, gaps = watch_and_delete_the_store_after_tick_1(db, monkeypatch, capsys, fail=fail, lose=lose)
        assert rc == want, (name, err)
        assert (f"ERROR: store {db}: the store file was deleted after tick 1; a watch keeps all its ticks in one store, "
                "so it stops here.") in err, err
        assert calls == {"10.0.0.1": 1} and gaps == [5.0] and not db.exists(), name   # no tick 2, no new empty store


def test_a_store_replaced_between_ticks_is_left_alone_and_ends_the_watch(tmp_path, monkeypatch, capsys):
    """Another file put where the store was is not the watch's store: the
    watch says so and stops, and the file is not touched."""
    db, other = tmp_path / "w.db", tmp_path / "other.db"
    other.write_bytes(b"")
    fake, calls = changing_fake()

    def replace_the_store(seconds):
        if other.exists():
            os.replace(other, db)

    rc, out, err, _ = run_watch(monkeypatch, capsys, ["--store", str(db), "--every", "5", "--times", "3",
                                                      "R1:10.0.0.1:junos", "-sC", "show version"], fake, sleeps=replace_the_store)
    assert rc == 2 and "the store file was replaced after tick 1" in err, err
    assert calls == {"10.0.0.1": 1} and db.read_bytes() == b""


def test_a_shortcut_is_resolved_once_for_the_whole_watch(tmp_path, monkeypatch, capsys):
    """`Resolved 'alarms' -> 'show chassis alarms' (junos)` went to stdout
    before every tick line. It is said once, before the first."""
    monkeypatch.setenv("HOME", str(tmp_path))          # the shipped shortcut, not one from ~/.h-ssh/commands
    fake, calls = changing_fake()
    rc, out, err, slept = run_watch(monkeypatch, capsys, ["--store", str(tmp_path / "w.db"), "--every", "5", "--times", "3",
                                                          "R1:10.0.0.1:junos", "-sC", "alarms"], fake)
    assert rc == 0, err
    lines = out.splitlines()
    assert lines[0] == "Resolved 'alarms' -> 'show chassis alarms' (junos)" and out.count("Resolved ") == 1, out
    assert len([ln for ln in lines if ln.startswith("tick ")]) == 3
