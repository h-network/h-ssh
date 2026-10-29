"""The result store (--store, h-ssh-store): every command's reply in one
SQLite file, byte for byte, read back by run, device and command."""

import asyncio
import builtins
import json
import os
import sqlite3
import stat
import sys
import threading
import time
import types

import pytest

from hssh import cli, drivers
from hssh import store as store_module
from hssh.store import Store, StoreError, main as store_main, new_run_id

SHOW = {"device": "r1", "host": "10.0.0.1", "vendor": "junos@ssh", "ok": True, "duration_ms": 120,
        "command": "show version", "output": "Hostname: r1\nJunos: 23.2\nencrypted-password \"$9$abcDEF\"\n"}
FAILED = {"device": "r2", "host": "10.0.0.2", "vendor": "junos@ssh", "ok": False, "duration_ms": 5000,
          "error": "ERROR: connect timed out"}
BATCH = {"device": "r1", "host": "10.0.0.1", "vendor": "junos@netconf", "ok": False, "duration_ms": 300,
         "commands": [{"command": "show version", "ok": True, "output": "Hostname: r1\nJunos: 23.3\n"},
                      {"command": "show system uptime", "ok": False, "error": "refused by the device: error: no"}]}
COMMITS = {"device": "r1", "host": "10.0.0.1", "vendor": "junos@netconf", "ok": True, "duration_ms": 50,
           "commits": [{"seq": 0, "user": "lab", "comment": None}]}


def filled(path):
    """Three runs: a show with one failure, a batch, a commit history."""
    s = Store(str(path))
    r1 = s.begin_run("show", ["--devices", "core.csv", "-sC", "version"], "lab", 2, "1.0.0", command="version")
    s.add_entry(r1, SHOW, "show version")
    s.add_entry(r1, FAILED, "show version")
    s.finish_run(r1, 1, 1, 0)
    r2 = s.begin_run("show-batch", ["--batch", "c.txt"], "lab", 1, "1.0.0", command="show version\nshow system uptime")
    s.add_entry(r2, BATCH, "")
    s.finish_run(r2, 0, 1, 0)
    r3 = s.begin_run("commit-status", ["--commit-status"], "lab", 1, "1.0.0", command="commit-status")
    s.add_entry(r3, COMMITS, "show system commit")
    s.finish_run(r3, 1, 0, 0)
    s.close()
    return r1, r2, r3


def rows(path, sql, *params):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in c.execute(sql, params).fetchall()]
    finally:
        c.close()


# --- the writer ------------------------------------------------------------------

def test_the_store_is_a_private_file_with_the_two_tables(tmp_path):
    path = tmp_path / "deep" / "runs.db"
    Store(str(path)).close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    names = {r["name"] for r in rows(path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"runs", "results"} <= names


def test_the_directories_made_for_a_store_are_private_whatever_the_umask(tmp_path):
    """The parents made for a store were the umask's, 0777 under umask 000
    (os.makedirs's mode is the last directory's alone, #149): each one
    made is 0700."""
    old = os.umask(0o000)
    try:
        path = tmp_path / "a" / "b" / "runs.db"
        Store(str(path)).close()
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [stat.S_IMODE(d.stat().st_mode) for d in (tmp_path / "a", tmp_path / "a" / "b")] == [0o700, 0o700]


def test_an_existing_store_file_is_made_private_and_another_users_is_refused(tmp_path, monkeypatch):
    """`touch h-ssh.db; chmod 644`, or the README's sqlite3.connect snippet
    run before the first run, left a 0644 store, and a run kept it so, its
    -wal and -shm with it, holding the replies; a store owned by another
    user, planted in a shared job directory, was opened and written (#149).
    An existing file is made 0600 at the open, a -wal left beside it too,
    and another user's file is refused before SQLite opens it."""
    path, wal, shm = tmp_path / "h-ssh.db", tmp_path / "h-ssh.db-wal", tmp_path / "h-ssh.db-shm"
    path.touch()
    path.chmod(0o644)
    wal.touch()
    wal.chmod(0o644)
    s = Store(str(path))
    r = s.begin_run("show", [], "lab", 1, "1.0.0", command="version")
    s.add_entry(r, SHOW, "show version")
    modes = [stat.S_IMODE(p.stat().st_mode) for p in (path, wal, shm)]
    s.close()
    assert modes == [0o600, 0o600, 0o600]
    uid = os.geteuid()
    monkeypatch.setattr(store_module, "_safe_dir", lambda path: None)   # the directory precondition apart (its own test)
    monkeypatch.setattr(os, "geteuid", lambda: uid + 1)
    with pytest.raises(StoreError, match=rf"h-ssh\.db: owned by another user \(uid {uid}\); a store is this user's own$"):
        Store(str(path))
    assert [r["device"] for r in rows(path, "SELECT device FROM results")] == ["r1"]


def test_a_store_in_a_directory_other_users_can_write_is_refused_unless_it_is_sticky(tmp_path, monkeypatch):
    """The swap/restore race (#149) needs another user able to rename
    entries in the store's directory; the precondition is closed by
    refusing such a directory. One group- or world-writable without the
    sticky bit is refused (nothing created); a sticky one (as /tmp, where
    others cannot rename a file they do not own) is fine, and so is a
    private one; a directory owned by another user is refused whoever may
    write it."""
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)                              # world-writable, no sticky
    with pytest.raises(StoreError, match=r"its directory .*/shared is writable by other users "
                                         r"\(mode 0777, no sticky bit\)"):
        Store(str(shared / "h-ssh.db"))
    assert not (shared / "h-ssh.db").exists()
    shared.chmod(0o1777)                             # sticky, as /tmp: others cannot rename our file
    Store(str(shared / "h-ssh.db")).close()
    assert (shared / "h-ssh.db").is_file()
    shared.chmod(0o700)
    uid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: uid + 1)
    with pytest.raises(StoreError, match=rf"its directory .*/shared is owned by another user \(uid {uid}\)"):
        Store(str(shared / "other.db"))
    assert not (shared / "other.db").exists()


def test_a_store_path_swapped_while_it_is_opened_is_refused(tmp_path, monkeypatch):
    """The descriptor that made the file private was closed before SQLite
    opened the path by name, which follows a symlink where that open did
    not (#149): one planted in between led SQLite into another file. The
    descriptor is held until SQLite has opened the path, which is then
    checked to lead to that file; or the store is not opened, and the file
    SQLite was led to is not written."""
    path, other = tmp_path / "h-ssh.db", tmp_path / "other.db"
    other.write_bytes(b"")
    real_connect = sqlite3.connect

    def planted(target, *a, **kw):
        if target == str(path):
            path.unlink()
            path.symlink_to(other)
        return real_connect(target, *a, **kw)
    monkeypatch.setattr(sqlite3, "connect", planted)
    with pytest.raises(StoreError, match="h-ssh.db: replaced while being opened"):
        Store(str(path))
    assert other.read_bytes() == b"" and path.is_symlink()


def test_a_symlink_in_place_of_the_store_is_refused(tmp_path):
    target = tmp_path / "elsewhere.db"
    target.write_text("")
    link = tmp_path / "runs.db"
    link.symlink_to(target)
    with pytest.raises(StoreError):
        Store(str(link))


def test_run_ids_sort_by_time_and_carry_four_hex_digits():
    import datetime
    a = new_run_id(datetime.datetime(2026, 10, 24, 17, 30, 55))
    b = new_run_id(datetime.datetime(2026, 10, 24, 17, 30, 56))
    assert a < b and a.startswith("20261024-173055-") and b.startswith("20261024-173056-")
    assert all(len(i) == len("20261024-173055-6dc0") and int(i[-4:], 16) >= 0 for i in (a, b))
    assert len({new_run_id()[-4:] for _ in range(5)}) > 1       # the suffix is random, not a clock


def test_two_runs_of_the_same_second_with_the_same_suffix_still_get_different_ids(tmp_path, monkeypatch):
    # Four hex digits collide once in 65536; a run must take another id
    # then, not fail. The suffix is pinned so the collision is certain.
    suffixes = iter(["6dc0", "6dc0", "6dc0", "9f12"])
    monkeypatch.setattr(store_module.secrets, "token_hex", lambda n=2: next(suffixes))
    store = Store(str(tmp_path / "runs.db"))
    first = store.begin_run("show", ["h-ssh"], "me", 1, "0")
    second = store.begin_run("show", ["h-ssh"], "me", 1, "0")
    assert first != second
    # The second run took the fresh suffix, unless the clock ticked between the two.
    assert second.endswith("-9f12") or second[:15] != first[:15]
    assert {r["run_id"] for r in store.runs()} == {first, second}
    # An id the caller chose is not replaced behind their back.
    with pytest.raises(sqlite3.IntegrityError):
        store.begin_run("show", ["h-ssh"], "me", 1, "0", run_id=first)
    store.close()


def test_one_row_per_command_kept_as_it_came(tmp_path):
    path = tmp_path / "runs.db"
    r1, r2, r3 = filled(path)
    runs = rows(path, "SELECT * FROM runs ORDER BY rowid")
    assert [r["mode"] for r in runs] == ["show", "show-batch", "commit-status"]
    assert runs[0]["argv"] == "--devices core.csv -sC version"     # as typed: a snapshot is not edited
    assert (runs[0]["targets"], runs[0]["ok"], runs[0]["failed"], runs[0]["skipped"]) == (2, 1, 1, 0)
    assert runs[0]["finished"] and runs[0]["command"] == "version"
    show = rows(path, "SELECT * FROM results WHERE run_id = ? ORDER BY device, seq", r1)
    assert [(r["device"], r["seq"], r["ok"]) for r in show] == [("r1", 0, 1), ("r2", 0, 0)]
    assert show[0]["command"] == "show version" and show[0]["format"] == "text"
    assert show[0]["output"] == SHOW["output"]                       # the hash stays: a restore needs it
    assert show[1]["output"] is None and show[1]["error"] == "ERROR: connect timed out"
    batch = rows(path, "SELECT * FROM results WHERE run_id = ? ORDER BY seq", r2)
    assert [(r["seq"], r["command"], r["ok"]) for r in batch] == \
        [(0, "show version", 1), (1, "show system uptime", 0)]
    assert batch[0]["duration_ms"] == 300 and batch[1]["duration_ms"] is None
    assert batch[1]["error"].startswith("refused by the device")
    commits = rows(path, "SELECT * FROM results WHERE run_id = ?", r3)
    assert commits[0]["format"] == "json" and json.loads(commits[0]["output"])[0]["user"] == "lab"
    assert commits[0]["command"] == "show system commit"


def test_a_json_reply_is_stored_as_json(tmp_path):
    path = tmp_path / "runs.db"
    s = Store(str(path))
    run = s.begin_run("show", ["-sC", "show version"], "lab", 1, "1.0.0")
    s.add_entry(run, {**SHOW, "device": "r9", "output": {"software-information": [{"host-name": [{"data": "r9"}]}]}},
                "show version", fmt="json")
    s.close()
    got = rows(path, "SELECT * FROM results")[0]
    assert got["format"] == "json" and json.loads(got["output"])["software-information"]


def test_a_second_result_for_the_same_command_replaces_the_first(tmp_path):
    path = tmp_path / "runs.db"
    s = Store(str(path))
    run = s.begin_run("show", [], "lab", 1, "1.0.0")
    s.add_entry(run, FAILED, "show version")
    s.add_entry(run, {**FAILED, "ok": True, "error": None, "output": "fine"}, "show version")
    s.close()
    got = rows(path, "SELECT * FROM results")
    assert len(got) == 1 and got[0]["ok"] == 1 and got[0]["output"] == "fine"


def test_a_run_is_found_by_its_id_or_a_unique_prefix_or_as_the_last(tmp_path):
    path = tmp_path / "runs.db"
    r1, r2, r3 = filled(path)
    s = Store(str(path), readonly=True)
    assert s.resolve_run(None) == r3
    assert s.resolve_run(r1) == r1
    assert s.resolve_run(r2[:-1]) == r2
    with pytest.raises(StoreError, match="matches 3 runs|matches 2 runs"):
        s.resolve_run(r1[:8])
    with pytest.raises(StoreError, match="no run"):
        s.resolve_run("nope")
    with pytest.raises(StoreError, match="no result for"):
        s.output(r1, "r9")
    s.close()
    with pytest.raises(StoreError, match="no store at"):
        Store(str(tmp_path / "missing.db"), readonly=True)


def writers_meet(monkeypatch, seconds=1.0):
    """Store._row made to wait inside its transaction, once, for a second
    writer to come in too; the list returned gets a name when two met
    there. One transaction at a time keeps it empty (the first waits out
    `seconds` and commits, the second only then gets in). Two writers
    inside one transaction meet whatever the scheduler does, on one CPU as
    on many."""
    meet, met = threading.Barrier(2, timeout=seconds), []
    real_row = Store._row

    def row(self, *a, **kw):
        try:
            meet.wait()
            met.append(threading.current_thread().name)
            meet.abort()                     # once is proof enough
        except threading.BrokenBarrierError:
            pass                             # nobody came in, or it is over
        return real_row(self, *a, **kw)
    monkeypatch.setattr(Store, "_row", row)
    return met


def test_two_threads_writing_one_store_keep_every_row(tmp_path, monkeypatch):
    """One Store written from two threads at once (two Fleets sharing it):
    one connection takes one transaction at a time, so a write waits for
    the other's commit instead of sharing its statement and losing rows."""
    path = tmp_path / "shared.db"
    st = Store(str(path))
    runs = [st.begin_run("show", ["t"], "u", 300, "0") for _ in range(2)]
    met = writers_meet(monkeypatch)
    errors = []

    def writer(run):
        try:
            for i in range(300):
                st.add_entry(run, {**SHOW, "device": f"d{i}", "output": "x" * 2000}, "show version")
            st.finish_run(run, 300, 0, 0)
        except Exception as e:                       # pragma: no cover - the failure we are testing against
            errors.append(f"{type(e).__name__}: {e}")

    threads = [threading.Thread(target=writer, args=(run,)) for run in runs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    st.close()
    assert met == []                                 # never two writers inside one transaction
    assert errors == []
    assert rows(path, "SELECT COUNT(*) AS n FROM results")[0]["n"] == 600
    assert all(r["finished"] for r in rows(path, "SELECT * FROM runs"))


# --- the reader --------------------------------------------------------------------

def reader(capsys, path, *argv):
    rc = store_main(["--store", str(path), *argv])
    out, err = capsys.readouterr()
    return rc, out, err


def test_runs_failed_and_output(tmp_path, capsys):
    path = tmp_path / "runs.db"
    r1, r2, r3 = filled(path)
    rc, out, _ = reader(capsys, path, "runs")
    lines = out.splitlines()
    assert rc == 0 and lines[0].startswith("run ") and [ln.split()[0] for ln in lines[1:]] == [r3, r2, r1]
    assert "2/1/1" in lines[3] and "commit-status" in lines[1]
    rc, out, _ = reader(capsys, path, "failed", r1)
    assert rc == 1 and f"run {r1}: 1 failed" in out and "r2" in out and "connect timed out" in out
    rc, out, _ = reader(capsys, path, "failed", r3)
    assert rc == 0 and "0 failed" in out
    rc, out, err = reader(capsys, path, "output", "r1", r1)
    assert rc == 0 and out == SHOW["output"]
    rc, out, err = reader(capsys, path, "output", "r2", r1)
    assert rc == 1 and out == "" and "connect timed out" in err
    rc, out, _ = reader(capsys, path, "output", "r1", r2, "--seq", "1")
    assert rc == 1
    rc, out, _ = reader(capsys, path, "output", "r1")          # the last run
    assert rc == 0 and json.loads(out)[0]["user"] == "lab"


def test_the_last_run_is_the_one_that_started_last_across_a_dst_fall_back(tmp_path, monkeypatch, capsys):
    """Europe/Amsterdam, 2026-10-25: 02:40 CEST comes thirty minutes before
    02:10 CET. Run ids and `started` are local time, so as strings the earlier
    run sorts last; the reader orders by the instant, which the stored offset
    gives it. The ids stay as they are."""
    real = store_module._now
    clock = ["2026-10-25T02:40:00+02:00", "2026-10-25T02:10:00+01:00"]
    monkeypatch.setattr(store_module, "_now", lambda: clock.pop(0) if clock else real())
    path = tmp_path / "runs.db"
    s = Store(str(path))
    summer = s.begin_run("show", ["a"], "u", 1, "0", run_id="20261025-024000-aaaa")
    winter = s.begin_run("show", ["b"], "u", 1, "0", run_id="20261025-021000-bbbb")   # the later run
    s.add(summer, "r1", 0, "show version", True, 1, None, "summer", ts="2026-10-25T02:40:01+02:00")
    s.add(winter, "r1", 0, "show version", True, 1, None, "winter", ts="2026-10-25T02:10:01+01:00")
    s.close()
    r = Store(str(path), readonly=True)
    assert r.last_run_id() == winter and r.resolve_run(None) == winter
    assert [x["run_id"] for x in r.runs()] == [winter, summer]
    r.close()
    rc, out, _ = reader(capsys, path, "runs")
    assert rc == 0 and [ln.split()[0] for ln in out.splitlines()[1:]] == [winter, summer]
    rc, out, _ = reader(capsys, path, "output", "r1")          # no run given: the last one
    assert rc == 0 and out == "winter\n"
    rc, out, _ = reader(capsys, path, "history", "r1")
    assert rc == 0 and [ln.split()[1] for ln in out.splitlines()[1:]] == [winter, summer]


def test_grep_field_diff_history_slowest(tmp_path, capsys):
    path = tmp_path / "runs.db"
    r1, r2, r3 = filled(path)
    rc, out, _ = reader(capsys, path, "grep", "junos:", "-i")
    assert rc == 0 and sorted(ln.split()[0] for ln in out.splitlines()) == sorted([r1, r2])
    assert "Junos: 23.2" in out and "Junos: 23.3" in out
    rc, out, _ = reader(capsys, path, "grep", "nothing-like-this")
    assert rc == 1 and out == ""
    rc, _, err = reader(capsys, path, "grep", "(")
    assert rc == 2 and "bad pattern" in err
    rc, out, _ = reader(capsys, path, "field", "0.user", "--run", r3)
    assert rc == 0 and out.strip().endswith("0.user = lab")
    rc, out, _ = reader(capsys, path, "field", "0.nothing")
    assert rc == 1
    rc, out, _ = reader(capsys, path, "diff", "r1", r1, r2)
    assert rc == 1 and "-Junos: 23.2" in out and "+Junos: 23.3" in out and out.startswith("--- r1 ")
    rc, out, _ = reader(capsys, path, "diff", "r1", r1, r1)
    assert rc == 0 and out == ""
    rc, out, _ = reader(capsys, path, "history", "r1")
    lines = out.splitlines()
    assert rc == 0 and len(lines) == 1 + 4 and "FAIL" in out and lines[1].split()[1] == r3
    rc, out, _ = reader(capsys, path, "history", "r1", "--command", "show version")
    assert rc == 0 and len(out.splitlines()) == 1 + 2
    rc, out, _ = reader(capsys, path, "slowest", "--last", "2")
    lines = out.splitlines()
    assert rc == 0 and lines[1].split()[:2] == ["5000", "r2"] and len(lines) == 3


@pytest.mark.parametrize("before, after", [
    ("Model: vmx\r\nJunos: x\r\n", "Model: vmx\nJunos: x"),
    ("Model: vmx\nJunos: x", "Model: vmx\nJunos: x\n"),
], ids=["crlf", "last-newline"])
def test_the_readers_diff_compares_lines_not_their_line_endings(tmp_path, capsys, before, after):
    """`h-ssh-store diff` compares the lines of two replies, not how they end:
    CRLF against LF, or a newline after the last line against none, is no
    difference (exit 0, nothing printed). h-ssh keeps a reply's own line
    endings in its rows (#111) and no newline after the last line; these
    come in through the Store API."""
    path = tmp_path / "runs.db"
    s = Store(str(path))
    runs = []
    for reply in (before, after):
        run = s.begin_run("show", ["-sC", "show version"], "lab", 1, "1.0.0", command="show version")
        s.add_entry(run, {**SHOW, "output": reply}, "show version")
        s.finish_run(run, 1, 0, 0)
        runs.append(run)
    s.close()
    rc, out, _ = reader(capsys, path, "diff", "r1", *runs)
    assert rc == 0 and out == ""


def test_export_csv_and_jsonl(tmp_path, capsys):
    """The rows as they are: CSV with a header (the batch's two commands are two
    rows, a failure keeps its error), JSON Lines with the same keys, --all for
    the whole store, --out to a file, filters, exit 1 when nothing matches."""
    import csv
    r1, r2, r3 = filled(tmp_path / "s.db")
    rc, out, err = reader(capsys, tmp_path / "s.db", "export", r1)
    assert rc == 0
    rows = list(csv.DictReader(out.splitlines()))
    assert [r["device"] for r in rows] == ["r1", "r2"] and rows[0]["output"].startswith("Hostname: r1")
    assert rows[1]["ok"] == "0" and rows[1]["error"] == "ERROR: connect timed out"
    assert list(rows[0]) == list(store_module.EXPORT_FIELDS)
    rc, out, err = reader(capsys, tmp_path / "s.db", "export", "--all", "--format", "jsonl")
    lines = [json.loads(ln) for ln in out.splitlines()]
    assert rc == 0 and len(lines) == 5 and {ln["run_id"] for ln in lines} == {r1, r2, r3}
    assert [ln["seq"] for ln in lines if ln["run_id"] == r2] == [0, 1]           # the batch: one row per command
    target = tmp_path / "rows.csv"
    rc, out, err = reader(capsys, tmp_path / "s.db", "export", "--all", "--device", "r1", "--out", str(target))
    assert rc == 0 and out == "" and "4 rows written to" in err
    assert len(list(csv.DictReader(target.read_text().splitlines()))) == 4     # r1: a show, two batch rows, a history
    rc, out, err = reader(capsys, tmp_path / "s.db", "export", "--all", "--device", "nobody")
    assert rc == 1 and out.strip() == ",".join(store_module.EXPORT_FIELDS)     # a header and nothing else


def test_the_reader_shows_a_terminal_no_escape_sequences_and_a_pipe_the_rows_as_kept(tmp_path, monkeypatch, capsys):
    """The rows are the replies as they came (#111), so `h-ssh-store output`
    on a terminal wrote a device's OSC retitle and clear-screen to it, which
    h-ssh itself never shows. On a terminal the reader takes out what the
    terminal would act on, wherever it prints a row's text; a pipe and
    `export --out` get the rows as they were kept."""
    evil = "\x1b]0;pwned-title\x07desc \x1b[2J\x1b[31mred\x1b[0m \x9b2Jgone"
    path = tmp_path / "runs.db"
    s = Store(str(path))
    a = s.begin_run("show", ["-sC", "show version"], "u", 3, "0", run_id="20261026-100000-aaaa")
    s.add(a, "R1", 0, "show version", True, 1, None, f"Hostname: R1\n{evil}\nModel: vmx")
    s.add(a, "R2", 0, "show version", False, 1, f"refused: {evil}")
    s.add(a, "R3", 0, "show version", True, 1, None, json.dumps({"descr": evil}), fmt="json")
    b = s.begin_run("show", ["-sC", "show version"], "u", 1, "0", run_id="20261026-110000-bbbb")
    s.add(b, "R1", 0, "show version", True, 1, None, f"Hostname: R1\n{evil}\nModel: mx")
    s.close()
    for tty, seen in ((True, "desc red gone"), (False, evil)):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: tty)
        monkeypatch.setattr(sys.stderr, "isatty", lambda: tty)
        for argv in (("output", "R1", a), ("output", "R2", a), ("grep", "desc", "--device", "R1"),
                     ("field", "descr"), ("failed", a), ("diff", "R1", a, b), ("export", a)):
            _, out, err = reader(capsys, path, *argv)
            assert seen in out + err, argv
            if tty:
                assert not any(c in out + err for c in "\x1b\x07\x9b"), argv
        _, out, _ = reader(capsys, path, "export", a, "--format", "jsonl")
        assert json.loads(out.splitlines()[0])["output"] == f"Hostname: R1\n{seen}\nModel: vmx"
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    rc, out, _ = reader(capsys, path, "diff", "R1", a, b)             # each diff line on a screen line
    assert rc == 1 and "-Model: vmx\n+Model: mx\n" in out
    rc, out, err = reader(capsys, path, "export", a, "--out", str(tmp_path / "rows.csv"))
    assert rc == 0 and out == "" and evil in (tmp_path / "rows.csv").read_text()   # a file is not a terminal


def test_the_reader_looks_where_the_run_wrote(tmp_path, capsys, monkeypatch):
    """--store, else HSSH_STORE, else the config file's `store`, else h-ssh.db here."""
    from hssh import core
    monkeypatch.delenv("HSSH_STORE", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(core, "get_config_path", lambda: tmp_path / "no-config")
    rc = store_main(["runs"])
    assert rc == 2 and "no store at h-ssh.db: no run has been kept here" in capsys.readouterr()[1]
    rc = store_main(["--store", str(tmp_path / "none.db"), "runs"])
    assert rc == 2 and "no store at" in capsys.readouterr()[1]
    filled(tmp_path / "h-ssh.db")
    assert store_main(["runs"]) == 0                       # the default: h-ssh.db in the current directory
    capsys.readouterr()
    filled(tmp_path / "from-config.db")
    (tmp_path / "config").write_text(f"store = {tmp_path / 'from-config.db'}\n")
    monkeypatch.setattr(core, "get_config_path", lambda: tmp_path / "config")
    assert store_main(["runs"]) == 0 and "from-config" not in capsys.readouterr()[0]   # read, no error
    monkeypatch.setenv("HSSH_STORE", str(tmp_path / "missing.db"))
    assert store_main(["runs"]) == 2                       # the variable beats the config file


def test_the_reader_reads_rows_as_it_goes_not_the_store_into_memory(tmp_path, monkeypatch):
    """results() hands back the cursor, and grep, field and export print a
    row before they read the next: a store of hundreds of megabytes costs
    the reader no more memory than a small one (fetchall() held every
    matching row, and so would a list() of the cursor)."""
    path = tmp_path / "runs.db"
    filled(path)
    s = Store(str(path))
    run = s.begin_run("commit-status", ["--commit-status"], "lab", 2, "1.0.0", command="commit-status")
    for device in ("r1", "r2"):                               # every run's first row is r1's, in whatever order the ids sort
        s.add_entry(run, {**COMMITS, "device": device}, "show system commit")
    s.close()
    trail = []

    class Cursor(sqlite3.Cursor):
        def __next__(self):
            row = super().__next__()
            trail.append("f")                                 # a row read from the store
            return row

    class Connection(sqlite3.Connection):
        def execute(self, sql, params=()):
            factory = Cursor if sql.startswith("SELECT * FROM results") else sqlite3.Cursor
            return self.cursor(factory).execute(sql, params)

    class Out:
        def write(self, text):
            trail.append("w")                                 # something printed
            return len(text)

        def flush(self):
            pass

    store = Store(str(path), readonly=True)
    store.conn.close()
    store.conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, factory=Connection)
    store.conn.row_factory = sqlite3.Row
    first = next(iter(store.results()))                       # one row asked for: one row read
    assert first["device"] == "r1" and trail == ["f"]
    monkeypatch.setattr(sys, "stdout", Out())
    parser = store_module.build_parser()
    for argv, read in ((["export", "--all"], 7), (["export", "--all", "--format", "jsonl"], 7),
                       (["grep", "."], 5), (["field", "0.user", "--command", "show system commit"], 3)):
        trail.clear()
        args = parser.parse_args(argv)
        assert args.fn(store, args) == 0
        seen = "".join(trail)
        assert seen.count("f") == read and "ff" not in seen, (argv, seen)     # never two rows held
    store.close()


def test_an_export_out_file_that_cannot_be_opened_or_written_is_an_error_line_not_a_traceback(tmp_path, capsys):
    """--out into a directory that is not there, onto a directory, into one
    that cannot be written, onto a disk that fills: one ERROR line and exit
    2, as every other failure of the reader."""
    filled(tmp_path / "s.db")
    rc, out, err = reader(capsys, tmp_path / "s.db", "export", "--out", str(tmp_path / "missing" / "rows.csv"))
    assert rc == 2 and out == "" and err.startswith("ERROR: --out ") and "rows.csv: No such file or directory" in err
    rc, out, err = reader(capsys, tmp_path / "s.db", "export", "--out", str(tmp_path))
    assert rc == 2 and "ERROR: --out" in err and "Is a directory" in err
    rc, out, err = reader(capsys, tmp_path / "s.db", "export", "--all", "--out", "/dev/full")
    assert rc == 2 and out == "" and err == "ERROR: --out /dev/full: No space left on device\n"
    if os.geteuid() != 0:                                     # root writes anywhere
        ro = tmp_path / "ro"
        ro.mkdir(mode=0o500)
        rc, out, err = reader(capsys, tmp_path / "s.db", "export", "--out", str(ro / "rows.csv"))
        assert rc == 2 and "ERROR: --out" in err and "Permission denied" in err


def test_an_export_out_file_is_private_and_never_a_link_a_fifo_or_the_live_wal(tmp_path, capsys):
    """--out was a plain open() (#149): 0644 under umask 022, a file that was
    there kept its mode, a symlink was followed and its target written
    world-readable, a FIFO blocked the reader, and a hard link to the live
    -wal, which realpath does not see, was emptied under the store. It is
    opened as --log is written: 0600 whatever was there, no symlink
    followed, a FIFO failed at once, a file of the store's under any name
    refused with the store untouched; /dev/null still takes the rows."""
    path = tmp_path / "h-ssh.db"
    filled(path)
    old = os.umask(0o022)
    try:
        out, loose = tmp_path / "rows.csv", tmp_path / "loose.csv"
        loose.write_text("x")
        loose.chmod(0o644)
        for target in (out, loose):
            rc, _, err = reader(capsys, path, "export", "--all", "--out", str(target))
            assert rc == 0 and err == f"5 rows written to {target}\n" and stat.S_IMODE(target.stat().st_mode) == 0o600
            assert target.read_text().startswith("run_id,device,")
    finally:
        os.umask(old)
    kept, link = tmp_path / "kept", tmp_path / "link.csv"
    kept.write_text("keep\n")
    link.symlink_to(kept)
    rc, _, err = reader(capsys, path, "export", "--all", "--out", str(link))
    assert rc == 2 and err == f"ERROR: --out {link}: a symbolic link, not followed\n" and kept.read_text() == "keep\n"
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    started = time.monotonic()
    rc, _, err = reader(capsys, path, "export", "--all", "--out", str(fifo))
    assert rc == 2 and err.startswith(f"ERROR: --out {fifo}: ") and time.monotonic() - started < 2
    writer = Store(str(path))                       # the -wal is there while a writer has the store
    run = writer.begin_run("show", [], "lab", 1, "1.0.0", command="version")
    writer.add_entry(run, SHOW, "show version")
    wal, hard = tmp_path / "h-ssh.db-wal", tmp_path / "hard.csv"
    frames = wal.read_bytes()
    os.link(wal, hard)
    rc, _, err = reader(capsys, path, "export", "--all", "--out", str(hard))
    assert rc == 2 and err == f"ERROR: --out {hard}: that is the store's -wal file\n"
    assert frames and wal.read_bytes() == frames
    writer.close()
    rc, _, err = reader(capsys, path, "export", "--all", "--out", "/dev/null")
    assert rc == 0 and err == "6 rows written to /dev/null\n"


def test_an_export_onto_the_store_itself_is_refused_and_the_store_kept(tmp_path, monkeypatch, capsys):
    """`--out h-<Tab>` in a job directory completes to h-ssh.db, and the
    export written there emptied the store under the rows being read
    ('malformed', no row left anywhere). Refused before anything is opened:
    the store as typed, through a symlink or a hard link, and the files
    SQLite keeps beside it."""
    path = tmp_path / "h-ssh.db"
    filled(path)
    kept = path.read_bytes()
    (tmp_path / "link.db").symlink_to(path)
    os.link(path, tmp_path / "hard.db")
    monkeypatch.chdir(tmp_path)
    for out in ("h-ssh.db", str(path), "link.db", "hard.db"):
        rc, got, err = reader(capsys, path, "export", "--all", "--out", out)
        assert rc == 2 and got == "" and err == f"ERROR: --out {out}: that is the store itself\n"
    for side in ("-wal", "-shm", "-journal"):
        rc, got, err = reader(capsys, path, "export", "--all", "--out", "h-ssh.db" + side)
        assert rc == 2 and err == f"ERROR: --out h-ssh.db{side}: that is the store's {side} file\n"
    assert path.read_bytes() == kept and not (tmp_path / "h-ssh.db-journal").exists()
    rc, got, _ = reader(capsys, path, "export", "--all", "--format", "jsonl")
    assert rc == 0 and len(got.splitlines()) == 5


def no_room_for_a_shm(monkeypatch, name="SQLITE_READONLY_DIRECTORY", text="attempt to write a readonly database"):
    """sqlite3.connect as in a directory the reader cannot write to: a WAL
    reader's first read fails for want of a -shm beside the store (root
    writes anywhere, so CI cannot chmod its way there). The refusal can be
    changed meanwhile; a `name` of None is the message alone, as Python 3.10
    gives it. Every URI opened is kept."""
    real, said = sqlite3.connect, {"name": name, "text": text, "uris": []}

    class Refused(sqlite3.Connection):
        def execute(self, *a, **kw):
            e = sqlite3.OperationalError(said["text"])
            if said["name"]:
                e.sqlite_errorname = said["name"]
            raise e

    def connect(database, *a, uri=False, **kw):
        if uri:
            said["uris"].append(database)
            if "mode=ro" in database and "immutable=1" not in database:
                kw["factory"] = Refused
        return real(database, *a, uri=uri, **kw)

    monkeypatch.setattr(sqlite3, "connect", connect)
    return said


def test_a_store_is_read_as_it_is_only_when_nothing_waits_beside_it(tmp_path, monkeypatch):
    """Where the reader cannot make a -shm, a store with nothing beside it,
    or with the empty -wal a reader leaves, is the whole store and is read
    as it is (immutable). WAL frames or a rollback journal beside it hold
    what the file alone does not say (committed rows, a crashed
    transaction), so the refusal stands, as does any other refusal; and it
    is beside the file itself that counts, not beside a symlink to it.
    Refused for its -wal (a run killed before it closed the store), the
    store says what to do."""
    path = tmp_path / "h-ssh.db"
    r1, r2, r3 = filled(path)
    wal, journal = tmp_path / "h-ssh.db-wal", tmp_path / "h-ssh.db-journal"
    copy_it = ("(its -wal holds rows not yet in the file, and SQLite reads them only in a directory "
               "it can write to: copy the store with its -wal to one you can)")
    link = tmp_path / "elsewhere" / "h-ssh.db"
    link.parent.mkdir()
    link.symlink_to(path)
    refusal = no_room_for_a_shm(monkeypatch)

    def opened(name="SQLITE_READONLY_DIRECTORY", text="attempt to write a readonly database", at=path):
        refusal.update(name=name, text=text)
        try:
            store = Store(str(at), readonly=True)
        except StoreError as e:
            return str(e)
        try:
            assert store.resolve_run(None) == r3              # read, to the last run
        finally:
            store.close()
        return refusal["uris"][-1]

    assert opened().endswith("?mode=ro&immutable=1")
    assert opened(None).endswith("?mode=ro&immutable=1")                          # Python 3.10: the message says it
    wal.write_bytes(b"")                                                           # an empty -wal, its -shm gone
    assert opened("SQLITE_CANTOPEN", "unable to open database file").endswith("?mode=ro&immutable=1")
    assert opened(None, "unable to open database file").endswith("?mode=ro&immutable=1")
    wal.write_bytes(b"frames")                                                     # committed rows the file lacks
    assert opened() == f"{path}: attempt to write a readonly database {copy_it}"
    assert opened("SQLITE_CANTOPEN", "unable to open database file") == f"{path}: unable to open database file {copy_it}"
    assert opened(None, "unable to open database file") == f"{path}: unable to open database file {copy_it}"
    assert opened(at=link) == f"{link}: attempt to write a readonly database {copy_it}"   # beside the file, not the link
    assert opened("SQLITE_BUSY", "database is locked") == f"{path}: database is locked"  # not for want of a -shm
    wal.unlink()
    journal.write_bytes(b"journal")                                                # a crashed transaction
    assert opened("SQLITE_READONLY_ROLLBACK") == f"{path}: attempt to write a readonly database"
    assert opened() == f"{path}: attempt to write a readonly database"
    assert opened(None) == f"{path}: attempt to write a readonly database"        # Python 3.10 alike
    journal.unlink()
    assert opened("SQLITE_READONLY_ROLLBACK") == f"{path}: attempt to write a readonly database"   # not about a -shm
    assert opened("SQLITE_BUSY", "database is locked") == f"{path}: database is locked"
    assert opened().endswith("?mode=ro&immutable=1")


def test_a_store_written_while_it_was_read_as_it_is_is_an_error_not_a_quiet_answer(tmp_path, monkeypatch, capsys):
    """Read as it is, the store has neither locks nor a snapshot: a run that
    writes it meanwhile (an --every tick, the owner's next job) moves pages
    under the reader, which then misses or repeats rows without a word, or
    says 'malformed' of a store that is not. The reader looks again when it
    is done: the file changed (grown, rewritten in place to the same size,
    or another file in its place), or WAL frames beside it now, is exit 2
    with the reason, after the rows it printed. A reader that came meanwhile
    (its empty -wal) wrote nothing."""
    path = tmp_path / "h-ssh.db"
    filled(path)
    no_room_for_a_shm(monkeypatch)
    held, said = [], []

    def next_run(stay=False):
        writer = Store(str(path))
        run = writer.begin_run("show", ["-sC", "show configuration"], "lab", 1, "1.0.0")
        writer.add(run, "r9", 0, "show configuration", True, output="x" * 65536)   # the file grows: seen whatever the clock
        if stay:
            held.append(writer)               # committed into its -wal, not yet into the file
        else:
            writer.close()                    # the last one out: into the file, the -wal gone

    def rewritten():
        """In place and to the same size: only the file's time says so."""
        st = path.stat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))

    def replaced():
        """Another file of the same size and time in its place."""
        st = path.stat()
        twin = tmp_path / "twin.db"
        twin.write_bytes(path.read_bytes())
        os.utime(twin, ns=(st.st_atime_ns, st.st_mtime_ns))
        os.replace(twin, path)

    def export_while(meanwhile):
        """export --all, with `meanwhile` done once its first row is out."""
        done = []

        class Out:
            def write(self, text):
                if not done:
                    done.append(meanwhile())
                return len(text)

            def flush(self):
                said.append("rows")               # what was buffered goes out

        monkeypatch.setattr(sys, "stdout", Out())
        rc = store_main(["--store", str(path), "export", "--all", "--format", "jsonl"])
        return rc, capsys.readouterr().err

    moved = (f"ERROR: {path} was written while it was read as it is; "
             "the output may miss or repeat rows, read it again\n")
    assert export_while(lambda: None) == (0, "")
    assert export_while((tmp_path / "h-ssh.db-wal").touch) == (0, "")             # a reader's empty -wal
    (tmp_path / "h-ssh.db-wal").unlink()
    assert export_while(next_run) == (2, moved)
    assert export_while(lambda: next_run(stay=True)) == (2, moved)
    held.pop().close()
    assert export_while(rewritten) == (2, moved)
    assert export_while(replaced) == (2, moved)
    said.clear()
    monkeypatch.setattr(sys, "stderr", types.SimpleNamespace(write=said.append, flush=lambda: None))
    assert export_while(next_run)[0] == 2 and said[:2] == ["rows", moved[:-1]]     # the rows out, then the reason


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes anywhere")
def test_a_finished_store_in_a_directory_the_reader_cannot_write_is_still_read(tmp_path, capsys):
    """An archived job directory, a read-only mount: the file is plain SQLite
    and the reader reads it where the run wrote it. A WAL reader wants a
    -shm file beside the store, which such a directory refuses; a finished
    store (no -wal left, or the empty one a reader leaves) is read as it is
    instead, and nothing is left beside it. One a run is still writing has
    both files beside it and is read through them; one whose run was killed
    with rows still in the -wal, archived without the -shm, is refused with
    what to do, and read where SQLite may write."""
    archived = tmp_path / "archived"
    archived.mkdir()
    r1, r2, r3 = filled(archived / "h-ssh.db")
    assert sorted(p.name for p in archived.iterdir()) == ["h-ssh.db"]       # finished: no -wal, no -shm
    archived.chmod(0o555)
    try:
        rc, out, err = reader(capsys, archived / "h-ssh.db", "runs")
        assert rc == 0 and err == "" and [ln.split()[0] for ln in out.splitlines()[1:]] == [r3, r2, r1]
        rc, out, _ = reader(capsys, archived / "h-ssh.db", "grep", "junos:", "-i")
        assert rc == 0 and "Junos: 23.2" in out
        rc, out, _ = reader(capsys, archived / "h-ssh.db", "export", "--all", "--format", "jsonl")
        assert rc == 0 and len(out.splitlines()) == 5
        assert sorted(p.name for p in archived.iterdir()) == ["h-ssh.db"]   # nothing was left beside it
    finally:
        archived.chmod(0o755)
    assert reader(capsys, archived / "h-ssh.db", "runs")[0] == 0            # read where it may write: an empty -wal stays
    assert (archived / "h-ssh.db-wal").stat().st_size == 0
    (archived / "h-ssh.db-shm").unlink()                                    # archived without the -shm
    archived.chmod(0o555)
    try:
        rc, out, err = reader(capsys, archived / "h-ssh.db", "export", "--all", "--format", "jsonl")
        assert rc == 0 and err == "" and len(out.splitlines()) == 5
    finally:
        archived.chmod(0o755)
    live = tmp_path / "live"
    live.mkdir()
    writer = Store(str(live / "h-ssh.db"))
    run = writer.begin_run("show", ["-sC", "show version"], "lab", 1, "1.0.0")
    writer.add(run, "r7", 0, "show version", True, output="Junos: 24.4\n")   # committed, sits in the -wal
    assert (live / "h-ssh.db-wal").exists()
    killed = tmp_path / "killed"                                            # the run killed there, archived
    killed.mkdir()                                                          # without the -shm
    for name in ("h-ssh.db", "h-ssh.db-wal"):
        (killed / name).write_bytes((live / name).read_bytes())
    killed.chmod(0o555)
    try:
        rc, out, err = reader(capsys, killed / "h-ssh.db", "grep", "junos:", "-i")
        assert rc == 2 and out == "" and err.startswith(f"ERROR: {killed / 'h-ssh.db'}: ")
        assert err.endswith("(its -wal holds rows not yet in the file, and SQLite reads them only in a "
                            "directory it can write to: copy the store with its -wal to one you can)\n")
    finally:
        killed.chmod(0o755)
    rc, out, _ = reader(capsys, killed / "h-ssh.db", "grep", "junos:", "-i")     # where SQLite may write
    assert rc == 0 and "Junos: 24.4" in out
    live.chmod(0o555)
    try:
        rc, out, _ = reader(capsys, live / "h-ssh.db", "grep", "junos:", "-i")
        assert rc == 0 and "Junos: 24.4" in out                            # read through the -wal, not past it
    finally:
        live.chmod(0o755)
        writer.close()


class Gone:
    """stdout (or stderr) on a pipe whose reader left: the write fails, or
    only the flush (a short reply sits in the buffer until the end). What
    was not taken stays in the buffer, so every later flush fails too."""
    def __init__(self, at):
        self.at = at

    def write(self, text):
        if self.at == "write":
            raise BrokenPipeError
        return len(text)

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def flush(self):
        raise BrokenPipeError

    def fileno(self):
        return 1


def test_a_reader_that_stops_early_is_exit_0_not_a_traceback(tmp_path, monkeypatch, capsys):
    """`h-ssh-store ... | head`: the pipe closes under the reader in the
    middle. Exit 0, not a word about it, as h-ssh itself does. main() leaves
    the calling process's descriptors alone; the console script parks
    stdout on /dev/null so the interpreter's final flush does not fail a
    second time (that was exit 120)."""
    filled(tmp_path / "s.db")
    parked = []
    monkeypatch.setattr(os, "dup2", lambda fd, to: parked.append(to))
    for argv in (["export", "--all", "--format", "jsonl"], ["grep", "junos", "-i"]):
        argv = ["--store", str(tmp_path / "s.db"), *argv]
        monkeypatch.setattr(sys, "stdout", Gone("write"))
        assert store_main(argv) == 0 and parked == [] and capsys.readouterr().err == "", argv
        monkeypatch.setattr(sys, "argv", ["h-ssh-store", *argv])
        with pytest.raises(SystemExit) as end:
            store_module.main_sync()
        assert end.value.code == 0 and parked[:1] == [1] and capsys.readouterr().err == "", argv
        parked.clear()


def test_a_reader_that_left_keeps_the_verdict_the_command_already_had(tmp_path, monkeypatch, capsys):
    """`failed`, `diff` and `output` know their verdict before they print
    ('there are failures', 'they differ', 'the row failed'), and it stands
    whether the pipe closed in the middle (a long list into `| head`) or is
    found closed at the final flush, as h-ssh's does: `set -o pipefail`
    never reads it as a clean 0. So does the exit code of a line on stderr
    that went with the pipe (`2>&1 | head`), an ERROR line's 2 included."""
    path = tmp_path / "s.db"
    r1, r2, r3 = filled(path)
    out, parked = sys.stdout, []
    monkeypatch.setattr(os, "dup2", lambda fd, to: parked.append(to))
    for at in ("write", "flush"):
        for argv, verdict in ((["failed", r1], 1), (["diff", "r1", r1, r2], 1), (["slowest"], 0)):
            argv = ["--store", str(path), *argv]
            monkeypatch.setattr(sys, "stdout", Gone(at))
            assert store_main(argv) == verdict and parked == [], (at, argv)
            monkeypatch.setattr(sys, "argv", ["h-ssh-store", *argv])
            with pytest.raises(SystemExit) as end:
                store_module.main_sync()
            assert end.value.code == verdict and parked[:1] == [1] and capsys.readouterr().err == "", (at, argv)
            parked.clear()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", Gone("write"))
    for argv, verdict in ((["output", "r2", r1], 1),                         # the row failed
                          (["output", "nobody"], 2),                         # no such row: the ERROR line
                          (["export", "--all", "--device", "nobody", "--out", str(tmp_path / "none.csv")], 1)):
        assert store_main(["--store", str(path), *argv]) == verdict, argv


def test_a_reader_started_with_stdout_or_stderr_closed_is_no_traceback(tmp_path, monkeypatch):
    """`h-ssh-store runs >&-` (or `2>&-`): a descriptor closed before the
    start leaves Python no stream at all (None), and print() prints
    nothing. The flushes that look for a reader that left skip it rather
    than fail on it (that was a traceback, exit 1)."""
    filled(tmp_path / "s.db")
    argv = ["--store", str(tmp_path / "s.db"), "runs"]
    monkeypatch.setattr(sys, "argv", ["h-ssh-store", *argv])
    for stream in ("stdout", "stderr"):
        with monkeypatch.context() as m:
            m.setattr(sys, stream, None)
            assert store_main(argv) == 0, stream
            with pytest.raises(SystemExit) as end:
                store_module.main_sync()
            assert end.value.code == 0, stream


# --- through the CLI ----------------------------------------------------------------

def run_cli(monkeypatch, capsys, argv, fake=None):
    fake = fake or types.SimpleNamespace(
        AVAILABLE=True,
        show=lambda host, user, passwd, cmd, *a, **kw: f"Hostname: {host}\nroot-authentication encrypted-password \"$9$zz\"\n",
        show_batch=lambda host, user, passwd, cmds, *a, **kw: [
            {"command": c, "ok": c != "show nothing", **({"output": f"{c} on {host}"} if c != "show nothing"
                                                          else {"error": "'show nothing' was refused by the device: error: syntax error"})}
            for c in cmds],
        edit=lambda *a, **kw: "COMMIT OK\n")
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", fake)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER", "HSSH_STORE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", *argv])
    try:
        rc = asyncio.run(cli.main())
    except SystemExit as e:
        rc = e.code
    out, err = capsys.readouterr()
    return rc, out, err


def test_a_show_run_lands_in_the_store_with_its_run_row(tmp_path, monkeypatch, capsys):
    path = tmp_path / "runs.db"
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(path), "--target", "R1:10.0.0.1:junos",
                                                 "--target", "R2:10.0.0.2:junos", "-sC", "show version"])
    assert rc == 0, err
    runs = rows(path, "SELECT * FROM runs")
    assert len(runs) == 1
    run = runs[0]
    assert run["mode"] == "show" and run["user"] == "u" and run["command"] == "show version"
    assert (run["targets"], run["ok"], run["failed"], run["skipped"], run["interrupted"]) == (2, 2, 0, 0, 0)
    assert run["finished"] is not None and run["version"] == cli.__version__
    assert run["argv"].startswith("--config ") and "--store" in run["argv"]
    got = {r["device"]: r for r in rows(path, "SELECT * FROM results")}
    assert set(got) == {"R1", "R2"}
    assert got["R1"]["command"] == "show version" and got["R1"]["vendor"] == "junos" and got["R1"]["host"] == "10.0.0.1"
    assert got["R1"]["output"] == "Hostname: 10.0.0.1\nroot-authentication encrypted-password \"$9$zz\""
    assert got["R1"]["ok"] == 1 and got["R1"]["format"] == "text" and got["R1"]["duration_ms"] is not None
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_batch_is_one_row_per_command_and_a_failure_is_the_devices_line(tmp_path, monkeypatch, capsys):
    path = tmp_path / "runs.db"
    cmds = tmp_path / "cmds.txt"
    cmds.write_text("show version\nshow nothing\nshow route\n")
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(path), "--target", "R1:10.0.0.1:junos",
                                                 "--batch", str(cmds)])
    assert rc == 1, err
    got = rows(path, "SELECT * FROM results ORDER BY seq")
    assert [(r["seq"], r["command"], r["ok"]) for r in got] == \
        [(0, "show version", 1), (1, "show nothing", 0), (2, "show route", 1)]
    assert got[1]["error"].startswith("'show nothing' was refused by the device")
    assert got[2]["output"] == "show route on 10.0.0.1"
    run = rows(path, "SELECT * FROM runs")[0]
    assert run["mode"] == "show-batch" and run["command"] == "show version\nshow nothing\nshow route"
    assert (run["ok"], run["failed"]) == (0, 1)
    # the reader sees what the CLI stored
    rc = store_main(["--store", str(path), "failed"])
    assert rc == 1 and "show nothing" in capsys.readouterr()[0]


def test_a_job_that_names_one_device_twice_keeps_a_row_per_entry(tmp_path, monkeypatch, capsys):
    """Every job entry was written at seq 0, so a device named in two entries
    kept only the row of whichever finished last: run row 3/3, two rows. Now
    seq counts up per device in file order, as a batch's commands do."""
    path = tmp_path / "runs.db"
    job = tmp_path / "job.json"
    job.write_text(json.dumps([
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R1:10.0.0.1:junos", "show": "show interfaces terse"},
        {"target": "R2:10.0.0.2:junos", "show": "show version"},
    ]))
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda host, user, passwd, cmd, *a, **kw: f"{cmd} on {host}\n")
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(path), "--job", str(job), "--json"], fake=fake)
    assert rc == 0, err
    assert len(json.loads(out)) == 3
    got = rows(path, "SELECT device, seq, command, output FROM results ORDER BY device, seq")
    assert [(r["device"], r["seq"], r["command"], r["output"]) for r in got] == [
        ("R1", 0, "show version", "show version on 10.0.0.1"),
        ("R1", 1, "show interfaces terse", "show interfaces terse on 10.0.0.1"),
        ("R2", 0, "show version", "show version on 10.0.0.2")]
    run = rows(path, "SELECT * FROM runs")[0]
    assert run["mode"] == "job" and (run["targets"], run["ok"], run["failed"]) == (3, 3, 0)
    rc, out, _ = reader(capsys, path, "output", "R1", "--seq", "1")
    assert rc == 0 and out == "show interfaces terse on 10.0.0.1\n"


def test_the_row_is_the_reply_as_it_came_whether_stdout_is_a_terminal_or_a_pipe(tmp_path, monkeypatch, capsys):
    """The row (and --log) was built from the text as shown: on a terminal
    the escape sequences, BEL and C1 bytes were gone; on a pipe splitlines()
    had turned NEL, VT, FF and the Unicode separators into LF. The record is
    the reply as it came either way; only the screen is sanitised."""
    reply = "Hostname: R1\x1b[31m red\x1b[0m\x07 bell\nnel\x85vt\x0bff\x0cls\u2028ps\u2029end\nModel: vmx\n"
    kept = reply.rstrip("\n")                   # the runner frames the reply and drops the newline at its end
    assert cli.strip_result_header("DEVICE: R1\nHOST:   10.0.0.1\nMODE:   show\nVENDOR: junos\n\n" + kept) == kept
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: reply)
    for where, tty in (("pipe", False), ("terminal", True)):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: tty)      # the CLI asks the stream it has at run time
        db, log = tmp_path / f"{where}.db", tmp_path / f"{where}.jsonl"
        rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(db), "--target", "R1:10.0.0.1:junos",
                                                     "-sC", "show version", "-v", "--log", str(log)], fake=fake)
        assert rc == 0, err
        assert rows(db, "SELECT output FROM results")[0]["output"] == kept, where
        assert json.loads(log.read_text())["output"] == kept, where
        assert "Hostname: R1" in out and "Model: vmx" in out
        if tty:
            assert not any(c in out for c in ("\x1b", "\x07", "\x85", "\x0b", "\x0c")), where
        else:
            assert "\x1b[31m red\x1b[0m\x07 bell" in out, where


def test_a_crlf_reply_keeps_its_line_endings_in_the_row_and_on_raw_to_a_pipe(tmp_path, monkeypatch, capsys):
    """An exec channel that ends its lines with CRLF (an IOS-shaped device)
    came out LF in the record and on --raw, from a splitlines(). The reply's
    own line endings are kept; only the line end after its last line goes,
    with the runner's framing."""
    reply = "interface Gi0/1\r\n description uplink\r\n shutdown\r\n"
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: reply)
    monkeypatch.setitem(drivers.MODULES, "ios@ssh", fake)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    path = tmp_path / "runs.db"
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(path), "--target", "R1:10.0.0.1:ios@ssh",
                                                 "-sC", "show running-config interface Gi0/1", "--raw"], fake=fake)
    assert rc == 0, err
    assert out == "R1:\ninterface Gi0/1\r\n description uplink\r\n shutdown\n\n"
    assert rows(path, "SELECT output FROM results")[0]["output"] == "interface Gi0/1\r\n description uplink\r\n shutdown"


VMX = "Model: vmx\nJunos: 24.2R1-S2.5\n"


@pytest.mark.parametrize("before, after, hunk", [
    (VMX, "Model: vmx\nJunos: 23.4R2.13\n", "@@ -1,2 +1,2 @@\n Model: vmx\n-Junos: 24.2R1-S2.5\n+Junos: 23.4R2.13\n"),
    (VMX, VMX + "Peer: 10.9.9.8\n", "@@ -1,2 +1,3 @@\n Model: vmx\n Junos: 24.2R1-S2.5\n+Peer: 10.9.9.8\n"),
    (VMX + "Peer: 10.9.9.8\n", VMX, "@@ -1,3 +1,2 @@\n Model: vmx\n Junos: 24.2R1-S2.5\n-Peer: 10.9.9.8\n"),
], ids=["changed", "added", "removed"])
def test_the_readers_diff_treats_the_trimmed_last_line_like_any_other(tmp_path, monkeypatch, capsys, before, after,
                                                                       hunk):
    """The CLI keeps a reply trimmed, with no newline after its last line;
    `h-ssh-store diff` still takes it as a line like any other. Changed, it
    is a line taken away and a line put in, a line each; left as it was, with
    a line added or taken away after it, it is no change."""
    path = tmp_path / "runs.db"

    def answering(reply):
        return types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: reply)

    for reply in (before, after):
        rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(path), "--target", "R1:10.0.0.1:junos",
                                                     "-sC", "show version"], fake=answering(reply))
        assert rc == 0, err
    first, second = [r["run_id"] for r in rows(path, "SELECT run_id FROM runs ORDER BY rowid")]
    rc, out, _ = reader(capsys, path, "diff", "R1", first, second)
    assert rc == 1 and out == f"--- R1 {first}\n+++ R1 {second}\n" + hunk


def test_the_store_env_var_names_the_file(tmp_path, monkeypatch, capsys):
    path = tmp_path / "runs.db"
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(
        AVAILABLE=True, show=lambda *a, **kw: "encrypted-password \"$9$keep\"\n"))
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_STORE", str(path))
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u",
                                      "--target", "R1:10.0.0.1:junos", "-sC", "show version"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 0, err
    assert rows(path, "SELECT output FROM results")[0]["output"] == "encrypted-password \"$9$keep\""


def test_an_unwritable_store_refuses_to_start(tmp_path, monkeypatch, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("")
    calls = []
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: calls.append(1) or "ok")
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(blocker / "runs.db"), "--target", "R1:10.0.0.1:junos",
                                                 "-sC", "show version"], fake=fake)
    assert rc == 2 and "every run is kept" in err and "--no-store" in err and "refusing to start" in err
    assert calls == []


def test_every_run_is_kept_in_h_ssh_db_in_the_current_directory(tmp_path, monkeypatch, capsys):
    """No flag, no variable, no config: the store is ./h-ssh.db, and the
    evidence sits with the job."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HSSH_STORE", raising=False)
    rc, out, err = run_cli(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version"])
    assert rc == 0, err
    assert (tmp_path / "h-ssh.db").is_file() and stat.S_IMODE((tmp_path / "h-ssh.db").stat().st_mode) == 0o600
    got = rows(tmp_path / "h-ssh.db", "SELECT device, command, ok FROM results")
    assert got == [{"device": "R1", "command": "show version", "ok": 1}]
    # the reader finds it the same way
    assert store_main(["runs"]) == 0 and "show version" in capsys.readouterr()[0]


def test_the_config_file_can_name_the_store(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HSSH_STORE", raising=False)
    cfg = tmp_path / "config"
    cfg.write_text(f"store = {tmp_path / 'kept' / 'fleet.db'}\n")
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "ok"))
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", str(cfg), "--user", "u", "--target", "R1:10.0.0.1:junos",
                                      "-sC", "show version"])
    assert asyncio.run(cli.main()) == 0
    assert (tmp_path / "kept" / "fleet.db").is_file() and not (tmp_path / "h-ssh.db").exists()
    # the variable beats the file, the flag beats both
    monkeypatch.setenv("HSSH_STORE", str(tmp_path / "env.db"))
    assert asyncio.run(cli.main()) == 0 and (tmp_path / "env.db").is_file()
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", str(cfg), "--user", "u", "--store", str(tmp_path / "flag.db"),
                                      "--target", "R1:10.0.0.1:junos", "-sC", "show version"])
    assert asyncio.run(cli.main()) == 0 and (tmp_path / "flag.db").is_file()
    assert len(rows(tmp_path / "env.db", "SELECT * FROM runs")) == 1


def test_a_tilde_in_the_config_or_the_variable_means_home(tmp_path, monkeypatch, capsys):
    """`store = ~/.h-ssh/runs.db` made a directory called `~` where the run
    started, and the reader followed it there, so nobody noticed."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HSSH_STORE", raising=False)
    assert store_module.where(None, {"store": "~/.h-ssh/runs.db"}) == str(home / ".h-ssh" / "runs.db")
    assert store_module.where("~/flag.db") == str(home / "flag.db")
    monkeypatch.setenv("HSSH_STORE", "~/env.db")
    assert store_module.where() == str(home / "env.db")
    monkeypatch.delenv("HSSH_STORE")
    cfg = tmp_path / "config"
    cfg.write_text("store = ~/.h-ssh/runs.db\n")
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "ok"))
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", str(cfg), "--user", "u", "--target", "R1:10.0.0.1:junos",
                                      "-sC", "show version"])
    assert asyncio.run(cli.main()) == 0
    assert (home / ".h-ssh" / "runs.db").is_file() and not (tmp_path / "~").exists()
    capsys.readouterr()
    monkeypatch.setenv("HSSH_STORE", "~/.h-ssh/runs.db")           # the reader expands it the same way
    assert store_main(["runs"]) == 0 and "show version" in capsys.readouterr()[0]


def test_no_store_keeps_nothing_and_contradicts_store(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HSSH_STORE", raising=False)
    rc, out, err = run_cli(monkeypatch, capsys, ["--no-store", "--target", "R1:10.0.0.1:junos", "-sC", "show version"])
    assert rc == 0, err
    assert not (tmp_path / "h-ssh.db").exists() and "R1" in out
    rc, out, err = run_cli(monkeypatch, capsys, ["--no-store", "--store", str(tmp_path / "x.db"), "--target", "R1:10.0.0.1:junos",
                                                 "-sC", "show version"])
    assert rc == 2 and "contradict" in err and not (tmp_path / "x.db").exists()


@pytest.mark.parametrize("argv, password, says", [
    (["-sC", "show version", "--raw", "-v"], "p", "--raw and -v are mutually exclusive"),
    (["-sC", "show version", "--raw", "--json"], "p", "--raw and --json are mutually exclusive"),
    (["-eC", "set system host-name x"], "p", "Edit operation requires confirmation but stdin is not a TTY"),
    (["-eC", "set system host-name x", "--show-diff"], "p", "--show-diff needs a terminal to ask, or -y"),
    (["-sC", "show version"], "", "HSSH_PASSWORD is set but empty"),
    (["-sC", "show version", "--safety-file", "{tmp}/plain/safety.json"], "p", "--safety-file requested but unusable"),
    (["-sC", "show version", "--save-output", "{tmp}/plain"], "p", "exists and is not a directory"),
    (["-sC", "show version", "--save-output", "{tmp}/plain/out"], "p", "--save-output"),
], ids=["raw-v", "raw-json", "edit-no-terminal", "show-diff-no-terminal", "empty-password", "safety-file",
        "save-output-file", "save-output-mkdir"])
def test_a_run_refused_before_it_starts_leaves_no_store_file(tmp_path, monkeypatch, capsys, argv, password, says):
    """#136: the store was opened before these refusals, so a run that
    exited 2 with nothing run left an empty h-ssh.db (no run in it) where it
    was started. Every refusal that needs no store comes before the store is
    opened, and one after it (a safety file or a --save-output directory
    that cannot be used) takes away the store the run made; a run that
    passes them makes the store and fills it."""
    work = tmp_path / "job"
    work.mkdir()
    (tmp_path / "plain").write_text("")             # a file where a directory is wanted
    monkeypatch.chdir(work)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER", "HSSH_STORE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli, "_tty", lambda stream: False)          # a pipeline: no terminal to ask at
    calls = []
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(
        AVAILABLE=True, show=lambda *a, **kw: calls.append(a[3]) or "ok", edit=lambda *a, **kw: calls.append(a[3]) or "COMMIT OK\n"))

    def h_ssh(*args, password="p"):
        monkeypatch.setenv("HSSH_PASSWORD", password)
        monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "R1:10.0.0.1:junos",
                                          *(a.replace("{tmp}", str(tmp_path)) for a in args)])
        rc = asyncio.run(cli.main())
        return (rc, *capsys.readouterr())

    rc, out, err = h_ssh(*argv, password=password)
    assert rc == 2 and says in err and calls == []
    assert os.listdir(work) == []
    rc, out, err = h_ssh("-sC", "show version")
    assert rc == 0, err
    assert calls == ["show version"] and os.listdir(work) == ["h-ssh.db"]
    assert rows(work / "h-ssh.db", "SELECT device, command, output FROM results") == [
        {"device": "R1", "command": "show version", "output": "ok"}]


@pytest.mark.parametrize("stop", ["ctrl-d", "ctrl-c"])
def test_a_run_stopped_at_the_password_prompt_leaves_no_store_file(tmp_path, monkeypatch, capsys, stop):
    """#136 review: the store is opened before the password prompt, so a
    run stopped there, Ctrl-D (exit 2, nothing was sent) or Ctrl-C, left an
    empty h-ssh.db with no run in it, its -wal and -shm while it lived. The
    store that run made is taken away; one that was there stays as it was."""
    work = tmp_path / "job"
    work.mkdir()
    monkeypatch.chdir(work)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER", "HSSH_STORE", "HSSH_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli, "_tty", lambda stream: True)                # by hand, at a terminal
    calls = []
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(
        AVAILABLE=True, show=lambda *a, **kw: calls.append(a[2]) or "ok"))

    def h_ssh(typed):
        def getpass(prompt=""):
            assert sorted(os.listdir(work)) == ["h-ssh.db", "h-ssh.db-shm", "h-ssh.db-wal"]   # open as it asks
            if typed is None:
                raise EOFError if stop == "ctrl-d" else KeyboardInterrupt
            return typed
        monkeypatch.setattr(cli.getpass, "getpass", getpass)
        monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "R1:10.0.0.1:junos",
                                          "-sC", "show version"])
        try:
            rc = asyncio.run(cli.main())
        except KeyboardInterrupt:
            rc = 130
        return (rc, *capsys.readouterr())

    rc, out, err = h_ssh(None)
    assert rc == (2 if stop == "ctrl-d" else 130) and calls == []
    assert stop == "ctrl-c" or "no password given at the prompt" in err
    assert os.listdir(work) == []
    rc, out, err = h_ssh("s3cret")
    assert rc == 0 and calls == ["s3cret"], err
    rc, out, err = h_ssh(None)                       # a store that was there is no run's to take away
    assert calls == ["s3cret"] and os.listdir(work) == ["h-ssh.db"]
    assert rows(work / "h-ssh.db", "SELECT device, command, output FROM results") == [
        {"device": "R1", "command": "show version", "output": "ok"}]


def test_main_closes_the_store_it_opened_however_it_returns(tmp_path, monkeypatch, capsys):
    """#180: main() opened the store, and most of its return paths after
    that (an edit stopped at `Proceed with changes?` here) returned without
    closing it. A process exits anyway; a caller of main() in-process (a
    script, this suite, the watch's next tick) kept the connection and the
    fd of the store's directory until garbage collection, which Python 3.13
    says as a ResourceWarning wherever that happens to run. The store is
    closed when main() returns, whichever way it does."""
    opened = []
    real = cli.Store

    def store_made(*a, **kw):
        opened.append(real(*a, **kw))
        return opened[-1]
    monkeypatch.setattr(cli, "Store", store_made)
    monkeypatch.setattr(cli, "_tty", lambda stream: True)                # by hand, at a terminal
    monkeypatch.setattr(builtins, "input", lambda prompt="": "n")
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(tmp_path / "runs.db"), "--target", "R1:10.0.0.1:junos",
                                                 "-eC", "set system host-name R1"])
    assert rc == 0 and "Aborted by user." in out, err
    store, = opened
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        store.conn.execute("SELECT 1")


def test_discard_takes_away_only_a_store_this_store_made_and_nobody_kept_a_run_in(tmp_path):
    """Store.discard(), for a run stopped before it starts: the file goes,
    with its -wal and -shm, when this Store made it and nothing is kept in
    it. A file that was there, one another connection still has open, one
    another run kept a row in meanwhile, and one that is not the file this
    Store opened (another took its name) all stay, with their rows."""
    path = tmp_path / "s.db"
    s = Store(str(path))
    assert s.made and s.discard() is True and os.listdir(tmp_path) == []
    Store(str(path)).close()
    found = Store(str(path))                         # there before: never this run's to take away
    assert not found.made and found.discard() is False and os.listdir(tmp_path) == ["s.db"]
    path.unlink()
    s, other = Store(str(path)), Store(str(path))    # another run opened what this one made
    assert s.made and not other.made
    assert s.discard() is False and path.exists()
    run = other.begin_run("show", ["-sC", "show version"], "u", 1, "1.0.0")
    other.add_entry(run, SHOW, "show version")
    other.close()
    assert [r["device"] for r in rows(path, "SELECT device FROM results")] == ["r1"]
    path.unlink()
    s, other = Store(str(path)), Store(str(path))
    other.begin_run("show", ["-sC", "show version"], "u", 1, "1.0.0")
    other.close()                                    # kept a run and went before this one looked
    assert s.discard() is False and len(rows(path, "SELECT * FROM runs")) == 1
    path.unlink()
    s = Store(str(path))
    s.identity = (0, 0)                              # the file at the name is not the one it opened
    assert s.discard() is False and os.listdir(tmp_path) == ["s.db"]


@pytest.mark.parametrize("where", ["a file in the store's way", "a directory you cannot write in"])
def test_a_store_refused_leaves_no_safety_file_and_no_save_output_directory(tmp_path, monkeypatch, capsys, where):
    """#136 review: with the store opened after them, a store refused left
    the --safety-file, its .lock and an empty --save-output directory
    behind, which the run before #136 did not. The store is opened before
    both again; a run refused after it takes away the store it made."""
    if where == "a directory you cannot write in" and os.geteuid() == 0:
        pytest.skip("root writes anywhere")
    work = tmp_path / "job"
    work.mkdir()
    (work / "plainfile").write_text("")
    monkeypatch.chdir(work)
    calls = []
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: calls.append(1) or "ok")
    if where == "a file in the store's way":
        argv, said = ["--store", "plainfile/x.db", "--save-output", "out", "--safety-file", "gate.json"], "plainfile/x.db"
    else:
        work.chmod(0o500)
        argv, said = ["--save-output", str(tmp_path / "out"), "--safety-file", str(tmp_path / "gate.json")], "h-ssh.db"
    try:
        rc, out, err = run_cli(monkeypatch, capsys, [*argv, "R1:10.0.0.1:junos", "-sC", "show version"], fake=fake)
    finally:
        work.chmod(0o700)
    assert rc == 2 and f"ERROR: store {said}" in err and calls == []
    assert os.listdir(work) == ["plainfile"] and os.listdir(tmp_path) == ["job"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes anywhere")
def test_a_directory_you_cannot_write_in_is_no_run(tmp_path, monkeypatch, capsys):
    """The user's rule: not being able to store is a no-go for the run."""
    ro = tmp_path / "ro"
    ro.mkdir(mode=0o500)
    monkeypatch.chdir(ro)
    monkeypatch.delenv("HSSH_STORE", raising=False)
    calls = []
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: calls.append(1) or "ok")
    rc, out, err = run_cli(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version"], fake=fake)
    assert rc == 2 and "h-ssh.db" in err and "every run is kept" in err and calls == []
    rc, out, err = run_cli(monkeypatch, capsys, ["--no-store", "--target", "R1:10.0.0.1:junos", "-sC", "show version"], fake=fake)
    assert rc == 0 and calls == [1]


def test_a_dry_run_edit_stores_the_payload_and_the_verdict(tmp_path, monkeypatch, capsys):
    path = tmp_path / "runs.db"
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "",
                                 edit=lambda *a, **kw: "DRY-RUN\n\nDIFF:\n[edit system]\n+  host-name x;\n")
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(path), "--target", "R1:10.0.0.1:junos", "-y",
                                                 "--dry-run", "-eC", "set system host-name x"], fake=fake)
    assert rc == 0, err
    got = rows(path, "SELECT * FROM results")[0]
    assert got["command"] == "set system host-name x" and got["ok"] == 1
    assert "+  host-name x;" in got["output"]
    run = rows(path, "SELECT * FROM runs")[0]
    assert run["mode"] == "edit-cmd" and run["command"] == "set system host-name x" and "--dry-run" in run["argv"]
