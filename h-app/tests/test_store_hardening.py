"""The store under load and under misfortune: two runs creating one file at
the same instant, the cost of a row, a store that fills or disappears
mid-run (said, counted, exit 4, never silent), and the workers hint."""

import json
import re
import multiprocessing
import os
import sqlite3
import time

import pytest

from hssh import store as S
from hssh.store import Store
from tests.test_store import BATCH, FAILED, SHOW, rows, run_cli


def _racer(path, barrier, q):
    barrier.wait(30)
    try:
        st = Store(path)
        run = st.begin_run("show", ["race"], "u", 20, "0")
        for i in range(20):
            st.add(run, f"d{i}", 0, "show version", True, 1, None, "o")
        st.finish_run(run, 20, 0, 0)
        st.close()
        q.put("ok")
    except Exception as e:                       # pragma: no cover - the failure we are testing against
        q.put(f"{type(e).__name__}: {e}")


def test_two_runs_creating_a_fresh_store_at_the_same_instant_both_start(tmp_path):
    """Switching a new file to WAL takes an exclusive lock SQLite does not wait
    for; one of two simultaneous first runs used to refuse to start with
    'database is locked' (half the time, live). Now the second waits it out."""
    ctx = multiprocessing.get_context("spawn")      # not fork: this process has threads (the pool reaper)
    for trial in range(8):
        path = str(tmp_path / f"race{trial}.db")
        barrier, q = ctx.Barrier(2), ctx.Queue()
        procs = [ctx.Process(target=_racer, args=(path, barrier, q), daemon=True) for _ in range(2)]
        for p in procs:
            p.start()
        outcomes = [q.get(timeout=30) for _ in procs]
        for p in procs:
            p.join(30)
        assert outcomes == ["ok", "ok"], (trial, outcomes)
        assert rows(path, "SELECT COUNT(*) AS n FROM runs")[0]["n"] == 2
        assert rows(path, "SELECT COUNT(*) AS n FROM results")[0]["n"] == 40


class _Conn:
    """A connection whose WAL switch is locked the first `locked` times."""

    def __init__(self, mode="delete", locked=0):
        self.mode, self.locked, self.switches = mode, locked, 0

    def execute(self, sql):
        if sql == "PRAGMA journal_mode":
            return _Row(self.mode)
        assert sql == "PRAGMA journal_mode=WAL"
        self.switches += 1
        if self.switches <= self.locked:
            raise sqlite3.OperationalError("database is locked")
        self.mode = "wal"
        return _Row("wal")


class _Row:
    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return (self.value,)


def test_the_wal_switch_waits_out_a_lock_and_gives_up_after_the_timeout():
    c = _Conn(locked=2)
    S._wal(c)
    assert c.mode == "wal" and c.switches == 3                 # two refusals waited out, the third went through
    c = _Conn(mode="wal")
    S._wal(c)
    assert c.switches == 0                                     # already WAL: nothing to switch, no lock taken
    c = _Conn(locked=10 ** 6)
    t = time.monotonic()
    with pytest.raises(sqlite3.OperationalError):
        S._wal(c, timeout=0.1)
    assert 0.1 <= time.monotonic() - t < 2.0                   # gives up on the clock, not after N tries
    c = _Conn(locked=1)
    c.execute = lambda sql: (_ for _ in ()).throw(sqlite3.OperationalError("disk I/O error")) if "=" in sql else _Row("delete")
    with pytest.raises(sqlite3.OperationalError):
        S._wal(c)                                              # another error is not waited out


def test_synchronous_normal_and_one_commit_per_device_result(tmp_path):
    st = Store(str(tmp_path / "s.db"))
    assert st.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert st.conn.execute("PRAGMA synchronous").fetchone()[0] == 1          # NORMAL
    statements = []
    st.conn.set_trace_callback(statements.append)
    run = st.begin_run("show-batch", ["b"], "u", 1, "0")
    statements.clear()
    assert st.add_entry(run, BATCH, "") == 2                                   # two command rows
    assert sum(1 for s in statements if s.upper().startswith("COMMIT")) == 1  # one transaction for the device
    run2 = st.begin_run("show", ["s"], "u", 1, "0")                           # same device, another run
    statements.clear()
    st.add_entry(run2, SHOW, "show version")
    assert sum(1 for s in statements if s.upper().startswith("COMMIT")) == 1
    st.close()
    assert rows(tmp_path / "s.db", "SELECT COUNT(*) AS n FROM results")[0]["n"] == 3


def _three(extra=()):
    return ["--target", "R1:10.0.0.1:junos", "--target", "R2:10.0.0.2:junos", "--target", "R3:10.0.0.3:junos",
            "-sC", "show version", *extra]


def _summary(err):
    return json.loads([ln for ln in err.splitlines() if ln.startswith("[h-ssh] {")][-1][len("[h-ssh] "):])


def test_a_store_that_fails_mid_run_is_said_counted_and_exit_4(tmp_path, monkeypatch, capsys):
    """The disk fills after the first result. The run goes on and every reply
    is still shown; the loss is said once as it happens, counted at the end
    with the reason, put in the summary line, and the exit code is 4."""
    db = tmp_path / "full.db"
    calls = []
    real = Store.add_entry

    def failing(self, *a, **kw):
        calls.append(1)
        if len(calls) >= 2:
            raise sqlite3.OperationalError("database or disk is full")
        return real(self, *a, **kw)

    monkeypatch.setattr(Store, "add_entry", failing)
    rc, out, err = run_cli(monkeypatch, capsys, _three(["--store", str(db)]))
    assert rc == 4
    assert len(re.findall(r"R\d\s+OK$", out, re.M)) == 3                  # the devices' replies were shown
    assert "WARNING: store" in err and "database or disk is full" in err
    assert "2 of 3 results were not kept: database or disk is full" in err
    assert _summary(err)["not_kept"] == 2 and _summary(err)["ok"] == 3
    assert rows(db, "SELECT COUNT(*) AS n FROM results")[0]["n"] == 1    # what was kept is kept
    assert rows(db, "SELECT finished FROM runs")[0]["finished"]           # and the run row is closed


def test_a_store_deleted_during_the_run_is_said_not_silently_lost(tmp_path, monkeypatch, capsys):
    """SQLite keeps writing to a deleted file as if nothing happened and the
    run used to exit 0 with nothing on disk. The run now checks the file is
    still the one it opened and says what happened: exit 4."""
    import types
    db = tmp_path / "gone.db"

    def show(host, user, passwd, cmd, *a, **kw):
        if host == "10.0.0.2":
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(str(db) + suffix)
                except FileNotFoundError:
                    pass
        return f"Hostname: {host}\n"

    fake = types.SimpleNamespace(AVAILABLE=True, show=show)
    rc, out, err = run_cli(monkeypatch, capsys, _three(["--store", str(db), "--workers", "1"]), fake=fake)
    assert rc == 4
    assert len(re.findall(r"R\d\s+OK$", out, re.M)) == 3
    assert "3 of 3 results were not kept: the store file was deleted during the run" in err
    assert err.index("the store file was deleted during the run; the run goes on") < err.index("[h-ssh] {")   # said as it happened
    assert _summary(err)["not_kept"] == 3
    assert not db.exists()


def test_a_store_opened_by_a_relative_path_is_still_itself_after_a_chdir(tmp_path, monkeypatch):
    """still_there() stat'ed the path as given, so a library script that opened
    Store("h-ssh.db") and chdir'ed later was told the file was deleted: every
    result not kept, the run row left open, the file untouched. The store
    looks the file up in the directory it held open at the open; messages
    keep the path as given."""
    monkeypatch.chdir(tmp_path)
    st = Store("h-ssh.db")
    run = st.begin_run("show", ["t"], "u", 1, "0")
    (tmp_path / "elsewhere").mkdir()
    monkeypatch.chdir(tmp_path / "elsewhere")
    assert st.still_there() is None and st.path == "h-ssh.db"
    st.add_entry(run, SHOW, "show version")
    st.finish_run(run, 1, 0, 0)
    assert rows(tmp_path / "h-ssh.db", "SELECT finished FROM runs")[0]["finished"]
    os.unlink(tmp_path / "h-ssh.db")                                # a real deletion is still seen from here
    assert st.still_there() == "the store file was deleted during the run"
    st.close()


def test_a_dot_dot_after_a_symlinked_directory_is_the_file_sqlite_opened(tmp_path, monkeypatch, capsys):
    """abspath() takes `link/..` away as text, where the kernel and SQLite go
    up from wherever the link leads: the identity was bound to a file that
    was not there, and a run that kept its row in real/x.db said the store
    had been deleted (exit 4, the run row left open). The directory is
    opened and made as the path names it, not normalised, so it is the one
    the kernel and SQLite went to."""
    (tmp_path / "real" / "sub").mkdir(parents=True)
    (tmp_path / "link").symlink_to(tmp_path / "real" / "sub")
    monkeypatch.chdir(tmp_path)
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", "link/../x.db", "--target", "R1:10.0.0.1:junos",
                                                 "-sC", "show version"])
    assert rc == 0 and "WARNING" not in err, err
    run, = rows(tmp_path / "real" / "x.db", "SELECT * FROM runs")
    assert run["finished"] is not None and len(rows(tmp_path / "real" / "x.db", "SELECT * FROM results")) == 1
    assert not (tmp_path / "x.db").exists()
    st = Store("link/../new/y.db")
    assert st.still_there() is None and (tmp_path / "real" / "new" / "y.db").is_file()
    assert not (tmp_path / "new").exists()
    st.close()


def test_a_job_directory_renamed_during_the_run_is_not_a_lost_store(tmp_path, monkeypatch, capsys):
    """The identity was bound to a path string, so `mv customer-x
    customer-x-done` while a run was in flight read as a deletion: exit 4,
    every result not kept, the run row left open, with every row in
    customer-x-done/h-ssh.db. The store holds its directory open and looks
    the file up in it by name: a rename above it loses nothing, and a
    deletion or a replacement is still said."""
    import types
    job = tmp_path / "customer-x"
    job.mkdir()
    monkeypatch.chdir(job)

    def show(host, *a, **kw):
        if job.exists():
            job.rename(tmp_path / "customer-x-done")
        return f"Hostname: {host}\n"

    rc, out, err = run_cli(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version"],
                           fake=types.SimpleNamespace(AVAILABLE=True, show=show))
    assert rc == 0 and "WARNING" not in err, err
    db = tmp_path / "customer-x-done" / "h-ssh.db"
    run, = rows(db, "SELECT * FROM runs")
    assert run["finished"] is not None and len(rows(db, "SELECT * FROM results")) == 1
    st = Store(str(tmp_path / "customer-x-done" / "lib.db"))          # an absolute path: the same
    archived = tmp_path / "archived"
    (tmp_path / "customer-x-done").rename(archived)
    assert st.still_there() is None
    os.replace(archived / "h-ssh.db", archived / "lib.db")             # another file in its place
    assert st.still_there() == "the store file was replaced during the run"
    os.unlink(archived / "lib.db")
    assert st.still_there() == "the store file was deleted during the run"
    st.close()


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="names the open files through /proc")
def test_a_store_lets_go_of_the_directory_it_holds_when_closed_or_dropped(tmp_path):
    """still_there() looks the file up in its directory, which the store
    holds open. A watch opens a store every tick: close() lets the directory
    go (asked again, a closed store looks by the path, not through a dead fd),
    and so does a store a script drops without closing it."""
    import gc
    here = os.path.realpath(tmp_path)

    def held():                                          # what this process has open under tmp_path
        names = []
        for fd in os.listdir("/proc/self/fd"):
            try:
                names.append(os.readlink(f"/proc/self/fd/{fd}"))
            except OSError:
                pass
        return sorted(n for n in names if n == here or n.startswith(here + os.sep))

    gc.collect()
    stores = [Store(str(tmp_path / f"s{i}.db")) for i in range(3)]
    assert held().count(here) == 3                       # each store holds the directory
    for st in stores:
        st.close()
    assert held() == []                                  # still referenced: close() let go
    assert [st.still_there() for st in stores] == [None] * 3          # asked after: by the path, not a dead fd
    st = Store(str(tmp_path / "dropped.db"))
    st.conn.close()
    assert held() == [here]
    del st, stores
    gc.collect()
    assert held() == []


@pytest.mark.parametrize("first", ["close", "discard"])
def test_a_store_closed_twice_lets_go_of_its_directory_once(tmp_path, first):
    """#180: main() closes the store it opened when it returns, on most
    paths after the run's own close() or discard(). The first lets the
    directory go; by the second, its fd number may be another file's (here
    the directory opened again, at that number), which stays open."""
    st = Store(str(tmp_path / "s.db"))
    fd = st._where[1]
    getattr(st, first)()
    other = os.open(tmp_path, os.O_RDONLY)
    os.dup2(other, fd)                                   # the number the store let go is another file's now
    os.close(other)
    st.close()
    os.fstat(fd)                                         # still open: the second close let go of nothing
    os.close(fd)


def test_a_store_in_a_directory_that_was_removed_is_refused_with_the_reason(tmp_path, monkeypatch, capsys):
    """A reader started in a directory that was removed met a traceback (the
    current directory asked for before the file was looked for) where it
    says no run is kept there, and a run started there was a traceback too.
    Both say why instead: the reader's `no store at`, the run's exit 2 with
    nothing sent."""
    import types
    from hssh import core
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()
    monkeypatch.delenv("HSSH_STORE", raising=False)
    monkeypatch.setattr(core, "get_config_path", lambda: tmp_path / "no-config")
    assert S.main(["runs"]) == 2
    assert "no store at h-ssh.db: no run has been kept here" in capsys.readouterr()[1]
    sent = []
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: sent.append(a) or "x")
    rc, out, err = run_cli(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version"], fake=fake)
    assert rc == 2 and "ERROR: store h-ssh.db: No such file or directory; " in err and sent == []


def test_a_device_failure_and_a_store_loss_both_show_and_exit_4(tmp_path, monkeypatch, capsys):
    import types
    db = tmp_path / "both.db"
    monkeypatch.setattr(Store, "add_entry", lambda self, *a, **kw: (_ for _ in ()).throw(sqlite3.OperationalError("disk I/O error")))

    def show(host, user, passwd, cmd, *a, **kw):
        if host == "10.0.0.2":
            raise RuntimeError("connect timed out")
        return "ok"

    rc, out, err = run_cli(monkeypatch, capsys, _three(["--store", str(db), "--retries", "0"]),
                           fake=types.SimpleNamespace(AVAILABLE=True, show=show))
    s = _summary(err)
    assert rc == 4 and s["fail"] == 1 and s["not_kept"] == 3
    assert "3 of 3 results were not kept: disk I/O error" in err


def test_the_banner_hints_at_more_workers_for_a_big_fleet(tmp_path, monkeypatch, capsys):
    targets = [x for i in range(1, 41) for x in ("--target", f"R{i}:10.0.0.{i}:junos")]
    rc, out, err = run_cli(monkeypatch, capsys, [*targets, "-sC", "show version", "--store", str(tmp_path / "h.db")])
    assert rc == 0
    assert "Hint: 40 devices at 8 workers is 5 waves; --workers 64 would be 1 (one session per router either way)" in out
    rc, out, err = run_cli(monkeypatch, capsys, [*targets, "-sC", "show version", "--workers", "40", "--store", str(tmp_path / "h.db")])
    assert rc == 0 and "Hint:" not in out
    big = [x for i in range(1, 251) for x in ("--target", f"R{i}:10.1.{i // 256}.{i % 256}:junos")]
    rc, out, err = run_cli(monkeypatch, capsys, [*big, "-sC", "show version", "--workers", "64", "--store", str(tmp_path / "h.db")])
    assert rc == 0 and "Hint:" not in out                     # 4 waves at 64: nothing more to suggest


def test_the_hint_counts_a_device_once_however_its_port_is_written(tmp_path, monkeypatch, capsys):
    """#110 review: a job may name a device with its port and without it (one
    router since #110); the hint counted the port as typed, so twice."""
    jobs = [{"target": f"R{i}:10.0.0.{i}{port}:junos", "show": "show version"} for i in range(1, 6) for port in ("", ":830")]
    job = tmp_path / "job.json"
    job.write_text(json.dumps(jobs))
    rc, out, err = run_cli(monkeypatch, capsys, ["--job", str(job), "--workers", "1", "--store", str(tmp_path / "h.db")])
    assert rc == 0, err
    assert "Hint: 5 devices at 1 workers is 5 waves; --workers 64 would be 1 (one session per router either way)" in out


def test_a_store_may_be_written_from_another_thread_than_the_one_that_opened_it(tmp_path):
    """A library caller opens the store where it builds the fleet and writes it
    from the thread that consumes the results. One writer at a time is still
    the rule; the thread need not be the opening one."""
    import threading
    st = Store(str(tmp_path / "t.db"))
    run = st.begin_run("show", ["t"], "u", 2, "0")
    errors = []

    def writer():
        try:
            st.add_entry(run, FAILED, "show version")            # r2's failure, r1's two batch rows
            st.add_entry(run, BATCH, "")
        except Exception as e:                       # pragma: no cover - the failure we are testing against
            errors.append(e)

    th = threading.Thread(target=writer)
    th.start()
    th.join(10)
    st.finish_run(run, 2, 0, 0)
    st.close()
    assert errors == []
    assert rows(tmp_path / "t.db", "SELECT COUNT(*) AS n FROM results")[0]["n"] == 3
