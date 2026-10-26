"""The result store: every command's reply, as it came back, in one SQLite file.

Every run is kept. The store is h-ssh.db in the directory h-ssh runs from,
unless --store PATH, HSSH_STORE or `store = PATH` in ~/.h-ssh/config says
another file; --no-store skips it for one run. A store that cannot be
written is no run: it is opened before the first device is touched. One
row per command per device: who ran what, when, against which device,
whether it worked, how long it took, and the device's own reply, byte for
byte. A snapshot one may have to restore from is kept as it came: nothing
is redacted, parsed, normalised or modelled. The store holds output, and
what is done with it is the reader's business (`h-ssh-store`, or any
sqlite3 client). One file serves many runs, and replaces a directory of
--save-output files.

Two tables. `runs`: one row per h-ssh invocation (run_id, when it started
and finished, the mode, the command line, who ran it, the counts).
`results`: one row per command on one device, unique on (run_id, device,
seq): a show is seq 0, a batch is seq 0..n-1 in the batch's order, an edit
is seq 0 with the payload as the command and the device's verdict (the diff,
or the commit line) as the output; a job that names one device in several
entries gives them seq 0, 1, ... in file order. `format` says what the output
is: text, xml or json as the device was asked for; a commit history is json.
"""

import argparse
import csv
import datetime as _dt
import difflib
import json
import os
import pathlib
import random
import re
import secrets
import sqlite3
import stat
import sys
import threading
import time
import weakref
from typing import Iterable, Iterator, List, Optional

from .screen import is_terminal, terminal_safe

ENV_VAR = "HSSH_STORE"
DEFAULT = "h-ssh.db"          # in the directory h-ssh runs from: the evidence sits with the job
CONFIG_KEY = "store"          # `store = PATH` in ~/.h-ssh/config
BUSY_TIMEOUT = 10.0           # seconds a write waits for another h-ssh writing the same file
WAL_SWITCH_TIMEOUT = 5.0      # seconds the first run on a new file may wait to switch it to WAL


def where(flag: Optional[str] = None, config: Optional[dict] = None) -> str:
    """The store a run writes and the reader reads: --store, else HSSH_STORE,
    else the config file's `store`, else h-ssh.db in the current directory.
    A leading `~` is the home directory in each of them."""
    return os.path.expanduser(flag or os.environ.get(ENV_VAR) or (config or {}).get(CONFIG_KEY) or DEFAULT)

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id     TEXT PRIMARY KEY,
    started    TEXT NOT NULL,
    finished   TEXT,
    mode       TEXT NOT NULL,
    command    TEXT,
    argv       TEXT NOT NULL,
    user       TEXT,
    origin     TEXT,
    version    TEXT,
    targets    INTEGER,
    ok         INTEGER,
    failed     INTEGER,
    skipped    INTEGER,
    interrupted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS results (
    run_id      TEXT NOT NULL REFERENCES runs(run_id),
    device      TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    host        TEXT,
    vendor      TEXT,
    command     TEXT NOT NULL,
    ts          TEXT NOT NULL,
    ok          INTEGER NOT NULL,
    duration_ms INTEGER,
    error       TEXT,
    format      TEXT NOT NULL DEFAULT 'text',
    output      TEXT,
    PRIMARY KEY (run_id, device, seq)
);
CREATE INDEX IF NOT EXISTS results_device ON results(device, ts);
CREATE INDEX IF NOT EXISTS results_command ON results(command);
"""


def _identity(path: str, dir_fd: Optional[int] = None):
    """What makes the file at `path` this file: device and inode; None if nothing is there.
    With `dir_fd`, `path` is a name in that directory."""
    try:
        st = os.stat(path, dir_fd=dir_fd)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


# A directory held for still_there(). O_PATH (Linux) needs no read permission
# on it, only the search permission the path to the file needs anyway.
_DIRECTORY = getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_DIRECTORY", 0)


def _hold_directory(path: str):
    """(the file's name, an fd on the directory `path` names it in): what the
    file is looked up by. (path, None) when the directory cannot be opened:
    the file is then looked up by the path as given."""
    try:
        return os.path.basename(path), os.open(os.path.dirname(path) or ".", _DIRECTORY)
    except OSError:
        return path, None


def _let_go(fd: Optional[int]) -> None:
    if fd is not None:
        os.close(fd)


def _waiting(path: str) -> Optional[str]:
    """What waits beside the store at `path` that SQLite would apply first:
    a crashed transaction's "-journal", or a "-wal" with committed rows not
    yet in the file (the empty one a reader leaves is nothing). None when
    the file is the whole store."""
    if os.path.lexists(path + "-journal"):
        return "-journal"
    try:
        return "-wal" if os.path.getsize(path + "-wal") else None
    except OSError:
        return None


def _settled(path: str):
    """The file at `path` as it stands (device, inode, size, mtime) when it
    is the whole store; None when something waits beside it."""
    if _waiting(path):
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _no_shm(e: sqlite3.Error) -> bool:
    """The read-only open failed for want of a -shm beside the store: a
    directory the reader cannot write to does not let SQLite make one
    (SQLITE_READONLY_DIRECTORY; SQLITE_CANTOPEN beside the empty -wal a
    reader left). Python 3.10 gives the message only."""
    name = getattr(e, "sqlite_errorname", None)
    if name is not None:
        return name in ("SQLITE_READONLY_DIRECTORY", "SQLITE_CANTOPEN")
    text = str(e).lower()
    return "readonly" in text or "unable to open" in text


def _wal(conn, timeout: float = WAL_SWITCH_TIMEOUT) -> None:
    """Put the file in WAL mode, once. Switching needs an exclusive lock and
    SQLite does not wait for it (no busy handler for this pragma), so two
    runs creating the same store at the same instant raced and one refused
    to start with 'database is locked'. A file already in WAL mode needs
    nothing; a fresh one is switched, waiting out the other run."""
    if str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal":
        return
    deadline = time.monotonic() + timeout
    while True:
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError as e:
            if "locked" not in str(e).lower() or time.monotonic() >= deadline:
                raise
            time.sleep(0.005 + random.random() * 0.03)


def _now() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def new_run_id(now: Optional[_dt.datetime] = None) -> str:
    """When the run started plus four hex digits: sortable, and two runs
    started in the same second stay apart."""
    now = now or _dt.datetime.now()
    return now.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


class StoreError(Exception):
    """The store file cannot be used: the message says why, for the operator."""


class Store:
    """One SQLite file, opened for writing by the run and for reading by
    `h-ssh-store`. The file is created 0600, as --log's is: it holds
    replies, diffs and payloads as the devices gave them."""

    def __init__(self, path: str, readonly: bool = False):
        self.path = path
        self._as_is = None          # (file, what it was) for a store read as it is
        if readonly:
            if not os.path.exists(path):
                raise StoreError(f"no store at {path}: no run has been kept here "
                                 f"(--store PATH or {ENV_VAR} for another file)")
            try:
                self.conn = self._open_readonly(str(pathlib.Path(path).resolve()))
            except sqlite3.Error as e:
                raise StoreError(f"{path}: {e}") from e
        else:
            self._create_private(path)
            try:
                # Not pinned to the opening thread: a library caller may open a
                # store here and write it from the thread that consumes the results,
                # or hand one Store to several Fleets on several threads. One
                # connection takes one transaction at a time (two threads inside
                # it at once lose rows, or worse: "bad parameter or other API
                # misuse"), so every write below is one transaction under _writing.
                self.conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT, check_same_thread=False)
                _wal(self.conn)
                # WAL with synchronous=NORMAL: every commit is safe against the
                # process dying, the file never corrupts, and only a power cut
                # can lose the last commits. FULL fsynced every row: 1.2 ms a
                # row, a tenth of that now, and a fleet run writes thousands.
                self.conn.execute("PRAGMA synchronous=NORMAL")
                self.conn.executescript(SCHEMA)
                self.conn.commit()
            except sqlite3.Error as e:
                raise StoreError(f"{path}: {e}") from e
        self.conn.row_factory = sqlite3.Row
        # The file is looked up by its name in its directory, which is held
        # open from here: a library script that chdirs, a `..` after a
        # symlinked directory and a job directory renamed during the run all
        # still lead to the file SQLite opened; a path string would not.
        # Messages keep the path as given.
        self._where = _hold_directory(path)
        self._release_dir = weakref.finalize(self, _let_go, self._where[1])
        self.identity = _identity(*self._where)
        self._writing = threading.Lock()

    def still_there(self) -> Optional[str]:
        """None while the file this store opened is still where it was opened
        (its name in its directory), else why not. SQLite goes on writing to a
        deleted or replaced file without a word, so a run asks before it says
        its results are kept."""
        now = _identity(*self._where)
        if now is None:
            return "the store file was deleted during the run"
        if now != self.identity:
            return "the store file was replaced during the run"
        return None

    def written_while_read(self) -> bool:
        """A store read as it is has neither locks nor a snapshot: a writer
        that came meanwhile (a run, an --every tick, a cleanup) moves pages
        under the reader, which then misses or repeats rows without an
        error. True when the file is no longer what it was at the open, or
        has WAL frames or a journal beside it now. A store read the usual
        way is SQLite's to keep consistent: always False."""
        if self._as_is is None:
            return False
        resolved, then = self._as_is
        return _settled(resolved) != then

    @staticmethod
    def _create_private(path: str) -> None:
        """The file is made 0600 before SQLite ever opens it, and must be a
        regular file (no following a planted symlink into another file). Its
        directory is made from the path as given, not normalised: abspath()
        takes `link/..` away as text, where the kernel (and SQLite) go up from
        wherever the link leads."""
        directory = os.path.dirname(path)
        try:
            if directory:
                os.makedirs(directory, mode=0o700, exist_ok=True)
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags, 0o600)
        except OSError as e:
            raise StoreError(f"{path}: {e.strerror or e}") from e
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise StoreError(f"{path}: not a regular file")
        finally:
            os.close(fd)

    def _open_readonly(self, resolved: str) -> sqlite3.Connection:
        """The reader never writes the store, but a WAL reader wants a -shm
        file beside it, and a directory the reader cannot write to (an
        archived job directory, a read-only mount, another user's) does not
        let it make one: 'attempt to write a readonly database' at the first
        read. With nothing waiting beside it (_settled), the file is the
        whole store and is read as it is (immutable): no -shm, and no locks
        either, so written_while_read() looks again at the end. WAL frames
        or a journal beside it keep the error (a -wal's says what to do):
        read past them, the store would miss committed rows or show
        uncommitted ones. SQLite looks beside the file itself, so
        `resolved` has its symlinks followed."""
        uri = pathlib.Path(resolved).as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        try:
            conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
            return conn
        except sqlite3.Error as e:
            conn.close()
            if not _no_shm(e):
                raise
            if _waiting(resolved) == "-wal":
                # A run killed before its rows left the -wal, archived without the -shm.
                raise StoreError(f"{self.path}: {e} (its -wal holds rows not yet in the file, and SQLite "
                                 "reads them only in a directory it can write to: copy the store with "
                                 "its -wal to one you can)") from e
            then = _settled(resolved)
            if then is None:
                raise
            self._as_is = (resolved, then)
            return sqlite3.connect(uri + "&immutable=1", uri=True)

    def close(self) -> None:
        """Closed once the write under way, if any, has committed."""
        with self._writing:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass
        self._where = (self.path, None)         # once closed, the fd's number may be another file's
        self._release_dir()

    # --- writing ------------------------------------------------------------

    def begin_run(self, mode: str, argv: List[str], user: Optional[str], targets: int,
                  version: str, origin: Optional[str] = None, command: Optional[str] = None,
                  run_id: Optional[str] = None) -> str:
        """Record that a run started; its row is completed by finish_run().
        `command` is what the run was about (the show, the batch, the edit);
        `argv` the command line as typed."""
        # The id's four hex digits keep two runs of the same second apart
        # almost always; when they do not (one in 65536), take another id
        # rather than fail the run. An id the caller chose is theirs to keep
        # unique, so that one is not replaced.
        for attempt in range(8):
            candidate = run_id or new_run_id()
            try:
                with self._writing, self.conn:
                    self.conn.execute(
                        "INSERT INTO runs (run_id, started, mode, command, argv, user, origin, version, targets) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (candidate, _now(), mode, command, " ".join(argv), user, origin, version, targets))
            except sqlite3.IntegrityError:
                if run_id is not None or attempt == 7:
                    raise
                continue
            return candidate
        raise AssertionError("unreachable")

    def add(self, run_id: str, device: str, seq: int, command: str, ok: bool,
            duration_ms: Optional[int] = None, error: Optional[str] = None,
            output: Optional[str] = None, fmt: str = "text", host: Optional[str] = None,
            vendor: Optional[str] = None, ts: Optional[str] = None) -> None:
        """One command's row, committed. A second result for the same (run,
        device, seq) replaces the first: a retry's verdict is the one that
        stands."""
        with self._writing, self.conn:
            self._row(run_id, device, seq, command, ok, duration_ms, error, output, fmt, host, vendor, ts)

    def _row(self, run_id, device, seq, command, ok, duration_ms, error, output, fmt, host, vendor, ts=None) -> None:
        """One row inside the caller's transaction."""
        self.conn.execute(
            "INSERT OR REPLACE INTO results (run_id, device, seq, host, vendor, command, ts, ok, "
            "duration_ms, error, format, output) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, device, seq, host, vendor, command, ts or _now(), 1 if ok else 0,
             duration_ms, error, fmt, output))

    def add_entry(self, run_id: str, entry: dict, command: str, fmt: str = "text", seq: int = 0) -> int:
        """The rows of one device's result as the CLI builds it (`entry`: the
        --json record): a batch is one row per command in its order; anything
        else one row, with `command` what was sent (the resolved show, the
        edit payload, `rollback N`, `show system commit`) and the output the
        reply, the diff, or the commit history as JSON. `seq` is the first
        row's (a batch's commands follow at seq + 1, ...): 0, or in a job that
        names one device in several entries, the entry's place among them,
        which is enough because a job entry is one row (a show or an edit).
        One transaction per device result, however many rows. Returns the
        rows written."""
        device, host, vendor = entry["device"], entry.get("host"), entry.get("vendor")
        duration = entry.get("duration_ms")
        with self._writing, self.conn:
            if "commands" in entry and isinstance(entry["commands"], list) and entry["commands"]:
                for i, cr in enumerate(entry["commands"]):
                    out = cr.get("output")
                    self._row(run_id, device, seq + i, cr.get("command", ""), bool(cr.get("ok")),
                              duration if i == 0 else None, cr.get("error"),
                              out if isinstance(out, str) or out is None else json.dumps(out),
                              fmt if isinstance(out, str) else "json", host, vendor)
                return len(entry["commands"])
            if "commits" in entry:
                output = json.dumps(entry["commits"]) if entry.get("ok") else None
                self._row(run_id, device, seq, command, bool(entry.get("ok")), duration, entry.get("error"),
                          output, "json", host, vendor)
                return 1
            output = entry.get("output")
            if output is not None and not isinstance(output, str):
                output, fmt = json.dumps(output), "json"
            self._row(run_id, device, seq, command, bool(entry.get("ok")), duration, entry.get("error"),
                      output, fmt, host, vendor)
            return 1

    def finish_run(self, run_id: str, ok: int, failed: int, skipped: int, interrupted: bool = False) -> None:
        with self._writing, self.conn:
            self.conn.execute(
                "UPDATE runs SET finished = ?, ok = ?, failed = ?, skipped = ?, interrupted = ? WHERE run_id = ?",
                (_now(), ok, failed, skipped, 1 if interrupted else 0, run_id))

    # --- reading ------------------------------------------------------------

    # Newest first by the instant: `started` carries its UTC offset, and across
    # a DST fall-back the local-time strings (and the run ids made of them)
    # sort the wrong way round. The ids stay as they are; the order is not theirs.
    NEWEST_FIRST = "datetime(started) DESC, rowid DESC"

    def runs(self, last: int = 20) -> List[sqlite3.Row]:
        return self.conn.execute(f"SELECT * FROM runs ORDER BY {self.NEWEST_FIRST} LIMIT ?",
                                 (last,)).fetchall()

    def last_run_id(self) -> Optional[str]:
        row = self.conn.execute(f"SELECT run_id FROM runs ORDER BY {self.NEWEST_FIRST} LIMIT 1").fetchone()
        return row["run_id"] if row else None

    def resolve_run(self, run: Optional[str]) -> str:
        """A run id as typed, a unique prefix of one, or the last run when
        none is given."""
        if not run:
            found = self.last_run_id()
            if not found:
                raise StoreError("the store holds no runs")
            return found
        rows = self.conn.execute("SELECT run_id FROM runs WHERE run_id = ? OR run_id LIKE ? "
                                 "ORDER BY run_id", (run, run + "%")).fetchall()
        exact = [r["run_id"] for r in rows if r["run_id"] == run]
        if exact:
            return exact[0]
        if len(rows) == 1:
            return rows[0]["run_id"]
        if not rows:
            raise StoreError(f"no run {run!r}")
        raise StoreError(f"{run!r} matches {len(rows)} runs: " + ", ".join(r["run_id"] for r in rows[:6]))

    def results(self, run_id: Optional[str] = None, device: Optional[str] = None,
                command: Optional[str] = None, ok: Optional[bool] = None,
                order: str = "run_id, device, seq", limit: Optional[int] = None) -> Iterator[sqlite3.Row]:
        """The matching rows in order, as the cursor: a row is read when it
        is asked for, so grep, field and export hold one row at a time,
        not the store. A cursor is read once, has no len() and is always
        true: list() it to keep the rows."""
        where, params = [], []
        if run_id:
            where.append("run_id = ?")
            params.append(run_id)
        if device:
            where.append("device = ?")
            params.append(device)
        if command:
            where.append("command = ?")
            params.append(command)
        if ok is not None:
            where.append("ok = ?")
            params.append(1 if ok else 0)
        sql = "SELECT * FROM results"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY {order}"
        if limit:
            sql += " LIMIT %d" % int(limit)
        return self.conn.execute(sql, params)

    def output(self, run_id: str, device: str, seq: int = 0) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM results WHERE run_id = ? AND device = ? AND seq = ?",
                                (run_id, device, seq)).fetchone()
        if row is None:
            raise StoreError(f"no result for {device} seq {seq} in run {run_id}")
        return row


# --- the reader: h-ssh-store -----------------------------------------------------

def _store_path(args) -> str:
    """The reader looks where the run wrote: --store, HSSH_STORE, the config
    file's `store`, else h-ssh.db here."""
    try:
        from .core import load_config
        config = load_config()
    except ValueError:
        config = {}
    return where(args.store, config)


def _shown_on(stream):
    """How the reader prints stored text to `stream`: on a terminal, what the
    terminal would act on is taken out, as h-ssh does with a reply; a pipe or
    a file gets the bytes as they were kept."""
    return terminal_safe if is_terminal(stream) else (lambda text: text)


def _table(rows: Iterable[Iterable[str]], head: Iterable[str]) -> List[str]:
    rows = [tuple(str(c) for c in r) for r in rows]
    head = tuple(head)
    if not rows:
        return ["(nothing)"]
    widths = [max(len(r[i]) for r in rows + [head]) for i in range(len(head) - 1)]
    fmt = "  ".join("{:<%d}" % w for w in widths) + "  {}"
    return [fmt.format(*head)] + [fmt.format(*r) for r in rows]


def _short_cmd(text: str, width: int = 48) -> str:
    first = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    more = (text or "").strip().count("\n")
    if more:
        first += f" (+{more} lines)"
    return first if len(first) <= width else first[:width - 1] + "…"


def cmd_runs(store: Store, args) -> int:
    rows = [(r["run_id"], r["started"][:19], r["mode"], r["user"] or "-",
             f"{r['targets'] or 0}/{r['ok'] if r['ok'] is not None else '?'}/{r['failed'] if r['failed'] is not None else '?'}"
             + ("/int" if r["interrupted"] else ""), _short_cmd(r["command"] or r["argv"], 60))
            for r in store.runs(args.last)]
    print("\n".join(_table(rows, ("run", "started", "mode", "user", "targets/ok/fail", "command"))))
    return 0


def cmd_failed(store: Store, args) -> int:
    run_id = store.resolve_run(args.run)
    shown = _shown_on(sys.stdout)
    rows = [(r["device"], r["seq"], _short_cmd(r["command"]),
             shown((r["error"] or "").strip().splitlines()[0]) if r["error"] else "-")
            for r in store.results(run_id=run_id, ok=False)]
    args.verdict = 1 if rows else 0         # known before a line is out: main() keeps it if the reader leaves
    print(f"run {run_id}: {len(rows)} failed")
    if rows:
        print("\n".join(_table(rows, ("device", "seq", "command", "error"))))
    return args.verdict


def cmd_output(store: Store, args) -> int:
    run_id = store.resolve_run(args.run)
    row = store.output(run_id, args.device, args.seq)
    args.verdict = 0 if row["ok"] else 1
    if row["output"] is not None:
        text = _shown_on(sys.stdout)(row["output"])
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    if not row["ok"]:
        print(f"ERROR: {_shown_on(sys.stderr)(row['error'] or 'failed')}", file=sys.stderr)
    return args.verdict


def cmd_grep(store: Store, args) -> int:
    try:
        pattern = re.compile(args.pattern, re.IGNORECASE if args.ignore_case else 0)
    except re.error as e:
        raise StoreError(f"bad pattern {args.pattern!r}: {e}")
    run_id = store.resolve_run(args.run) if args.run else None
    shown = _shown_on(sys.stdout)
    hits = 0
    for r in store.results(run_id=run_id, device=args.device, command=args.command, ok=True):
        for line in (r["output"] or "").splitlines():
            if pattern.search(line):
                hits += 1
                print(f"{r['run_id']}  {r['device']}  {_short_cmd(r['command'], 32)}: {shown(line.rstrip())}")
    return 0 if hits else 1


def _json_path(value, path: str):
    for key in [k for k in path.split(".") if k]:
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list) and key.lstrip("-").isdigit():
            try:
                value = value[int(key)]
            except IndexError:
                return None
        else:
            return None
    return value


def cmd_field(store: Store, args) -> int:
    """A dotted path into a JSON reply (a `--format json` show, or a commit
    history): the device's own structure, read, not parsed."""
    run_id = store.resolve_run(args.run) if args.run else None
    as_shown = _shown_on(sys.stdout)
    shown = 0
    for r in store.results(run_id=run_id, device=args.device, command=args.command, ok=True):
        if r["format"] != "json" or not r["output"]:
            continue
        try:
            data = json.loads(r["output"])
        except ValueError:
            continue
        value = _json_path(data, args.path)
        if value is None:
            continue
        shown += 1
        text = value if isinstance(value, str) else json.dumps(value)
        print(f"{r['run_id']}  {r['device']}  {args.path} = {as_shown(text)}")
    return 0 if shown else 1


def cmd_diff(store: Store, args) -> int:
    a, b = store.resolve_run(args.run_a), store.resolve_run(args.run_b)
    ra, rb = store.output(a, args.device, args.seq), store.output(b, args.device, args.seq)
    la, lb = (ra["output"] or "").splitlines(keepends=True), (rb["output"] or "").splitlines(keepends=True)
    diff = list(difflib.unified_diff(la, lb, fromfile=f"{args.device} {a}", tofile=f"{args.device} {b}"))
    args.verdict = 1 if diff else 0
    if is_terminal(sys.stdout):
        # What the terminal would act on taken out, and each diff line on a
        # screen line of its own: VT, FF and NEL end a line here and go with
        # the rest, and a reply's last line has no newline of its own.
        diff = [ln if ln.endswith("\n") else ln + "\n" for ln in map(terminal_safe, diff)]
    sys.stdout.writelines(diff)
    if diff and not diff[-1].endswith("\n"):
        print()
    return args.verdict


def cmd_history(store: Store, args) -> int:
    rows = [(r["ts"][:19], r["run_id"], r["seq"], _short_cmd(r["command"]), "OK" if r["ok"] else "FAIL",
             r["duration_ms"] if r["duration_ms"] is not None else "-")
            for r in store.results(device=args.device, command=args.command,
                                   order="datetime(ts) DESC, seq, rowid DESC", limit=args.last)]
    print("\n".join(_table(rows, ("when", "run", "seq", "command", "verdict", "ms"))))
    return 0


def cmd_slowest(store: Store, args) -> int:
    run_id = store.resolve_run(args.run) if args.run else None
    rows = [(r["duration_ms"], r["device"], r["run_id"], _short_cmd(r["command"]), "OK" if r["ok"] else "FAIL")
            for r in store.results(run_id=run_id, order="duration_ms DESC", limit=args.last)
            if r["duration_ms"] is not None]
    print("\n".join(_table(rows, ("ms", "device", "run", "command", "verdict"))))
    return 0


EXPORT_FIELDS = ("run_id", "device", "seq", "host", "vendor", "command", "ts", "ok", "duration_ms",
                 "error", "format", "output")


def _part_of_store(store: Store, out: str) -> Optional[str]:
    """What of the store `out` names, if anything: the file itself (as
    typed, through a symlink or a hard link), or one SQLite keeps beside
    it. Opened for writing, it would empty the store under the reader."""
    try:
        if os.path.samefile(out, store.path):
            return "the store itself"
    except OSError:
        pass                            # nothing at --out yet: a new file, unless named as one beside the store
    real, base = os.path.realpath(out), os.path.realpath(store.path)
    for side in ("-wal", "-shm", "-journal"):
        if real == base + side:
            return f"the store's {side} file"
    return None


def cmd_export(store: Store, args) -> int:
    """The rows as they are, for a spreadsheet or a notebook: CSV (Excel opens
    it; a multi-line reply stays one quoted cell) or JSON Lines, one object a
    row. One run (default: the last) or --all; --out writes a file. Printed
    to a terminal, the text is shown as `output` shows it."""
    part = _part_of_store(store, args.out) if args.out else None
    if part:
        raise StoreError(f"--out {args.out}: that is {part}")
    run_id = None if args.all else store.resolve_run(args.run)
    rows = store.results(run_id=run_id, device=args.device, command=args.command)
    if args.out:
        try:
            out = open(args.out, "w", newline="", encoding="utf-8")
        except OSError as e:
            raise StoreError(f"--out {args.out}: {e.strerror or e}") from e
    else:
        out = sys.stdout
    shown = _shown_on(out)

    def cells(r):
        return [shown(r[f]) if isinstance(r[f], str) else r[f] for f in EXPORT_FIELDS]

    written = 0
    try:
        try:
            if args.format == "csv":
                writer = csv.writer(out)
                writer.writerow(EXPORT_FIELDS)
                for r in rows:
                    writer.writerow(cells(r))
                    written += 1
            else:
                for r in rows:
                    out.write(json.dumps(dict(zip(EXPORT_FIELDS, cells(r))), ensure_ascii=False) + "\n")
                    written += 1
        finally:
            if args.out:
                out.close()             # the rest of the buffer is written here: a full disk may say so only now
    except OSError as e:
        if not args.out:
            raise                       # stdout: a reader that left (`| head`) is main()'s business
        raise StoreError(f"--out {args.out}: {e.strerror or e}") from e
    args.verdict = 0 if written else 1
    if args.out:
        print(f"{written} rows written to {args.out}", file=sys.stderr)
    return args.verdict


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="h-ssh-store",
                                description="Read what h-ssh --store kept: runs, failures, outputs, diffs.")
    p.add_argument("--store", help=f"the SQLite file (default: ${ENV_VAR}, the config file's store, "
                                    f"else ./{DEFAULT})")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("runs", help="the runs in the store, newest first")
    s.add_argument("--last", type=int, default=20)
    s.set_defaults(fn=cmd_runs)
    s = sub.add_parser("failed", help="what failed in a run (default: the last run)")
    s.add_argument("run", nargs="?")
    s.set_defaults(fn=cmd_failed)
    s = sub.add_parser("output", help="one device's reply from a run")
    s.add_argument("device")
    s.add_argument("run", nargs="?", help="run id or a unique prefix; default: the last run")
    s.add_argument("--seq", type=int, default=0, help="which command of a batch, or entry of a job (default 0)")
    s.set_defaults(fn=cmd_output)
    s = sub.add_parser("grep", help="lines of stored output that match a regex")
    s.add_argument("pattern")
    s.add_argument("--run")
    s.add_argument("--device")
    s.add_argument("--command", help="only results of exactly this command")
    s.add_argument("-i", "--ignore-case", action="store_true")
    s.set_defaults(fn=cmd_grep)
    s = sub.add_parser("field", help="a dotted path into JSON replies (--format json shows, commit history)")
    s.add_argument("path")
    s.add_argument("--run")
    s.add_argument("--device")
    s.add_argument("--command")
    s.set_defaults(fn=cmd_field)
    s = sub.add_parser("diff", help="one device's reply in two runs, as a unified diff")
    s.add_argument("device")
    s.add_argument("run_a")
    s.add_argument("run_b")
    s.add_argument("--seq", type=int, default=0, help="which command of a batch, or entry of a job (default 0)")
    s.set_defaults(fn=cmd_diff)
    s = sub.add_parser("history", help="every stored result for a device, newest first")
    s.add_argument("device")
    s.add_argument("--command")
    s.add_argument("--last", type=int, default=50)
    s.set_defaults(fn=cmd_history)
    s = sub.add_parser("slowest", help="the slowest results (of a run, or overall)")
    s.add_argument("run", nargs="?")
    s.add_argument("--last", type=int, default=20)
    s.set_defaults(fn=cmd_slowest)
    s = sub.add_parser("export", help="the rows of a run (default: the last) or of the whole store, as CSV or JSON Lines")
    s.add_argument("run", nargs="?", help="run id or a unique prefix; default: the last run")
    s.add_argument("--all", action="store_true", help="every run in the store")
    s.add_argument("--device")
    s.add_argument("--command", help="only results of exactly this command")
    s.add_argument("--format", choices=("csv", "jsonl"), default="csv")
    s.add_argument("--out", help="write to this file instead of stdout")
    s.set_defaults(fn=cmd_export)
    return p


def _stdout_gone() -> None:
    """The reader of our output closed it (`| head`, also `2>&1 | head`).
    Point both fds at /dev/null so the interpreter's final flush does not
    fail a second time."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        for stream in (sys.stdout, sys.stderr):
            os.dup2(devnull, stream.fileno())
    except (OSError, ValueError, AttributeError):
        pass


def main(argv: Optional[List[str]] = None) -> int:
    """The reader's exit code. A reader of the output that leaves early
    (`h-ssh-store ... | head`) has what it wanted: no traceback, as with
    h-ssh itself, and exit 0, or the verdict the command had before it
    printed (failed, diff, output), whether the pipe closed in the middle
    or only at the final flush."""
    args = build_parser().parse_args(argv)
    try:
        store = Store(_store_path(args), readonly=True)
    except StoreError as e:
        return _error(str(e))
    error = None
    try:
        rc = args.fn(store, args)
    except BrokenPipeError:
        rc = getattr(args, "verdict", 0)        # the reader left in the middle
    except StoreError as e:
        rc, error = 2, str(e)
    except sqlite3.Error as e:
        rc, error = 2, f"{store.path}: {e}"
    finally:
        moved = store.written_while_read()
        store.close()
    if moved:
        # What was read may miss or repeat rows, and a read the move cut
        # short says 'malformed' of a store that is not: the write is the news.
        rc, error = 2, (f"{store.path} was written while it was read as it is; "
                        "the output may miss or repeat rows, read it again")
    try:
        # The rows go out before any ERROR line; a reader found gone here
        # left after the last of them, and the verdict stands.
        _flush(sys.stdout)
    except BrokenPipeError:
        pass
    return _error(error) if error else rc


def _error(text: str) -> int:
    """One ERROR line on stderr, exit 2. A reader that took stderr with it
    (`2>&1 | head`) left after the verdict, and the verdict stands."""
    try:
        print(f"ERROR: {text}", file=sys.stderr)
    except BrokenPipeError:
        pass
    return 2


def _flush(stream) -> None:
    """Out with what is still buffered. A descriptor closed before the start
    (`>&-`) leaves Python no stream at all: None, nothing to flush."""
    if stream is not None:
        stream.flush()


def main_sync() -> None:
    rc = main()
    try:
        # A reader that left takes nothing more: what is still buffered goes
        # to /dev/null rather than fail the interpreter's flush at exit
        # (exit 120, 'Exception ignored').
        _flush(sys.stdout)
        _flush(sys.stderr)
    except BrokenPipeError:
        _stdout_gone()
    sys.exit(rc)
