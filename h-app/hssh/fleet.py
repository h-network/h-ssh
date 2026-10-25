"""The fleet as a library: one call runs a command on many devices and hands
back the results as values, in the order the devices finish.

    from hssh import Fleet

    with Fleet(["10.0.1.1", "cr2:10.0.1.2:junos"], transport="junos", user="admin") as fleet:
        for r in fleet.show("show bgp summary"):          # as each device finishes
            print(r.device, r.ok, r.output if r.ok else r.error)

Threads talk to the devices; the caller never sees one. Each device gets
the runner's run (`run_for_target`): the session and command timeouts, the
retry budget with its classification (a failure the same call cannot fix is
tried once, a command that is not a read is sent once), the typed result.
A device that fails is a result with `ok` False and the failure in `error`,
never an exception out of the loop. At most `workers` devices are in flight
at once. A transport call that has not returned within its own timeouts
plus GRACE_SECONDS is reported as a failed result and its thread left to
finish by itself, so one wedged device cannot hold the run. Sessions are
pooled for the Fleet's lifetime (one NETCONF session per device however
many commands) and closed on exit. With `store=`, every result is kept in
the result store the way the CLI keeps it, written from the thread that
iterates. The library reads no environment variable and no config file:
what it is given is what it uses.

Reads only, `show` and `batch`. An edit has gates the CLI applies before
the runner is called (the set-syntax guard, the pre-flight check, the
question); those stay with the CLI and the transports' own edit()/begin().
"""

import asyncio
import concurrent.futures as cf
import datetime as _dt
import getpass
import json
import os
import socket
import threading
import time
import warnings
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Iterable, Iterator, List, Optional, Union

from . import drivers, pool
from .core import Target, check_unique, load_devices_csv, parse_bare_target
from .drivers import results as R
from .runner import RunResult, _backoff, run_for_target
from .store import Store

__all__ = ["Fleet", "Results", "DeviceResult", "MAX_WORKERS", "GRACE_SECONDS", "FORMATS"]

# The CLI's ceiling: an in-flight device is a thread, and on openssh a process.
MAX_WORKERS = 256
# Past the transports' own timeouts (session set-up, the commands, the
# retries' backoff) before a call that has not returned is given up on.
GRACE_SECONDS = 10
# While devices wait for a worker, the consumer looks this often for ones
# that started in the meantime, so their deadline is always watched.
_POLL_SECONDS = 0.5
FORMATS = ("text", "json", "xml")

_POOL_LOCK = threading.Lock()
_POOL_FLEETS = 0     # Fleets using a pool that a Fleet turned on


def _version() -> str:
    from . import __version__
    return __version__


def _now() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _pool_acquire() -> bool:
    """Turn the session pool on for a Fleet. True when Fleets own it (the
    last one to close turns it off); False when the caller had enabled it
    already, in which case it is used and left as it was."""
    global _POOL_FLEETS
    with _POOL_LOCK:
        if _POOL_FLEETS == 0 and pool.POOL.enabled:
            return False
        _POOL_FLEETS += 1
        pool.enable()
        return True


def _pool_release() -> None:
    global _POOL_FLEETS
    with _POOL_LOCK:
        _POOL_FLEETS -= 1
        if _POOL_FLEETS == 0:
            # Idle sessions close now; one still borrowed by a call that has
            # not returned closes when that call does.
            pool.disable()


def _as_targets(spec, transport: str) -> List[Target]:
    """Targets from what the caller gave: a Target; a bare host (a device
    named after itself on `transport`) or a name:host[:vendor][:port]
    string, as the CLI takes them; a pathlib.Path to a CSV inventory; or a
    list of any of those. A str on its own is an inventory file."""
    if isinstance(spec, Target):
        return [spec]
    if isinstance(spec, (str, os.PathLike)):
        return load_devices_csv(os.fspath(spec), default_vendor=transport)
    targets: List[Target] = []
    for item in spec:
        if isinstance(item, Target):
            targets.append(item)
        elif isinstance(item, os.PathLike):
            targets.extend(load_devices_csv(os.fspath(item), default_vendor=transport))
        elif isinstance(item, str):
            targets.append(parse_bare_target(item, default_vendor=transport))
        else:
            raise TypeError("a target is a Target, a host, a name:host[:vendor][:port] string or a "
                            f"Path to an inventory file, not {type(item).__name__}")
    return targets


def _check_int(name: str, value, low: int, high: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer, not {value!r}")
    if value < low or (high is not None and value > high):
        span = f"{low}..{high}" if high is not None else f"at least {low}"
        raise ValueError(f"{name} must be {span}, got {value!r}")
    return value


def _check_seconds(name: str, value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{name} must be a number of seconds above 0, not {value!r}")
    return value


def _reply(text: str, command: Optional[str]) -> str:
    """Just what the device said. The text transports open a reply with the
    command as `$ cmd` (framing --raw drops too); it goes only when it is
    exactly the command sent, so output that starts with '$ ' survives."""
    lines = text.splitlines()
    if lines and command and lines[0] == f"$ {command}":
        lines = lines[1:]
    return "\n".join(lines).strip("\n")


def _failed(t: Target, mode: str, error: str, duration_ms: int) -> RunResult:
    """A failure in the runner's own shape, for what the runner never saw."""
    text = f"DEVICE: {t.name}\nHOST:   {t.host}\nMODE:   {mode}\nVENDOR: {t.vendor}\n\nERROR: {error}\n"
    return RunResult(t.name, False, text, duration_ms, error=error)


@dataclass
class DeviceResult:
    """What one device's run came to, as a value.

    `output` is the reply (text; the data for fmt="json"; the XML for
    fmt="xml"), None for a failure and for a batch. A batch's answers are in
    `commands`, one dict per command in the batch's order with `command`,
    `ok` and `output` or `error`. `error` is the failure in one line; `ts`
    when the result came in (ISO 8601, local offset); `command` what was
    sent (the list, for a batch). `result` is the driver's typed answer and
    `text` the runner's full report, as `run_for_target` returns them."""

    device: str
    host: str
    vendor: str
    ok: bool
    command: Any
    output: Any
    error: Optional[str]
    duration_ms: int
    ts: str
    commands: Optional[List[dict]] = None
    run: Optional[RunResult] = field(default=None, repr=False, compare=False)

    @property
    def result(self) -> Any:
        return self.run.result if self.run is not None else None

    @property
    def text(self) -> str:
        return self.run.text if self.run is not None else ""

    def to_dict(self) -> dict:
        """The result as plain data, JSON-serialisable: the record the CLI's
        --json prints and the store takes, plus `ts`, with `output` and
        `error` always present (None when there is none)."""
        d = {"device": self.device, "host": self.host, "vendor": self.vendor, "ok": self.ok,
             "duration_ms": self.duration_ms, "ts": self.ts}
        if self.commands is not None:
            d["commands"] = [dict(c) for c in self.commands]
        else:
            d["command"] = self.command
            d["output"] = self.output
        d["error"] = self.error
        return d


class _Task:
    __slots__ = ("target", "future", "started")

    def __init__(self, target: Target):
        self.target = target
        self.future: Optional[cf.Future] = None
        self.started: Optional[float] = None    # set by the worker thread when it picks the task up


class _Run:
    """One show or batch across the fleet: its tasks, what came back, and the
    store rows it writes. Everything here but `work` runs on the thread
    that iterates; `work` is what the worker threads run."""

    def __init__(self, fleet: "Fleet", mode: str, command, fmt: str):
        self.fleet = fleet
        self.mode = mode                 # "show" or "show-batch", the runner's and the store's names
        self.command = command           # the command, or the list for a batch
        self.fmt = fmt
        self.tasks = [_Task(t) for t in fleet.targets]
        self.pending: List[_Task] = list(self.tasks)
        self.done: List[DeviceResult] = []
        self.by_future: dict = {}
        self.store_run = None
        self.ended = False
        self.warned = False
        self.attempts = fleet.retries + 1
        commands = len(command) if mode == "show-batch" else 1
        # What the transports promise to return within, worst case, plus grace.
        self.budget = (self.attempts * (fleet.session_timeout + fleet.command_timeout * commands)
                       + sum(_backoff(i) for i in range(1, self.attempts)) + GRACE_SECONDS)

    # --- on the calling thread ----------------------------------------------

    def start(self) -> None:
        fleet = self.fleet
        batch = self.mode == "show-batch"
        if fleet._store is not None:
            # Before the first device is touched: a store that cannot be written is no run.
            argv = ["Fleet.batch", *self.command] if batch else ["Fleet.show", self.command]
            about = "\n".join(self.command) if batch else self.command
            self.store_run = fleet._store.begin_run(self.mode, argv, fleet.user, len(self.tasks), _version(),
                                                    origin=socket.gethostname(), command=about)
        executor = fleet._engine(self)
        for task in self.tasks:
            task.future = executor.submit(self.work, task)
            self.by_future[task.future] = task

    # --- on a worker thread -------------------------------------------------

    def work(self, task: _Task) -> RunResult:
        task.started = time.monotonic()
        t, fleet = task.target, self.fleet
        try:
            return run_for_target(
                t=t, transport=t.vendor, mode=self.mode,
                show_cmd=self.command if self.mode == "show" else None,
                edit_cmd=None, config_dir=None, broadcast_file=None,
                user=fleet.user, passwd=fleet._passwd,
                session_timeout=fleet.session_timeout, command_timeout=fleet.command_timeout,
                dry_run=False, commit_confirmed=None, save_dir=None, quiet=True,
                batch_cmds=list(self.command) if self.mode == "show-batch" else None,
                max_attempts=self.attempts, fmt=self.fmt)
        except Exception as e:
            # The runner reports every failure as a result; this is the way
            # out for one it did not expect, so the device still gets a verdict.
            return _failed(t, self.mode, f"{type(e).__name__}: {e}", int((time.monotonic() - task.started) * 1000))
        finally:
            fleet._stuck.discard(task)

    # --- on the consuming thread --------------------------------------------

    def wait_timeout(self) -> float:
        """How long the consumer may wait for a completion before a deadline
        needs looking at: the soonest budget to run out, or the poll
        interval while a device still waits for a worker."""
        now = time.monotonic()
        soonest = None
        for task in self.pending:
            left = _POLL_SECONDS if task.started is None else task.started + self.budget - now
            soonest = left if soonest is None else min(soonest, left)
        return max(0.0, soonest or 0.0)

    def overdue(self) -> List[_Task]:
        """Tasks to give up on: past their budget, or never going to start
        because every worker thread is held by a call that has not returned."""
        now = time.monotonic()
        due = [t for t in self.pending if t.started is not None and now >= t.started + self.budget]
        if len(self.fleet._stuck) >= self.fleet.workers:
            for t in self.pending:
                # cancel() is False once a thread has picked the task up: then it gets its deadline
                if t.started is None and t not in due and t.future.cancel():
                    due.append(t)
        return due

    def finish(self, task: _Task) -> DeviceResult:
        """One task's outcome as the result the caller gets, recorded in the
        store on this thread; the run's store row is closed with the last."""
        self.pending.remove(task)
        if task.future.done() and not task.future.cancelled():
            try:
                run = task.future.result()
            except BaseException as e:   # noqa: BLE001 - a worker that died is this device's failure
                run = _failed(task.target, self.mode, f"{type(e).__name__}: {e}", 0)
            result = self._result(task.target, run)
        else:
            result = self._given_up(task)
        self.done.append(result)
        self._record(result)
        if not self.pending:
            self.end(interrupted=False)
        return result

    def _given_up(self, task: _Task) -> DeviceResult:
        fleet = self.fleet
        if task.started is None:
            ms = 0
            error = (f"not started: every worker thread ({fleet.workers}) is held by a call to a device "
                     "that has not returned")
        else:
            fleet._stuck.add(task)
            if task.future.done():          # it returned just now: not stuck after all
                fleet._stuck.discard(task)
            ms = int((time.monotonic() - task.started) * 1000)
            each = f"session_timeout {fleet.session_timeout:g}s + command_timeout {fleet.command_timeout:g}s"
            if self.mode == "show-batch":
                each += f" x {len(self.command)} commands"
            error = (f"no result within {self.budget:g}s ({self.attempts} attempt(s) at {each}, plus "
                     f"{GRACE_SECONDS:g}s): the transport call has not returned")
        return self._result(task.target, _failed(task.target, self.mode, error, ms))

    def _result(self, t: Target, run: RunResult) -> DeviceResult:
        ts = _now()
        error = run.error if run.error is not None or run.ok else "unknown error"
        if self.mode == "show-batch":
            commands = []
            if isinstance(run.result, R.BatchResult):
                for cr in run.result.to_list():
                    if cr.get("ok") and isinstance(cr.get("output"), str):   # only text carries the echo
                        cr["output"] = _reply(cr["output"], cr.get("command"))
                    commands.append(cr)
            return DeviceResult(t.name, t.host, t.vendor, run.ok, list(self.command), None, error,
                                run.duration_ms, ts, commands=commands, run=run)
        output = run.result if run.ok else None
        if isinstance(output, str):
            output = _reply(output, self.command)
        return DeviceResult(t.name, t.host, t.vendor, run.ok, self.command, output, error,
                            run.duration_ms, ts, run=run)

    def _record(self, result: DeviceResult) -> None:
        if self.store_run is None:
            return
        sent = json.dumps(list(self.command)) if self.mode == "show-batch" else self.command
        try:
            self.fleet._store.add_entry(self.store_run, result.to_dict(), sent, fmt=self.fmt)
        except Exception as e:
            self._warn(e)

    def end(self, interrupted: bool) -> None:
        """The run is over, complete or not: what has not started is
        cancelled, and the store's run row gets its counts. What is still
        in flight finishes on its own thread; nothing waits for it."""
        if self.ended:
            return
        self.ended = True
        for task in self.pending:
            task.future.cancel()
        self.fleet._forget(self)
        if self.store_run is not None:
            ok = sum(1 for r in self.done if r.ok)
            try:
                self.fleet._store.finish_run(self.store_run, ok, len(self.done) - ok, len(self.pending), interrupted)
            except Exception as e:
                self._warn(e)

    def _warn(self, e: Exception) -> None:
        if not self.warned:
            self.warned = True
            warnings.warn(f"store {self.fleet._store.path}: {e}", RuntimeWarning, stacklevel=4)


class Results:
    """One show's or batch's results, as the devices finish. Iterate with
    `for` (it blocks for the next device) or `async for`. Iterating again
    replays what has come back, then waits for the rest. `to_dicts()` waits
    for every device and returns the results as plain data."""

    def __init__(self, run: _Run):
        self._run = run

    def __iter__(self) -> Iterator[DeviceResult]:
        run = self._run
        i = 0
        while True:
            while i < len(run.done):
                yield run.done[i]
                i += 1
            if not run.pending:
                return
            due = run.overdue()
            if due:
                for task in due:
                    run.finish(task)
                continue
            done, _ = cf.wait([t.future for t in run.pending], timeout=run.wait_timeout(),
                              return_when=cf.FIRST_COMPLETED)
            for future in done:
                task = run.by_future[future]
                if task in run.pending:
                    run.finish(task)

    def __aiter__(self) -> AsyncIterator[DeviceResult]:
        return self._aiter()

    async def _aiter(self) -> AsyncIterator[DeviceResult]:
        run = self._run
        loop = asyncio.get_running_loop()
        wrapped: dict = {}     # task -> its future as the loop sees it, made once
        i = 0
        while True:
            while i < len(run.done):
                yield run.done[i]
                i += 1
            if not run.pending:
                return
            due = run.overdue()
            if due:
                for task in due:
                    run.finish(task)
                continue
            waiting = {}
            for task in run.pending:
                af = wrapped.get(task)
                if af is None:
                    af = wrapped[task] = asyncio.wrap_future(task.future, loop=loop)
                waiting[af] = task
            done, _ = await asyncio.wait(waiting, timeout=run.wait_timeout(), return_when=asyncio.FIRST_COMPLETED)
            for af in done:
                task = waiting[af]
                if task in run.pending:
                    run.finish(task)

    def to_dicts(self) -> List[dict]:
        """Every device's result as a dict (see DeviceResult.to_dict), in
        completion order, once the last device is in."""
        return [r.to_dict() for r in self]

    def __repr__(self) -> str:
        run = self._run
        return f"Results({run.mode}, {len(run.done)} of {len(run.tasks)} in)"


class Fleet:
    """Devices to run commands on, as a library: `show(cmd)` and
    `batch(cmds)` return the results as the devices finish, on the thread
    that iterates, with no thread in sight. See the module docstring.

    `targets`: bare hosts, name:host[:vendor][:port] strings, Target
    objects, pathlib.Paths to CSV inventories, or one inventory path as a
    str; a name or host listed twice is refused here, before anything runs.
    `transport`: the vendor for a target that names none. `user`: None is
    the login name. `passwd`: None is keys or an agent. `workers`: devices
    in flight at once. `session_timeout`, `command_timeout`: seconds, as
    the CLI's flags. `retries`: attempts after the first, for failures the
    runner's classification allows. `store`: a path, or an open Store, to
    keep every result in; a path the Fleet opens it closes on exit."""

    def __init__(self, targets, transport: str = "ssh", user: Optional[str] = None,
                 passwd: Optional[str] = None, workers: int = 32, session_timeout=30,
                 command_timeout=60, retries: int = 0, store: Union[None, str, os.PathLike, Store] = None):
        self.transport = transport
        found = _as_targets(targets, transport)
        if not found:
            raise ValueError("no targets")
        check_unique(found)
        for t in found:
            drivers.get(t.vendor)        # an unknown vendor is refused here, not once per device
        self.targets = tuple(found)
        if user is None:
            try:
                user = getpass.getuser()
            except Exception as e:       # no login name to be had (a bare container): say so
                raise ValueError(f"user: the login name could not be determined ({e}); pass user=") from e
        self.user = user
        self._passwd = passwd
        self.workers = _check_int("workers", workers, 1, MAX_WORKERS)
        self.session_timeout = _check_seconds("session_timeout", session_timeout)
        self.command_timeout = _check_seconds("command_timeout", command_timeout)
        self.retries = _check_int("retries", retries, 0)
        if isinstance(store, Store) or store is None:
            self._store, self._owns_store = store, False
        else:
            self._store, self._owns_store = Store(os.fspath(store)), True
        self._lock = threading.Lock()
        self._executor: Optional[cf.ThreadPoolExecutor] = None
        self._owns_pool = False
        self._closed = False
        self._runs: set = set()      # started and not yet ended
        self._stuck: set = set()     # tasks whose transport call never returned, holding a thread each

    # --- reads --------------------------------------------------------------

    def show(self, command: str, fmt: str = "text") -> Results:
        """`command` on every device, sent as typed. The devices start now;
        iterate the Results for what they said. `fmt` "json" or "xml" asks
        for the router's own data (NETCONF only; refused elsewhere as that
        device's failure, nothing sent)."""
        if not isinstance(command, str) or not command.strip():
            raise ValueError("show needs a command")
        return self._start("show", command, fmt)

    def batch(self, commands: Iterable[str], fmt: str = "text") -> Results:
        """Several commands on every device, each device on one session;
        every result carries one answer per command, in this order."""
        if isinstance(commands, str):
            raise TypeError("batch takes a list of commands; show() takes one")
        cmds = list(commands)
        if not cmds or any(not isinstance(c, str) or not c.strip() for c in cmds):
            raise ValueError("batch needs commands, none of them empty")
        return self._start("show-batch", cmds, fmt)

    def show_async(self, command: str, fmt: str = "text") -> Results:
        """The same run as show(), for `async for`."""
        return self.show(command, fmt)

    def batch_async(self, commands: Iterable[str], fmt: str = "text") -> Results:
        """The same run as batch(), for `async for`."""
        return self.batch(commands, fmt)

    def _start(self, mode: str, command, fmt: str) -> Results:
        if fmt not in FORMATS:
            raise ValueError(f"fmt must be one of {', '.join(FORMATS)}, not {fmt!r}")
        if self._closed:
            raise RuntimeError("this Fleet is closed")
        run = _Run(self, mode, command, fmt)
        run.start()
        return Results(run)

    # --- lifetime -----------------------------------------------------------

    def _engine(self, run: _Run) -> cf.ThreadPoolExecutor:
        with self._lock:
            if self._closed:
                raise RuntimeError("this Fleet is closed")
            if self._executor is None:
                self._executor = cf.ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="hssh-fleet")
                self._owns_pool = _pool_acquire()
            self._runs.add(run)
            return self._executor

    def _forget(self, run: _Run) -> None:
        with self._lock:
            self._runs.discard(run)

    def close(self) -> None:
        """Done with the fleet: devices not yet started are not started, a run
        left unfinished is recorded as interrupted, the sessions close (one
        still in use closes when its call returns), the executor is let go,
        and a store this Fleet opened is closed. Nothing waits on a device."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            runs, executor, owns_pool = list(self._runs), self._executor, self._owns_pool
        for run in runs:
            run.end(interrupted=True)
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
            if owns_pool:
                _pool_release()
        if self._owns_store and self._store is not None:
            self._store.close()

    def __enter__(self) -> "Fleet":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __len__(self) -> int:
        return len(self.targets)

    def __repr__(self) -> str:
        return (f"Fleet({len(self.targets)} target(s), transport={self.transport!r}, user={self.user!r}, "
                f"workers={self.workers})")
