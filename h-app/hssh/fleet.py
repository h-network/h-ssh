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
at once, `workers` lowered to what the open-file limit carries. A transport
call that has not returned within its own timeouts plus GRACE_SECONDS is
reported as a failed result and its thread left to finish by itself, so one
wedged device cannot hold the run; a later run on the same Fleet does not
call that device again until the call has returned. The worker threads are
daemon threads: a call that never returns keeps its thread, never the
interpreter's exit. One run at a time per Fleet: a second show() or batch()
while devices of the first are still in flight is refused, because two runs
on one Fleet would queue on the pool's per-router locks and the time bound
would then fail honest devices. Sessions are pooled for the Fleet's lifetime
(one NETCONF session per device however many commands) and closed on exit.
With `store=`, every result is kept in the result store the way the CLI
keeps it, written from the thread that iterates (from a worker thread of
the event loop, under `async for`); what the store could not keep is counted
in `Results.not_kept`, said as a RuntimeWarning, never raised. The library
reads no environment variable and no config file: what it is given is what
it uses.

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
import queue
import socket
import threading
import time
import warnings
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Iterable, Iterator, List, Optional, Union

from . import drivers, limits, pool
from .core import Target, check_unique, control_character, load_devices_csv, parse_bare_target
from .drivers import results as R
from .runner import RunResult, _backoff, run_for_target
from .store import Store

__all__ = ["Fleet", "Results", "DeviceResult", "MAX_WORKERS", "GRACE_SECONDS", "FORMATS", "DEFAULT_RETRIES"]

MAX_WORKERS = limits.MAX_WORKERS
# The CLI's --retries default: one engine, one behaviour.
DEFAULT_RETRIES = 2
# Past the transports' own timeouts (session set-up, the commands, the
# retries' backoff) before a call that has not returned is given up on.
GRACE_SECONDS = 10
# While devices wait for a worker, the consumer looks this often for ones
# that started in the meantime, so their deadline is always watched.
_POLL_SECONDS = 0.5
FORMATS = ("text", "json", "xml")
_INVENTORY_SUFFIXES = (".csv", ".yaml", ".yml", ".json")
_BUSY = "a run is still in progress on this Fleet: iterate it to the end, or close()"

_POOL_LOCK = threading.Lock()
_POOL_FLEETS = 0        # Fleets using the session pool right now
_POOL_WAS_OFF = False   # it was off before the first of them turned it on


def _version() -> str:
    from . import __version__
    return __version__


def _now() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _pool_acquire() -> None:
    """A Fleet starts using the process-wide session pool: turned on if it
    was off, and that remembered, so that the last Fleet to close turns it
    off again; a pool the caller enabled is used and left on."""
    global _POOL_FLEETS, _POOL_WAS_OFF
    with _POOL_LOCK:
        if _POOL_FLEETS == 0:
            _POOL_WAS_OFF = not pool.POOL.enabled
        _POOL_FLEETS += 1
        pool.enable()


def _pool_release() -> None:
    global _POOL_FLEETS, _POOL_WAS_OFF
    with _POOL_LOCK:
        _POOL_FLEETS -= 1
        if _POOL_FLEETS == 0:
            if _POOL_WAS_OFF:
                # Idle sessions close now; one still borrowed by a call that
                # has not returned closes when that call does.
                pool.disable()
            _POOL_WAS_OFF = False


class _DaemonPool:
    """The threads that talk to the devices, up to `workers` of them, made
    as the work needs them: daemon threads, so a call that never returns
    holds its thread but never the interpreter's exit, on any Python. They
    do device I/O only (the store is written by the consumer), so an exit
    that cuts one short loses nothing that was promised. The Futures are
    concurrent.futures', with the semantics the rest of this module waits
    on: `cancel()` on a queued one is honoured by the worker that reaches
    it, `shutdown(cancel_futures=True)` cancels the queue at once."""

    def __init__(self, workers: int, name: str = "hssh-fleet"):
        self._max = workers
        self._name = name
        self._queue: queue.SimpleQueue = queue.SimpleQueue()
        self._threads: List[threading.Thread] = []
        self._idle = threading.Semaphore(0)     # a release per worker waiting for work
        self._lock = threading.Lock()
        self._down = False

    def submit(self, fn, *args) -> cf.Future:
        future: cf.Future = cf.Future()
        with self._lock:
            if self._down:
                raise RuntimeError("the worker pool is shut down")
            # Room for one more thread and no worker waiting for work: start
            # it, before the item is queued, so a thread the system refuses
            # (ulimit -u, memory) is the caller's error and not an item that
            # waits for a worker that never came.
            if len(self._threads) < self._max and not self._idle.acquire(timeout=0):
                t = threading.Thread(target=self._loop, name=f"{self._name}-{len(self._threads) + 1}", daemon=True)
                t.start()
                self._threads.append(t)
            self._queue.put((future, fn, args))
        return future

    def _loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            future, fn, args = item
            if future.set_running_or_notify_cancel():
                try:
                    result = fn(*args)
                except BaseException as e:   # noqa: BLE001 - the future carries it to the consumer
                    future.set_exception(e)
                else:
                    future.set_result(result)
            del item, future, fn, args
            self._idle.release()

    def shutdown(self, wait: bool = False, cancel_futures: bool = True, timeout: float = 1.0) -> None:
        """No more work. `cancel_futures`: what is queued is cancelled now,
        and notified, so a waiter sees it done. `wait`: the idle workers
        are joined, for at most `timeout` seconds in all; a worker inside a
        device call is never waited for."""
        with self._lock:
            self._down = True
            threads = list(self._threads)
        if cancel_futures:
            while True:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                if item is not None:
                    item[0].cancel()
                    item[0].set_running_or_notify_cancel()
        for _ in threads:
            self._queue.put(None)
        if wait:
            deadline = time.monotonic() + timeout
            for t in threads:
                t.join(max(0.0, deadline - time.monotonic()))

    @property
    def threads(self) -> List[threading.Thread]:
        with self._lock:
            return list(self._threads)


def _looks_like_a_path(text: str) -> bool:
    seps = [os.sep] + ([os.altsep] if os.altsep else [])
    return any(s in text for s in seps) or text.lower().endswith(_INVENTORY_SUFFIXES)


def _as_targets(spec, transport: str) -> List[Target]:
    """Targets from what the caller gave: a Target; a bare host (a device
    named after itself on `transport`) or a name:host[:vendor][:port]
    string, as the CLI takes them; a pathlib.Path to a CSV inventory; or a
    list of any of those. A str on its own: an existing file is the
    inventory; one that reads as a path (a separator, an inventory suffix)
    but is not there is refused, so a mistyped inventory path never becomes
    a device; anything else is one target."""
    if isinstance(spec, Target):
        return [spec]
    if isinstance(spec, str):
        if os.path.isfile(spec):
            return load_devices_csv(spec, default_vendor=transport)
        if _looks_like_a_path(spec):
            raise ValueError(f"no inventory file at {spec!r}")
        return [parse_bare_target(spec, default_vendor=transport)]
    if isinstance(spec, os.PathLike):
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


def _one_line(what: str, command: str) -> str:
    """The command as sent: one line of text. The line break that ends a
    line read from a file is dropped, as the CLI drops it from a batch
    file's lines; any other control character, a line break inside
    included, is a ValueError."""
    line = command[:-1].removesuffix("\r") if command.endswith("\n") else command
    found = control_character(line)
    if found:
        raise ValueError(f"{what}: {found} in {command!r}; a command is one line of text")
    return line


def _check_int(name: str, value, low: int, high: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer, not {value!r}")
    if value < low or (high is not None and value > high):
        span = f"{low}..{high}" if high is not None else f"at least {low}"
        raise ValueError(f"{name} must be {span}, got {value!r}")
    return value


def _connect_factor(target: Target) -> int:
    """How many session_timeouts the session set-up may take, worst case.
    The NETCONF transport runs the whole of it against one deadline (#66).
    The paramiko transport gives the TCP connect, the SSH banner and the
    authentication each the full timeout (hssh/transports/ssh.py, _connect),
    the OpenSSH client its ConnectTimeout and then the session clock, and
    the telnet login a handful of reads each bounded by it: three covers
    them."""
    return 1 if drivers.get(target.vendor).transport.name == "netconf" else 3


def _budget(fleet: "Fleet", target: Target, commands: int) -> float:
    """Seconds after which a device's call is given up on: what the
    transport promises to return within, every attempt and the backoff
    between them, plus GRACE_SECONDS."""
    attempts = fleet.retries + 1
    per_attempt = _connect_factor(target) * fleet.session_timeout + fleet.command_timeout * commands
    return attempts * per_attempt + sum(_backoff(i) for i in range(1, attempts)) + GRACE_SECONDS


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
    __slots__ = ("target", "future", "started", "budget")

    def __init__(self, target: Target, budget: float):
        self.target = target
        self.budget = budget
        self.future: Optional[cf.Future] = None
        self.started: Optional[float] = None    # set by the worker thread when it picks the task up


class _Run:
    """One show or batch across the fleet: its tasks, what came back, and the
    store rows it writes. `work` runs on the Fleet's worker threads;
    everything else on whichever thread consumes, closes or starts the next
    run, under the run's lock, so a close() from a watchdog thread while
    the consumer iterates finds a consistent run."""

    def __init__(self, fleet: "Fleet", mode: str, command, fmt: str):
        self.fleet = fleet
        self.mode = mode                 # "show" or "show-batch", the runner's and the store's names
        self.command = command           # the command, or the list for a batch
        self.fmt = fmt
        self.commands = len(command) if mode == "show-batch" else 1
        self.attempts = fleet.retries + 1
        self.tasks = [_Task(t, _budget(fleet, t, self.commands)) for t in fleet.targets]
        self.pending: List[_Task] = list(self.tasks)
        self.done: List[DeviceResult] = []
        self.by_future: dict = {}
        self.store_run = None
        self.ended = False
        self.rows_tried = 0              # results handed to the store
        self.not_kept = 0                # of those, the ones it could not keep
        self.store_error: Optional[str] = None
        self._lock = threading.RLock()
        # Among the futures a consumer waits on; end() completes it (as a
        # cancelled one), so a close() from another thread wakes the
        # consumer at once rather than when the next device answers.
        self.stop: cf.Future = cf.Future()

    # --- on the calling thread ----------------------------------------------

    def start(self) -> None:
        """Admit the run (one at a time per Fleet), open its store row, hand
        every device to the workers. Nothing is sent before the store row
        exists: a store that cannot be written is no run."""
        fleet = self.fleet
        fleet._admit(self)
        try:
            if fleet._store is not None:
                batch = self.mode == "show-batch"
                argv = ["Fleet.batch", *self.command] if batch else ["Fleet.show", self.command]
                about = "\n".join(self.command) if batch else self.command
                self.store_run = fleet._store.begin_run(self.mode, argv, fleet.user, len(self.tasks), _version(),
                                                        origin=socket.gethostname(), command=about)
            workers = fleet._engine()
        except BaseException:
            with self._lock:
                self.ended = True
            fleet._forget(self)
            raise
        try:
            self._submit_all(workers)
        except BaseException:
            self.end(interrupted=True)           # the devices not handed out are skipped, the row says so
            raise

    def _submit_all(self, workers: "_DaemonPool") -> None:
        fleet = self.fleet
        for task in self.tasks:
            with self._lock:
                if self.ended:                   # closed while starting: the rest never runs
                    break
                if fleet._stuck_task(task.target.name) is not None:
                    # An earlier run's call to this device has not returned. It
                    # holds a worker and, in real life, the pool's lock for that
                    # router: another call would queue behind it and be given up
                    # on too, costing a worker per run. Refused instead, at once.
                    future: cf.Future = cf.Future()
                    future.set_result(_failed(task.target, self.mode,
                                              "the previous call to this device has not returned", 0))
                else:
                    future = workers.submit(self.work, task)
                    # Runs once the future's state is set, so a task counted as
                    # stuck (see _given_up) is always let go of when its call returns.
                    future.add_done_callback(lambda f, task=task: fleet._stuck_release(task))
                task.future = future
                self.by_future[future] = task

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

    # --- on the consuming thread --------------------------------------------

    def _snapshot(self) -> List[_Task]:
        with self._lock:
            return list(self.pending)

    def has_pending(self) -> bool:
        with self._lock:
            return bool(self.pending)

    def waitable(self) -> List[cf.Future]:
        """The futures a consumer waits on: of the pending tasks, those
        handed to a worker and not cancelled (a cancelled one is a close()
        under way; end() counts it), and `stop`, which end() completes."""
        futures = [t.future for t in self._snapshot() if t.future is not None and not t.future.cancelled()]
        futures.append(self.stop)
        return futures

    def wait_timeout(self) -> float:
        """How long the consumer may wait for a completion before a deadline
        needs looking at: the soonest budget to run out, or the poll
        interval while a device still waits for a worker."""
        now = time.monotonic()
        soonest = None
        for task in self._snapshot():
            left = _POLL_SECONDS if task.started is None else task.started + task.budget - now
            soonest = left if soonest is None else min(soonest, left)
        return max(0.0, soonest or 0.0)

    def overdue(self) -> List[_Task]:
        """Tasks to give up on: past their budget, or never going to start
        because every worker thread is held by a call that has not returned."""
        now = time.monotonic()
        pending = self._snapshot()
        due = [t for t in pending if t.started is not None and now >= t.started + t.budget]
        if self.fleet._stuck_count() >= self.fleet.workers:
            for t in pending:
                # cancel() is False once a thread has picked the task up: then it gets its deadline
                if t.started is None and t not in due and t.future is not None and t.future.cancel():
                    due.append(t)
        return due

    def finish(self, task: _Task) -> Optional[DeviceResult]:
        """One task's outcome as the result the caller gets, recorded in the
        store on this thread; the run's store row is closed with the last.
        None when the task was finished already, or the run has ended."""
        with self._lock:
            result = self._finish(task)
            if not self.pending and not self.ended:
                self.end(interrupted=False)
        return result

    def settle(self) -> None:
        """Finish, without waiting, every pending task whose call has
        returned: a result nobody iterated for is still a result, and a
        store row."""
        with self._lock:
            for task in list(self.pending):
                if task.future is not None and task.future.done() and not task.future.cancelled():
                    self._finish(task)

    def _finish(self, task: _Task) -> Optional[DeviceResult]:
        """Caller holds the lock."""
        if self.ended or task not in self.pending:
            return None
        self.pending.remove(task)
        future = task.future
        if future is not None and future.done() and not future.cancelled():
            try:
                run = future.result()
            except BaseException as e:   # noqa: BLE001 - a worker that died is this device's failure
                run = _failed(task.target, self.mode, f"{type(e).__name__}: {e}", 0)
            result = self._result(task.target, run)
        else:
            result = self._given_up(task)
        self.done.append(result)
        self._record(result)
        return result

    def _given_up(self, task: _Task) -> DeviceResult:
        fleet = self.fleet
        if task.started is None:
            ms = 0
            error = (f"not started: every worker thread ({fleet.workers}) is held by a call to a device "
                     "that has not returned")
        else:
            fleet._stuck_hold(task)
            if task.future is not None and task.future.done():   # it returned just now: not stuck after all
                fleet._stuck_release(task)
            ms = int((time.monotonic() - task.started) * 1000)
            factor = _connect_factor(task.target)
            each = (f"{factor} x " if factor > 1 else "") + f"session_timeout {fleet.session_timeout}s"
            each += f" + command_timeout {fleet.command_timeout}s"
            if self.mode == "show-batch":
                each += f" x {self.commands} commands"
            error = (f"no result within {task.budget:g}s ({self.attempts} attempt(s) at {each}, plus "
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
        store = self.fleet._store
        sent = json.dumps(list(self.command)) if self.mode == "show-batch" else self.command
        self.rows_tried += 1
        try:
            store.add_entry(self.store_run, result.to_dict(), sent, fmt=self.fmt)
        except Exception as e:
            # The run goes on and the result is still handed over; the loss is
            # counted, said once as it happens and once more at the end.
            self.not_kept += 1
            if self.store_error is None:
                self.store_error = str(e)
                warnings.warn(f"store {store.path}: {e}; the run goes on, its results are shown but not kept",
                              RuntimeWarning, stacklevel=2)

    def _close_store_row(self, ok: int, failed: int, skipped: int, interrupted: bool) -> None:
        """Caller holds the lock. As the CLI: SQLite writes into a deleted or
        replaced file without a word, so the file is checked once here, and
        when it is gone nothing of the run was kept. The run row is closed
        when any result was kept; with nothing kept it stays open, a true
        record of a run that could not keep its results."""
        if self.store_run is None:
            return
        store = self.fleet._store
        gone = store.still_there()
        if gone is not None:
            self.not_kept, self.store_error = self.rows_tried, gone
        if self.not_kept < self.rows_tried or self.rows_tried == 0:
            try:
                store.finish_run(self.store_run, ok, failed, skipped, interrupted)
            except Exception as e:
                if self.store_error is None:
                    self.store_error = str(e)
                warnings.warn(f"store {store.path}: {e}", RuntimeWarning, stacklevel=2)
        if self.not_kept:
            warnings.warn(f"store {store.path}: {self.not_kept} of {self.rows_tried} results were not kept: "
                          f"{self.store_error}", RuntimeWarning, stacklevel=2)

    def wait_for_inflight(self, seconds: float) -> None:
        """close(wait=): the devices not started are not started; the ones a
        worker is talking to get `seconds` to answer."""
        with self._lock:
            for task in self.pending:
                if task.started is None and task.future is not None:
                    task.future.cancel()
            futures = [t.future for t in self.pending
                       if t.future is not None and not t.future.cancelled() and not t.future.done()]
        if futures:
            cf.wait(futures, timeout=seconds)

    def end(self, interrupted: bool) -> None:
        """The run is over, complete or not. What has returned by now is a
        result (and a store row); the rest is cancelled and counted as
        skipped, and a call still in flight is dropped when it returns: the
        store and the caller agree on what the run came to. The store's run
        row gets the counts."""
        with self._lock:
            if self.ended:
                return
            self.settle()
            self.ended = True
            for task in self.pending:
                if task.future is not None:
                    task.future.cancel()
            skipped = len(self.pending)
            ok = sum(1 for r in self.done if r.ok)
            self._close_store_row(ok, len(self.done) - ok, skipped, interrupted and skipped > 0)
        if self.stop.cancel():                   # wakes a consumer waiting on the run's futures
            self.stop.set_running_or_notify_cancel()
        self.fleet._forget(self)


def _finish_all(run: _Run, tasks: List[_Task]) -> None:
    for task in tasks:
        run.finish(task)


class Results:
    """One show's or batch's results, as the devices finish. Iterate with
    `for` (it blocks for the next device) or `async for` (the store writes
    run off the event loop). Iterating again replays what has come back,
    then waits for the rest. `to_dicts()` waits for every device and
    returns the results as plain data. Once the Fleet is closed, what was
    done by then is all there is. `not_kept` and `store_error` say what the
    store could not keep, once the run is over."""

    def __init__(self, run: _Run):
        self._run = run

    @property
    def not_kept(self) -> int:
        """Results the store could not keep: a write that failed, or every
        result of the run when the store file was deleted or replaced."""
        return self._run.not_kept

    @property
    def store_error(self) -> Optional[str]:
        """Why, the first reason; None while nothing was lost."""
        return self._run.store_error

    def __iter__(self) -> Iterator[DeviceResult]:
        run = self._run
        i = 0
        while True:
            while i < len(run.done):
                yield run.done[i]
                i += 1
            if run.ended:
                while i < len(run.done):     # settled by end(): nothing is appended after it
                    yield run.done[i]
                    i += 1
                return
            due = run.overdue()
            if due:
                _finish_all(run, due)
                continue
            futures = run.waitable()
            if not futures:                  # a close() is under way: it ends the run shortly
                time.sleep(0.05)
                continue
            done, _ = cf.wait(futures, timeout=run.wait_timeout(), return_when=cf.FIRST_COMPLETED)
            _finish_all(run, [run.by_future[f] for f in done if f in run.by_future])   # not `stop`

    def __aiter__(self) -> AsyncIterator[DeviceResult]:
        return self._aiter()

    async def _aiter(self) -> AsyncIterator[DeviceResult]:
        run = self._run
        loop = asyncio.get_running_loop()
        wrapped: dict = {}     # future -> the same future as the loop sees it, made once
        i = 0
        while True:
            while i < len(run.done):
                yield run.done[i]
                i += 1
            if run.ended:
                while i < len(run.done):
                    yield run.done[i]
                    i += 1
                return
            due = run.overdue()
            if due:
                await loop.run_in_executor(None, _finish_all, run, due)
                continue
            futures = run.waitable()
            if not futures:
                await asyncio.sleep(0.05)
                continue
            waiting = {}
            for f in futures:
                af = wrapped.get(f)
                if af is None:
                    af = wrapped[f] = asyncio.wrap_future(f, loop=loop)
                waiting[af] = f
            done, _ = await asyncio.wait(waiting, timeout=run.wait_timeout(), return_when=asyncio.FIRST_COMPLETED)
            ready = [run.by_future[waiting[af]] for af in done if waiting[af] in run.by_future]   # not `stop`
            if ready:
                # finish() builds the result and writes the store: SQLite, off the loop
                await loop.run_in_executor(None, _finish_all, run, ready)

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
    objects, pathlib.Paths to CSV inventories, or one str (an existing file
    is the inventory; one that reads as a path but is not there is refused;
    anything else one target); a name or host listed twice is refused here,
    before anything runs. `transport`: the vendor for a target that names
    none. `user`: None is the login name. `passwd`: None is keys or an
    agent; an empty string is refused, since the transports do not agree on
    what it means. `workers`: devices in flight at once, lowered to what
    the open-file limit carries (the soft limit is raised towards the hard
    one first, as the CLI does; a RuntimeWarning says when fewer run).
    `session_timeout`, `command_timeout`: whole seconds, as the CLI's flags.
    `retries`: attempts after the first, for failures the runner's
    classification allows; 2 by default, as the CLI's --retries. `store`: a
    path, or an open Store, to keep every result in; a path the Fleet opens
    it closes on exit.

    One run at a time: a second show() or batch() while devices of the
    previous run are still in flight raises RuntimeError; a previous run
    whose devices have all returned is wrapped up first (its results stay
    readable). close(wait=0), or leaving the `with` block: devices not yet
    started are not started; the devices a worker is talking to get `wait`
    seconds to answer, and what has returned by then is a result and a store
    row; the run is recorded as interrupted with the rest as skipped, and
    its Results give what was done by then and nothing more (a call that
    returns later is dropped: its row says skipped). The sessions close (one
    still in use closes when its call returns), a store this Fleet opened is
    closed. Nothing waits on a device beyond `wait`; the worker threads are
    daemon threads, so a call that never returns keeps its thread and
    nothing else. `async with`, and `aclose()`, do the same off the event
    loop."""

    def __init__(self, targets, transport: str = "ssh", user: Optional[str] = None,
                 passwd: Optional[str] = None, workers: int = 32, session_timeout: int = 30,
                 command_timeout: int = 60, retries: int = DEFAULT_RETRIES,
                 store: Union[None, str, os.PathLike, Store] = None):
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
        if passwd is not None and not isinstance(passwd, str):
            raise TypeError(f"passwd must be a str or None, not {type(passwd).__name__}")
        if passwd == "":
            raise ValueError("passwd: empty; pass None for keys or an agent")
        self._passwd = passwd
        self.workers = _check_int("workers", workers, 1, limits.MAX_WORKERS)
        self.session_timeout = _check_int("session_timeout", session_timeout, 1)
        self.command_timeout = _check_int("command_timeout", command_timeout, 1)
        self.retries = _check_int("retries", retries, 0)
        if isinstance(store, Store) or store is None:
            self._store, self._owns_store = store, False
        else:
            self._store, self._owns_store = Store(os.fspath(store)), True
        self._lock = threading.RLock()
        self._workers: Optional[_DaemonPool] = None
        self._pooled = False               # counted in the session pool's users
        self._closed = False
        self._run: Optional[_Run] = None   # the run in progress, if any
        self._stuck: dict = {}             # device name -> the task whose call has not returned
        self._stuck_lock = threading.Lock()

    # --- reads --------------------------------------------------------------

    def show(self, command: str, fmt: str = "text") -> Results:
        """`command` on every device, sent as typed: one line of text, so a
        line break or another control character in it is a ValueError
        before anything runs (the one that ends a line read from a file is
        dropped). The devices start now; iterate the Results for what they
        said. `fmt` "json" or "xml" asks for the router's own data
        (NETCONF only, and reads only: anything else is that device's
        failure, nothing sent)."""
        run = self._prepare("show", command, fmt)
        run.start()
        return Results(run)

    def batch(self, commands: Iterable[str], fmt: str = "text") -> Results:
        """Several commands on every device, each device on one session;
        every result carries one answer per command, in this order. Each
        command is held to show()'s rules, `fmt` included, so the lines of
        an open file may be passed as they are."""
        run = self._prepare("show-batch", commands, fmt)
        run.start()
        return Results(run)

    async def show_async(self, command: str, fmt: str = "text") -> AsyncIterator[DeviceResult]:
        """show() for asyncio code: `async for r in fleet.show_async(cmd)`.
        The run starts on the first step, and what could block the loop
        (the store's run row, the host name, every store write) runs on a
        worker of the loop instead."""
        async for r in self._run_async(self._prepare("show", command, fmt)):
            yield r

    async def batch_async(self, commands: Iterable[str], fmt: str = "text") -> AsyncIterator[DeviceResult]:
        """batch() for asyncio code, as show_async()."""
        async for r in self._run_async(self._prepare("show-batch", commands, fmt)):
            yield r

    async def _run_async(self, run: _Run) -> AsyncIterator[DeviceResult]:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, run.start)
        async for r in Results(run):
            yield r

    def _prepare(self, mode: str, command, fmt: str) -> _Run:
        if mode == "show":
            if not isinstance(command, str) or not command.strip():
                raise ValueError("show needs a command")
            command = _one_line("show", command)
        else:
            if isinstance(command, str):
                raise TypeError("batch takes a list of commands; show() takes one")
            command = list(command)
            if not command or any(not isinstance(c, str) or not c.strip() for c in command):
                raise ValueError("batch needs commands, none of them empty")
            command = [_one_line("batch", c) for c in command]
        if fmt not in FORMATS:
            raise ValueError(f"fmt must be one of {', '.join(FORMATS)}, not {fmt!r}")
        if self._closed:
            raise RuntimeError("this Fleet is closed")
        return _Run(self, mode, command, fmt)

    # --- lifetime -----------------------------------------------------------

    def _admit(self, run: _Run) -> None:
        """One run at a time. A previous run whose calls have all returned is
        wrapped up here (its results stay readable); one with a device
        still in flight refuses the new one. The Fleet's lock is never held
        while a run's lock is taken."""
        with self._lock:
            if self._closed:
                raise RuntimeError("this Fleet is closed")
            current = self._run
        if current is not None:
            current.settle()
            if current.has_pending():
                raise RuntimeError(_BUSY)
            current.end(interrupted=False)
        with self._lock:
            if self._closed:
                raise RuntimeError("this Fleet is closed")
            if self._run is not None:        # another thread got in first
                raise RuntimeError(_BUSY)
            self._run = run

    def _engine(self) -> _DaemonPool:
        with self._lock:
            if self._closed:
                raise RuntimeError("this Fleet is closed")
            if self._workers is None:
                fitted, note = limits.fit_workers_to_open_files(self.workers)
                if note:
                    warnings.warn(note, RuntimeWarning, stacklevel=4)
                self.workers = fitted
                self._workers = _DaemonPool(fitted)
                _pool_acquire()
                self._pooled = True
            return self._workers

    def _forget(self, run: _Run) -> None:
        with self._lock:
            if self._run is run:
                self._run = None

    def _stuck_task(self, name: str) -> Optional[_Task]:
        with self._stuck_lock:
            return self._stuck.get(name)

    def _stuck_count(self) -> int:
        with self._stuck_lock:
            return len(self._stuck)

    def _stuck_hold(self, task: _Task) -> None:
        with self._stuck_lock:
            self._stuck[task.target.name] = task

    def _stuck_release(self, task: _Task) -> None:
        with self._stuck_lock:
            if self._stuck.get(task.target.name) is task:
                del self._stuck[task.target.name]

    def close(self, wait: float = 0) -> None:
        """Done with the fleet; see the class docstring for what that means
        for a run still going. `wait`: seconds the devices in flight get to
        answer first (a Ctrl-C handler may pass a few). Every step runs,
        whatever an earlier one raised."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            run, workers, pooled = self._run, self._workers, self._pooled
        try:
            if run is not None:
                if wait and wait > 0:
                    run.wait_for_inflight(wait)
                run.end(interrupted=True)
        finally:
            try:
                if workers is not None:
                    workers.shutdown(wait=False, cancel_futures=True)
            finally:
                try:
                    if pooled:
                        _pool_release()
                finally:
                    if self._owns_store and self._store is not None:
                        self._store.close()

    async def aclose(self, wait: float = 0) -> None:
        """close(), off the event loop: the store, the pool and the collector
        it runs are not the loop's business."""
        await asyncio.get_running_loop().run_in_executor(None, self.close, wait)

    def __enter__(self) -> "Fleet":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    async def __aenter__(self) -> "Fleet":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    def __len__(self) -> int:
        return len(self.targets)

    def __repr__(self) -> str:
        return (f"Fleet({len(self.targets)} target(s), transport={self.transport!r}, user={self.user!r}, "
                f"workers={self.workers})")
