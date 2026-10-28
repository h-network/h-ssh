"""Session pool — keep a device session open between calls.

This is the thread-safe ConnectionPool that h-network contributed to
Juniper/junos-mcp-server (PR #27), carried over into h-ssh: one entry per
router with its own lock, a global lock for the table, idle connections
closed by a cleanup thread after a configurable timeout (default 300 s,
HSSH_POOL_IDLE_TIMEOUT), close_all() that never waits on an in-flight
operation at shutdown, and a half-opened device closed rather than leaked.

What a library needs on top, and only that:
- off by default — the CLI never enables it, so a one-shot run still opens
  and closes one session per operation; library code calls pool.enable()
- the borrower gets a Lease and may call lease.discard() when the driver
  knows the session is in doubt (ambiguous commit, failed unlock, ...)
- an optional liveness check before a reused session is handed out
- a re-entrant per-router lock, so a thread holding an open transaction
  can keep using the same session through the pool; another thread waits
  for a transaction held open there at most its command timeout, and a
  borrow nobody gives back (a Transaction dropped without commit or abort)
  closes its session instead of pooling it (#147)
- entries are keyed by whatever the driver passes (host, port, user), the
  driver supplies the opener/closer, so the pool knows no vendor

    from hssh import pool
    pool.enable()                 # sessions idle for 300 s are closed
    ... transports.netconf.show(...)   # every call now reuses the router's session
    pool.close_all()              # or leave it to atexit
"""

import atexit
import gc
import logging
import os
import threading
import time
from contextlib import contextmanager
from typing import Callable, Dict, Hashable, Optional

from .errors import NotAppliedError

log = logging.getLogger("hssh.pool")

DEFAULT_IDLE_TIMEOUT = 300
CLEANUP_INTERVAL = 60
CLOSE_WAIT = 1.0        # how long close_all() and reap() wait for the closes they started, in all
REAPER_CLOSE_WAIT = 10.0   # the same for the cleanup thread, which nobody waits on
# How long a borrower given no command timeout, and close_all(shutdown=False),
# wait for a router whose session a transaction holds open on another thread.
BUSY_WAIT = 60.0
BUSY = "router busy: a transaction is open on this session"
_POLL = 0.25            # how often a waiter looks again whether a transaction holds the router


class _RouterLock:
    """The per-router lock. Re-entrant for the thread that holds it, as an
    RLock is: a thread with an open transaction keeps using its session
    through the pool. Unlike an RLock, a borrow can be ended on another
    thread for the thread that took it, which is how an abandoned borrow
    ends: a Transaction the garbage collector frees on whatever thread it
    runs on, or one dropped on the event loop's thread after
    asyncio.to_thread() opened it. An RLock stayed owned by the thread that
    took it, perhaps gone by then, and held the router for good (#147).

    `count` is how many borrows the holder has open, nested ones included;
    `turns`, how many holders there have been. Nothing under `_mutex`
    allocates an object the garbage collector tracks, so no collection, and
    no abandoned borrow it ends, can start inside it on the same thread."""

    __slots__ = ("_slot", "_mutex", "owner", "count", "turns")

    def __init__(self):
        self._slot = threading.Lock()       # held while a borrow holds the router; any thread may let it go
        self._mutex = threading.Lock()      # owner, count and turns, read and written together
        self.owner: Optional[int] = None
        self.count = 0
        self.turns = 0

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        me = threading.get_ident()
        with self._mutex:
            if self.owner == me:
                self.count += 1
                return True
        got = self._slot.acquire(True, timeout) if blocking else self._slot.acquire(False)
        if got:
            with self._mutex:
                self.owner, self.count = me, 1
                self.turns += 1
        return got

    def release(self) -> None:
        """One of this thread's holds given back."""
        me = threading.get_ident()
        mine = free = False
        with self._mutex:
            if self.owner == me and self.count > 0:
                mine = True
                self.count -= 1
                if self.count == 0:
                    self.owner, free = None, True
        if not mine:
            raise RuntimeError("cannot release un-acquired lock")
        if free:
            self._slot.release()

    def last(self, owner: int) -> bool:
        """The end of a borrow taken on thread `owner`, here or on another
        thread. True when it was the holder's only borrow: the hold is now
        this thread's, to end with release() once the session's fate is
        settled. False when the holder has others open (an outer borrow, or
        a nested one): this borrow's share is given back, and the last of
        them settles the session."""
        me = threading.get_ident()
        held = alone = False
        with self._mutex:
            if self.owner == owner and self.count > 0:
                held = True
                if self.count == 1:
                    self.owner, alone = me, True
                else:
                    self.count -= 1
        if not held:
            raise RuntimeError("the borrow does not hold this router")
        return alone

    __enter__ = acquire

    def __exit__(self, *exc) -> None:
        self.release()


class Lease:
    """What a borrower gets: the session, whether it was reused, and a way to
    say it is no good. A discarded session is closed when the outermost
    borrow returns it — not before, so a call nested inside an open
    transaction cannot pull the session out from under it."""

    __slots__ = ("dev", "reused", "discarded", "_entry", "_open")

    def __init__(self, dev, reused: bool, entry: Optional[dict] = None):
        self.dev = dev
        self.reused = reused
        self.discarded = False
        self._entry = entry
        self._open = False

    def discard(self) -> None:
        self.discarded = True

    def hold_open(self) -> None:
        """The session stays borrowed past this call, for as long as the
        caller decides: a Transaction, until its commit() or abort(). Another
        thread that wants the router waits for a call in flight to its end,
        which the call's own timeouts bound, but for a session held open
        only its wait (get_connection), and is then refused: NotAppliedError,
        router busy, nothing sent (#147)."""
        if self._entry is not None:
            self._open = True
            self._entry["open"].add(id(self))

    @property
    def doomed(self) -> bool:
        """True once any borrower of this session — this one or a nested
        call — has discarded it; the outer holder must not send more work."""
        if self.discarded:
            return True
        return bool(self._entry and self._entry.get("doomed"))


class ConnectionPool:
    """Thread-safe session pool for network devices.

    Reuses sessions across calls instead of opening a new connection for
    every command. Idle connections are closed after a configurable timeout
    (default 300s, configurable via the HSSH_POOL_IDLE_TIMEOUT env var).
    """

    def __init__(self, idle_timeout: Optional[float] = None):
        self._connections: Dict[Hashable, dict] = {}
        self._pool_lock = threading.Lock()
        # The counters have a lock of their own, under which nothing is
        # allocated: an abandoned borrow ends wherever the collector frees
        # it, and on a thread inside _pool_lock that lock would hang it.
        self._stats_lock = threading.Lock()
        if idle_timeout is None:
            self._idle_timeout = DEFAULT_IDLE_TIMEOUT
            env_val = os.getenv("HSSH_POOL_IDLE_TIMEOUT")
            if env_val is not None:
                try:
                    self._idle_timeout = int(env_val)
                except ValueError:
                    log.warning(
                        "Invalid HSSH_POOL_IDLE_TIMEOUT environment variable "
                        "value: %s. Using default idle timeout.",
                        env_val,
                    )
        else:
            self._idle_timeout = idle_timeout
        self._enabled = False
        self._cleanup_thread: Optional[threading.Thread] = None
        # The running cleanup thread holds the token it was started with; a
        # later enable() hands out a new one, so a thread still finishing a
        # pass when disable() -> enable() happens exits instead of living on
        # beside its successor.
        self._cleanup_token = None
        # Bumped by close_all(): a session borrowed before the bump is closed
        # on return instead of going back into the pool.
        self._generation = 0
        self.stats = {"opens": 0, "reuses": 0, "discards": 0, "reaped": 0}
        atexit.register(self.close_all)

    # -- lifecycle -------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def idle_timeout(self) -> float:
        return self._idle_timeout

    @idle_timeout.setter
    def idle_timeout(self, value: float) -> None:
        self._idle_timeout = value

    def enable(self, idle_timeout: Optional[float] = None) -> None:
        """Start reusing sessions. Idempotent. A cleanup thread the system
        refuses (ulimit -u, memory) is the caller's error and the pool
        stays off: on without its reaper, no idle session would ever close."""
        with self._pool_lock:
            if idle_timeout is not None:
                self._idle_timeout = idle_timeout
            if self._enabled:
                return
            token = object()
            thread = threading.Thread(
                target=self._cleanup_loop, args=(token,), daemon=True, name="hssh-pool-cleanup"
            )
            self._cleanup_token = token
            try:
                thread.start()
            except BaseException:
                self._cleanup_token = None
                raise
            self._cleanup_thread = thread
            self._enabled = True
            log.info("Connection pool enabled (idle_timeout=%ds)", self._idle_timeout)

    def disable(self) -> None:
        """Close every session and go back to one session per call."""
        with self._pool_lock:
            self._enabled = False
            self._cleanup_token = None
        self.close_all(shutdown=True)

    # -- borrowing -------------------------------------------------------------

    @contextmanager
    def get_connection(self, key: Hashable, opener: Callable, closer: Callable,
                       timeout: Optional[float] = None, alive: Optional[Callable] = None,
                       wait: Optional[float] = None):
        """Get a pooled device session. Creates or reuses as needed.

        Args:
            key: What identifies the router to this pool (the junos driver
                uses (host, port, user))
            opener: Opens and returns a session; whatever it raises propagates
                untouched and leaves the slot empty
            closer: Closes a session this pool is done with; it may hand
                the close to a thread and return that Thread, which
                close_all() and the reaper wait for before they collect what
                the close leaves. Any other return value is ignored
            timeout: Command timeout to set on the device for this borrow
            alive: alive(dev, idle_seconds) asked before a session is reused;
                False or an exception means it is closed and a new one opened
            wait: how long to wait for the router while another thread holds
                its session open (Lease.hold_open(): a Transaction not yet
                committed or aborted): `timeout` when None, else BUSY_WAIT.
                Then NotAppliedError('router busy: a transaction is open on
                this session'), and nothing was sent. A call in flight there
                is waited for to its end, which its own timeouts bound.

        Yields:
            A Lease: .dev is the open session, .reused says whether it came
            from the pool, .discard() closes it on return instead of keeping it

        Note:
            The per-router lock serializes same-router work: other threads
            wanting this router wait, the thread holding it may re-enter. A
            borrow nobody gives back, because what held it was dropped (a
            Transaction left without commit() or abort(), freed on its own
            thread or another), ends as a discarded one: its session is
            closed, never pooled, so the device lets go of the configuration
            lock and the candidate with it, and the router is free (#147).
        """
        if not self._enabled:
            dev = opener()
            try:
                if timeout is not None:
                    dev.timeout = timeout
                yield Lease(dev, reused=False)
            finally:
                closer(dev)
            return

        entry = self._get_or_create_entry(key)
        self._take(entry, wait if wait is not None else BUSY_WAIT if timeout is None else timeout)
        owner = threading.get_ident()
        nested = entry["lock"].count > 1     # re-entrant: >1 means a call nested in an open borrow
        lease = None
        abandoned = False
        try:
            device = entry["device"]
            reused = device is not None
            if device is not None and not nested and not self._usable(
                    device, alive, time.time() - entry["last_used"]):
                self._drop(entry, "discards")
                device, reused = None, False
            if device is None:
                device = opener()
                entry["device"], entry["closer"] = device, closer
                entry["generation"] = self._generation
                self._count("opens")
                log.info("Pool: opened new connection to %s", key)
            else:
                self._count("reuses")
                log.debug("Pool: reusing connection to %s", key)

            if timeout is not None and not nested:
                device.timeout = timeout
            lease = Lease(device, reused, entry)
            yield lease
        except GeneratorExit:
            # Nobody gave this borrow back: what held it was dropped, here or
            # on the thread the garbage collector ran on. Its session may
            # hold the device's configuration lock and a loaded candidate (a
            # Transaction left without commit() or abort()), and the next
            # edit would have committed that candidate with its own: it is
            # closed instead of pooled, and the device lets go of both.
            abandoned = True
            raise
        except Exception:
            # Invalidate the pooled connection if the transport dropped; the
            # driver signals the other cases (an RPC that timed out, a commit
            # whose outcome is unknown) through lease.discard().
            dev = entry["device"]
            if dev is not None and not getattr(dev, "connected", True):
                entry["doomed"] = True
            raise
        finally:
            if abandoned or (lease is not None and lease.discarded):
                entry["doomed"] = True
            if lease is not None and lease._open:
                entry["open"].discard(id(lease))
            self._end(entry, owner)

    # kept for callers written against the first h-ssh pool
    lease = get_connection

    def _take(self, entry: dict, wait: float) -> None:
        """The router's lock, for this thread; a thread that holds it already
        re-enters at once. A borrow in flight on another thread is waited for
        to its end, which its own timeouts bound. A session a transaction
        holds open there is waited for at most `wait` seconds of that
        holder's turn, then NotAppliedError: nothing was sent (#147)."""
        lock = entry["lock"]
        if lock.acquire(blocking=False):
            return
        turn = since = None
        while True:
            if entry["open"]:
                now = time.monotonic()
                if since is None or turn != lock.turns:
                    turn, since = lock.turns, now
                left = since + wait - now
                if left <= 0:
                    raise NotAppliedError(BUSY)
                step = min(left, _POLL)
            else:
                turn = since = None
                step = _POLL
            if lock.acquire(timeout=step):
                return

    def _end(self, entry: dict, owner: int) -> None:
        """A borrow taken on thread `owner` is over: on that thread, or
        abandoned and ended on this one for it. Only the holder's last
        borrow decides the session's fate: a nested call that found it dead
        has marked it, and the holder of the outer borrow (a Transaction)
        still needs to finish on its own terms."""
        lock = entry["lock"]
        try:
            last = lock.last(owner)
        except RuntimeError as e:
            log.debug("Pool: %s", e)
            return
        # Refresh last_used on every borrow — success OR failure. Otherwise a
        # connection whose operation raised while still connected keeps
        # last_used at 0.0, and the idle-cleanup loop (which requires
        # last_used > 0) would never reap it.
        if not last:
            entry["last_used"] = time.time()
            return
        try:
            if entry["device"] is not None and (
                entry["doomed"] or not self._enabled or entry["generation"] != self._generation
            ):
                self._drop(entry, "discards")
            entry["doomed"] = False
            entry["last_used"] = time.time()
        finally:
            lock.release()

    def _get_or_create_entry(self, key: Hashable) -> dict:
        with self._pool_lock:
            if key not in self._connections:
                self._connections[key] = {
                    "device": None,
                    "closer": None,
                    "lock": _RouterLock(),
                    "last_used": 0.0,
                    "generation": 0,
                    "doomed": False,
                    "open": set(),      # the leases holding the session open (Lease.hold_open)
                }
            return self._connections[key]

    @staticmethod
    def _usable(device, alive: Optional[Callable], idle: float) -> bool:
        if not getattr(device, "connected", True):
            return False
        if alive is None:
            return True
        try:
            return bool(alive(device, idle))
        except Exception:
            return False

    def _drop(self, entry: dict, counter: str):
        """Close and forget the entry's session. Caller holds entry["lock"].
        Returns what the closer returned (the thread still finishing the
        close, if it handed the close to one)."""
        device, entry["device"] = entry["device"], None
        if device is None:
            return None
        self._count(counter)
        try:
            return entry["closer"](device)
        except Exception as e:
            log.debug("Pool: error closing connection: %s", e)
            return None

    def _count(self, name: str) -> None:
        with self._stats_lock:
            self.stats[name] += 1

    def live(self) -> int:
        """How many sessions are open right now."""
        with self._pool_lock:
            return sum(1 for e in self._connections.values() if e["device"] is not None)

    # -- idle cleanup -----------------------------------------------------------

    def _cleanup_loop(self, token) -> None:
        while self._cleanup_token is token:
            time.sleep(CLEANUP_INTERVAL)
            if self._cleanup_token is not token:
                break
            try:
                # Nobody waits on this thread, so it sees a slow close (one
                # the router never acknowledges gives up after seconds)
                # through before it collects what the close leaves (#113).
                self._cleanup_idle(wait=REAPER_CLOSE_WAIT)
            except Exception as e:
                log.debug("Pool: cleanup pass failed: %s", e)

    def _cleanup_idle(self, now: Optional[float] = None, wait: Optional[float] = None) -> int:
        """Close sessions idle for longer than idle_timeout; returns how many.
        The closes it starts get `wait` seconds in all (CLOSE_WAIT if None)
        before what they leave is collected."""
        now = time.time() if now is None else now
        # Collect idle candidates under the global lock, then close OUTSIDE it.
        # Holding _pool_lock across a blocking device.close() (a black-holed
        # device can stall on TCP/SSH timeout) would freeze every router's
        # borrow, since get_connection() needs the same lock. Mirrors close_all.
        candidates = []
        with self._pool_lock:
            for key, entry in self._connections.items():
                if (
                    entry["device"] is not None
                    and entry["last_used"] > 0
                    and (now - entry["last_used"]) >= self._idle_timeout
                ):
                    candidates.append((key, entry))
        closed, closes = 0, []
        for key, entry in candidates:
            # Non-blocking: skip entries currently in use this cycle.
            if not entry["lock"].acquire(blocking=False):
                continue
            try:
                # Re-check under the lock: the entry may have been used or closed
                # between collection and acquiring the lock.
                if (
                    entry["device"] is not None
                    and entry["last_used"] > 0
                    and (now - entry["last_used"]) >= self._idle_timeout
                ):
                    idle = now - entry["last_used"]
                    closes.append(self._drop(entry, "reaped"))
                    closed += 1
                    log.info("Pool: closed idle connection to %s (idle %.0fs)", key, idle)
            finally:
                entry["lock"].release()
        if closed:
            _release_closed_sessions(closes, wait)
        return closed

    reap = _cleanup_idle

    def close_all(self, shutdown: bool = True, wait: Optional[float] = None,
                  busy_wait: Optional[float] = None) -> None:
        """Close all pooled connections.

        Args:
            shutdown: If True (default), don't wait on an in-flight operation —
                skip busy entries; they are closed when their borrower returns
                them. Use at exit, so a SIGTERM during a long command doesn't
                hang teardown. If False, wait for in-flight operations so a
                live RPC is not severed — use when a run is over and the next
                one must start from fresh sessions. A session a transaction
                holds open on another thread is waited for at most
                `busy_wait` seconds (BUSY_WAIT if None): the others are
                closed, and then NotAppliedError('router busy: a transaction
                is open on this session') says how many were left; each
                closes when its transaction ends (#147).
            wait: Either way, the closes it starts get this long in all
                (CLOSE_WAIT, a second, if None) to be acknowledged, so their
                descriptors are freed with them (#113).
        """
        # Snapshot entries under the global lock, then close each under its own
        # per-router lock (outside the global lock, so a slow close can't block
        # unrelated routers). Do NOT clear _connections: clearing would detach an
        # entry that an in-flight get_connection() borrow already holds, leaving
        # the connection it is about to open untracked and never reaped. Leaving
        # device=None entries behind is cheap and keeps every connection
        # reapable.
        with self._pool_lock:
            self._generation += 1
            entries = list(self._connections.items())

        closes = []     # what each close handed back, whichever thread ran it
        busy = []       # the sessions a transaction held open past busy_wait

        def close_one(item):
            key, entry = item
            if shutdown:
                if not entry["lock"].acquire(blocking=False):
                    return
            else:
                try:
                    self._take(entry, BUSY_WAIT if busy_wait is None else busy_wait)
                except NotAppliedError:
                    busy.append(key)
                    return
            try:
                closes.append(self._drop(entry, "discards"))
            finally:
                entry["lock"].release()

        live = [item for item in entries if item[1]["device"] is not None]
        _side_by_side(close_one, live)
        if live:
            _release_closed_sessions(closes, wait)
        log.info("Connection pool: all connections closed")
        if busy:
            raise NotAppliedError(f"{BUSY}: {len(busy)} session(s) left open, each closed when its "
                                  "transaction ends")


def _side_by_side(fn, items, workers: int = 32) -> None:
    """fn(item) for every item, on up to `workers` threads at once: one
    unresponsive router costs its own close timeout, not one per router in a
    row, so a 350-router exit does not stall for minutes.

    Plain threads, not an executor: concurrent.futures takes no more work
    once the interpreter is exiting, which is when the atexit close_all()
    runs. What the system gives no thread for (ulimit -u, a container's
    pids.max) the threads it did give take on; with none at all, this
    thread does it, one after another (#113)."""
    if len(items) < 2:
        for item in items:
            fn(item)
        return
    todo = iter(items)
    lock = threading.Lock()

    def work():
        while True:
            with lock:
                item = next(todo, None)
            if item is None:
                return
            fn(item)

    threads = []
    for _ in range(min(workers, len(items))):
        t = threading.Thread(target=work, daemon=True, name="hssh-pool-close")
        try:
            t.start()
        except Exception as e:      # RuntimeError: can't start new thread
            log.debug("Pool: no thread to close on (%s)", e)
            break
        threads.append(t)
    for t in threads:
        t.join()
    work()          # what no thread took: all of it when the system gave none


def _release_closed_sessions(closes, wait: Optional[float] = None) -> None:
    """A closed ncclient session keeps one descriptor until the garbage
    collector runs: its reader thread's selector (an epoll fd) is a local of
    a frame that survives in a reference cycle with the exception that ended
    the loop (#58). Five hundred closed sessions are five hundred fds until
    the next full collection; one collection here, after the closes, frees
    them now. Once per close_all() or reaper pass, never per session.

    `closes` is what the closer returned per session. The junos closer only
    starts a thread and hands it back (#98), so the collection first waits
    for those, one deadline for all of them (`wait`, CLOSE_WAIT if None);
    collected before they are done, every session is still open and nothing
    is freed (#113). What is not a thread was a close already done."""
    deadline = time.monotonic() + (CLOSE_WAIT if wait is None else wait)
    for t in closes:
        if isinstance(t, threading.Thread):
            t.join(max(0.0, deadline - time.monotonic()))
    gc.collect()


SessionPool = ConnectionPool   # the name the first h-ssh pool had

POOL = ConnectionPool()

enable = POOL.enable
disable = POOL.disable
close_all = POOL.close_all
reap = POOL.reap
live = POOL.live
