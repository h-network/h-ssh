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
  can keep using the same session through the pool
- entries are keyed by whatever the driver passes (host, port, user), the
  driver supplies the opener/closer, so the pool knows no vendor

    from hssh import pool
    pool.enable()                 # sessions idle for 300 s are closed
    ... transports.netconf.show(...)   # every call now reuses the router's session
    pool.close_all()              # or leave it to atexit
"""

import atexit
from concurrent.futures import ThreadPoolExecutor
import gc
import logging
import os
import threading
import time
from contextlib import contextmanager
from typing import Callable, Dict, Hashable, Optional

log = logging.getLogger("hssh.pool")

DEFAULT_IDLE_TIMEOUT = 300
CLEANUP_INTERVAL = 60
CLOSE_WAIT = 1.0        # how long close_all() and the reaper wait for the closes they started, in all


class Lease:
    """What a borrower gets: the session, whether it was reused, and a way to
    say it is no good. A discarded session is closed when the outermost
    borrow returns it — not before, so a call nested inside an open
    transaction cannot pull the session out from under it."""

    __slots__ = ("dev", "reused", "discarded", "_entry")

    def __init__(self, dev, reused: bool, entry: Optional[dict] = None):
        self.dev = dev
        self.reused = reused
        self.discarded = False
        self._entry = entry

    def discard(self) -> None:
        self.discarded = True

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
        """Start reusing sessions. Idempotent."""
        with self._pool_lock:
            if idle_timeout is not None:
                self._idle_timeout = idle_timeout
            if self._enabled:
                return
            self._enabled = True
            token = object()
            self._cleanup_token = token
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_loop, args=(token,), daemon=True, name="hssh-pool-cleanup"
            )
            self._cleanup_thread.start()
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
                       timeout: Optional[float] = None, alive: Optional[Callable] = None):
        """Get a pooled device session. Creates or reuses as needed.

        Args:
            key: What identifies the router to this pool (the junos driver
                uses (host, port, user))
            opener: Opens and returns a session; whatever it raises propagates
                untouched and leaves the slot empty
            closer: Closes a session this pool is done with; may return a
                thread that is still finishing the close, which close_all()
                and the reaper wait for before they collect what it leaves
            timeout: Command timeout to set on the device for this borrow
            alive: alive(dev, idle_seconds) asked before a session is reused;
                False or an exception means it is closed and a new one opened

        Yields:
            A Lease: .dev is the open session, .reused says whether it came
            from the pool, .discard() closes it on return instead of keeping it

        Note:
            The per-router lock serializes same-router work: other threads
            wanting this router wait, the thread holding it may re-enter.
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
        entry["lock"].acquire()
        entry["depth"] += 1          # re-entrant: >1 means a call nested in an open borrow
        nested = entry["depth"] > 1
        lease = None
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
        except Exception:
            # Invalidate the pooled connection if the transport dropped; the
            # driver signals the other cases (an RPC that timed out, a commit
            # whose outcome is unknown) through lease.discard().
            dev = entry["device"]
            if dev is not None and not getattr(dev, "connected", True):
                entry["doomed"] = True
            raise
        finally:
            if lease is not None and lease.discarded:
                entry["doomed"] = True
            entry["depth"] -= 1
            # Only the outermost borrow closes: a nested call that found the
            # session dead has marked it, and the holder of the outer borrow
            # (a Transaction) still needs to finish on its own terms.
            if entry["depth"] == 0:
                if entry["device"] is not None and (
                    entry["doomed"] or not self._enabled or entry["generation"] != self._generation
                ):
                    self._drop(entry, "discards")
                entry["doomed"] = False
            # Refresh last_used on every borrow — success OR failure. Otherwise a
            # connection whose operation raised while still connected keeps
            # last_used at 0.0, and the idle-cleanup loop (which requires
            # last_used > 0) would never reap it.
            entry["last_used"] = time.time()
            try:
                entry["lock"].release()
            except RuntimeError:
                # Released from a thread that does not own the RLock: the
                # owner still holds it. Say so instead of hiding a sent
                # commit behind a lock error.
                log.error("Pool: borrow of %s returned from a thread that did not take it", key)

    # kept for callers written against the first h-ssh pool
    lease = get_connection

    def _get_or_create_entry(self, key: Hashable) -> dict:
        with self._pool_lock:
            if key not in self._connections:
                self._connections[key] = {
                    "device": None,
                    "closer": None,
                    "lock": threading.RLock(),
                    "last_used": 0.0,
                    "generation": 0,
                    "depth": 0,
                    "doomed": False,
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
        Returns what the closer returned: the thread still finishing the
        close, if it handed the close to one, else None."""
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
        with self._pool_lock:
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
                self._cleanup_idle()
            except Exception as e:
                log.debug("Pool: cleanup pass failed: %s", e)

    def _cleanup_idle(self, now: Optional[float] = None) -> int:
        """Close sessions idle for longer than idle_timeout; returns how many."""
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
            _release_closed_sessions(closes)
        return closed

    reap = _cleanup_idle

    def close_all(self, shutdown: bool = True) -> None:
        """Close all pooled connections.

        Args:
            shutdown: If True (default), don't wait on an in-flight operation —
                skip busy entries; they are closed when their borrower returns
                them. Use at exit, so a SIGTERM during a long command doesn't
                hang teardown. If False, wait for in-flight operations so a
                live RPC is not severed — use when a run is over and the next
                one must start from fresh sessions.
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

        def close_one(item):
            key, entry = item
            if shutdown:
                if not entry["lock"].acquire(blocking=False):
                    return None
            else:
                entry["lock"].acquire()
            try:
                return self._drop(entry, "discards")
            finally:
                entry["lock"].release()

        # Closes run side by side: one unresponsive router costs its own close
        # timeout, not one per router in a row, so a 350-router exit does not
        # stall for minutes.
        live = [item for item in entries if item[1]["device"] is not None]
        if len(live) > 1:
            with ThreadPoolExecutor(max_workers=min(32, len(live)), thread_name_prefix="hssh-pool-close") as ex:
                closes = list(ex.map(close_one, live))
        else:
            closes = [close_one(item) for item in live]
        if live:
            _release_closed_sessions(closes)
        log.info("Connection pool: all connections closed")


def _release_closed_sessions(closes, timeout: float = CLOSE_WAIT) -> None:
    """A closed ncclient session keeps one descriptor until the garbage
    collector runs: its reader thread's selector (an epoll fd) is a local of
    a frame that survives in a reference cycle with the exception that ended
    the loop (#58). Five hundred closed sessions are five hundred fds until
    the next full collection; one collection here, after the closes, frees
    them now. Once per close_all() or reaper pass, never per session.

    `closes` is what the closer returned per session. The junos closer only
    starts a thread and hands it back (#98), so the collection first waits
    for those, one deadline for all of them; collected before they are done,
    every session is still open and nothing is freed (#113)."""
    deadline = time.monotonic() + timeout
    for t in closes:
        if t is not None:
            t.join(max(0.0, deadline - time.monotonic()))
    gc.collect()


SessionPool = ConnectionPool   # the name the first h-ssh pool had

POOL = ConnectionPool()

enable = POOL.enable
disable = POOL.disable
close_all = POOL.close_all
reap = POOL.reap
live = POOL.live
