"""Session pool — keep a device session open between calls.

Off by default. The CLI never enables it, so a one-shot run still opens and
closes one session per operation, exactly as before. Library code that makes
many calls against the same router enables it once:

    from hssh import pool
    pool.enable()                 # sessions idle for 300 s are closed
    ... vendors.junos.show(...)   # every call now reuses the router's session
    pool.close_all()              # or leave it to atexit

One session per (host, port, user). A per-key lock means a session is never
used by two threads at once — same-router calls queue, different routers run
in parallel. The driver decides when a session is no good (`lease.discard()`),
a daemon thread reaps sessions nobody has used for `idle_timeout` seconds,
and `close_all` runs at interpreter exit.

Modelled on the pool in Juniper/junos-mcp-server (PR #27), cut down to what a
script needs.
"""

import atexit
import threading
import time
from contextlib import contextmanager
from typing import Callable, Dict, Hashable, Optional

DEFAULT_IDLE_TIMEOUT = 300
REAP_INTERVAL = 60


class Lease:
    """What a borrower gets: the session, whether it was reused, and a way to
    say it is no good. A discarded session is closed on return instead of kept."""

    __slots__ = ("dev", "reused", "discarded")

    def __init__(self, dev, reused: bool):
        self.dev = dev
        self.reused = reused
        self.discarded = False

    def discard(self) -> None:
        self.discarded = True


class _Entry:
    __slots__ = ("lock", "dev", "closer", "last_used", "generation")

    def __init__(self):
        self.lock = threading.Lock()
        self.dev = None
        self.closer: Optional[Callable] = None
        self.last_used = 0.0
        self.generation = 0


class SessionPool:
    def __init__(self, idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
                 reap_interval: float = REAP_INTERVAL):
        self.idle_timeout = idle_timeout
        self.reap_interval = reap_interval
        self._enabled = False
        self._entries: Dict[Hashable, _Entry] = {}
        self._lock = threading.Lock()  # guards _entries, stats and the reaper
        self._reaper: Optional[threading.Thread] = None
        self._stop: Optional[threading.Event] = None
        # Bumped by close_all(): a session borrowed before the bump is closed
        # on return instead of going back into the pool.
        self._generation = 0
        self.stats = {"opens": 0, "reuses": 0, "discards": 0, "reaped": 0}
        atexit.register(self.close_all)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self, idle_timeout: Optional[float] = None) -> None:
        """Start reusing sessions. Idempotent."""
        with self._lock:
            if idle_timeout is not None:
                self.idle_timeout = idle_timeout
            if self._enabled:
                return
            self._enabled = True
            # Each reaper owns its stop event, so a reaper still finishing a
            # pass when disable() -> enable() happens cannot pick up the new
            # one's flag and live on beside it.
            stop = threading.Event()
            self._stop = stop
            self._reaper = threading.Thread(
                target=self._reap_loop, args=(stop,), name="hssh-pool-reaper", daemon=True)
            self._reaper.start()

    def disable(self) -> None:
        """Close every session and go back to one session per call."""
        with self._lock:
            self._enabled = False
            if self._stop is not None:
                self._stop.set()
        self.close_all()

    @contextmanager
    def lease(self, key: Hashable, opener: Callable, closer: Callable,
              alive: Optional[Callable] = None):
        """Borrow the session for `key`, opening it with `opener()` if needed.

        Holds the key's lock for the duration, so same-key borrowers queue.
        `alive(dev, idle_seconds)` is asked before a session is reused; False
        or an exception means it is closed and a new one opened. Whatever
        `opener()` raises propagates untouched and leaves the slot empty.
        With the pool disabled this is plain open -> yield -> close.
        """
        if not self._enabled:
            dev = opener()
            try:
                yield Lease(dev, reused=False)
            finally:
                closer(dev)
            return

        entry = self._entry(key)
        with entry.lock:
            dev = entry.dev
            reused = dev is not None
            if reused and alive is not None:
                try:
                    ok = alive(dev, time.monotonic() - entry.last_used)
                except Exception:
                    ok = False
                if not ok:
                    self._drop(entry, "discards")
                    dev, reused = None, False
            if dev is None:
                dev = opener()
                entry.dev, entry.closer = dev, closer
                entry.generation = self._generation
                self._count("opens")
            else:
                self._count("reuses")
            lease = Lease(dev, reused)
            try:
                yield lease
            finally:
                entry.last_used = time.monotonic()
                if (lease.discarded or not self._enabled
                        or entry.generation != self._generation):
                    self._drop(entry, "discards")

    def close_all(self, wait: float = 5.0) -> None:
        """Close every pooled session. Waits up to `wait` seconds for a busy
        one; a session still busy after that is closed when its borrower
        returns it. Safe to call twice."""
        with self._lock:
            self._generation += 1
            entries = list(self._entries.values())
        for entry in entries:
            if not entry.lock.acquire(timeout=wait):
                continue
            try:
                self._drop(entry, "discards")
            finally:
                entry.lock.release()

    def reap(self, now: Optional[float] = None) -> int:
        """Close sessions idle for longer than idle_timeout. Never waits on a
        busy one. Returns how many were closed."""
        now = time.monotonic() if now is None else now
        with self._lock:
            entries = list(self._entries.values())
        closed = 0
        for entry in entries:
            if not entry.lock.acquire(blocking=False):
                continue
            try:
                if entry.dev is not None and now - entry.last_used >= self.idle_timeout:
                    self._drop(entry, "reaped")
                    closed += 1
            finally:
                entry.lock.release()
        return closed

    def live(self) -> int:
        """How many sessions are open right now."""
        with self._lock:
            return sum(1 for e in self._entries.values() if e.dev is not None)

    # -- internals --------------------------------------------------------

    def _entry(self, key: Hashable) -> _Entry:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = self._entries[key] = _Entry()
            return entry

    def _drop(self, entry: _Entry, counter: str) -> None:
        """Close and forget the entry's session. Caller holds entry.lock."""
        dev, entry.dev = entry.dev, None
        if dev is None:
            return
        self._count(counter)
        try:
            entry.closer(dev)
        except Exception:
            pass

    def _count(self, name: str) -> None:
        with self._lock:
            self.stats[name] += 1

    def _reap_loop(self, stop: threading.Event) -> None:
        while not stop.wait(self.reap_interval):
            try:
                self.reap()
            except Exception:
                pass


POOL = SessionPool()

enable = POOL.enable
disable = POOL.disable
close_all = POOL.close_all
reap = POOL.reap
live = POOL.live
