"""Session manager: opens, reuses and closes sessions; pooling across calls is its option (section 3.2)."""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass
from typing import Hashable

from hssh.communicators.base import Communicator, Session
from hssh.drivers import Driver
from hssh.model import Credentials, Fault, FaultKind, HostKeyPolicy, OperationResult, Target, Timeouts
from hssh.orchestrator.lifecycle import now

CLOSE_WAIT = 1.0

def session_key(driver: Driver, target: Target, creds: Credentials) -> Hashable:
    """One device is its host and the port the connection uses: the target's own, else the communicator's default."""
    port = target.port if target.port is not None else driver.communicator.default_port
    return (driver.name, target.host, port, creds.username)


@dataclass
class _Entry:
    communicator: Communicator
    session: Session
    in_use: bool = False


@dataclass
class _Close:
    """One close running beside the work: which target and driver it belongs to, and its fault once done."""

    target: str
    driver: str
    thread: threading.Thread | None = None
    fault: OperationResult | None = None


class SessionManager:
    """One open session per (driver, host, port, user). Without pooling, release() closes; with it, the session waits for the next acquire() until close_all()."""

    def __init__(self, pool: bool = False) -> None:
        self.pool = pool
        self._entries: dict[Hashable, _Entry] = {}
        self._lock = asyncio.Lock()
        self._closes: list[_Close] = []

    def pooled(self, driver: Driver, target: Target, creds: Credentials) -> bool:
        """Whether an idle session to `target` is waiting, so the next acquire() is no login."""
        entry = self._entries.get(session_key(driver, target, creds))
        return entry is not None and not entry.in_use

    async def acquire(self, driver: Driver, target: Target, creds: Credentials, timeouts: Timeouts,
                      host_key_policy: HostKeyPolicy) -> Session:
        """A session to `target`: a pooled idle one, else communicator.open() on the thread pool."""
        key = session_key(driver, target, creds)
        async with self._lock:
            entry = self._entries.get(key)
            if entry is not None and not entry.in_use:
                entry.in_use = True
                return entry.session
        session = await asyncio.to_thread(driver.communicator.open, target, creds, timeouts, host_key_policy)
        async with self._lock:
            self._entries[key] = _Entry(driver.communicator, session, in_use=True)
        return session

    async def release(self, driver: Driver, target: Target, creds: Credentials, discard: bool = False) -> None:
        """Give the session back: closed unless pooling keeps it; `discard` closes it regardless. The close runs on a helper thread, so the worker is free at once; wait_for_closes() joins it."""
        key = session_key(driver, target, creds)
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return
            entry.in_use = False
            if self.pool and not discard:
                return
            del self._entries[key]
        close = _Close(target.name, driver.name)
        close.thread = threading.Thread(target=self._close, args=(entry, close), name="hssh-close", daemon=True)
        self._closes.append(close)
        try:
            close.thread.start()
        except RuntimeError:
            close.thread = None
            await asyncio.to_thread(self._close, entry, close)

    @staticmethod
    def _close(entry: _Entry, close: _Close) -> None:
        """communicator.close(), its fault kept as the target's trailing 'close' operation."""
        started, t0 = now(), time.monotonic()
        try:
            entry.communicator.close(entry.session)
        except Fault as f:
            close.fault = OperationResult("close", f, started, int((time.monotonic() - t0) * 1000))
        except Exception as e:  # noqa: BLE001 - a communicator bug in close is a warning, never the run's end
            fault = Fault(FaultKind.LOCAL, f"{type(e).__name__}: {e}", True)
            close.fault = OperationResult("close", fault, started, int((time.monotonic() - t0) * 1000))

    def wait_for_closes(self, timeout: float = CLOSE_WAIT) -> dict[str, tuple[str, OperationResult]]:
        """Join the closes still in flight, `timeout` seconds in all; one not done by then goes away with the process. Returns the close faults by target name, with the driver name."""
        deadline = time.monotonic() + timeout
        closes, self._closes = self._closes, []
        for close in closes:
            if close.thread is not None:
                close.thread.join(max(0.0, deadline - time.monotonic()))
        return {c.target: (c.driver, c.fault) for c in closes if c.fault is not None}

    async def close_all(self) -> None:
        """Close every session, in-flight ones included; a close that fails is not the run's failure."""
        async with self._lock:
            entries, self._entries = list(self._entries.values()), {}
        for entry in entries:
            try:
                await asyncio.to_thread(entry.communicator.close, entry.session)
            except Exception:  # noqa: BLE001
                pass
