"""Session manager: opens, reuses and closes sessions; pooling across calls is its option (section 3.2)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Hashable

from hssh.communicators.base import Communicator, Session
from hssh.drivers import Driver
from hssh.model import Credentials, Fault, HostKeyPolicy, OperationResult, Target, Timeouts
from hssh.orchestrator.lifecycle import operation

def session_key(driver: Driver, target: Target, creds: Credentials) -> Hashable:
    return (driver.name, target.host, target.port, creds.username)


@dataclass
class _Entry:
    communicator: Communicator
    session: Session
    in_use: bool = False


class SessionManager:
    """One open session per (driver, host, port, user). Without pooling, release() closes; with it, the session waits for the next acquire() until close_all()."""

    def __init__(self, pool: bool = False) -> None:
        self.pool = pool
        self._entries: dict[Hashable, _Entry] = {}
        self._lock = asyncio.Lock()

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

    async def release(self, driver: Driver, target: Target, creds: Credentials,
                      discard: bool = False) -> OperationResult | None:
        """Give the session back: closed unless pooling keeps it; `discard` closes it regardless. A close that faults is returned as an operation named 'close'."""
        key = session_key(driver, target, creds)
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            entry.in_use = False
            if self.pool and not discard:
                return None
            del self._entries[key]
        closed = await operation("close", lambda: entry.communicator.close(entry.session))
        return closed if isinstance(closed.outcome, Fault) else None

    async def close_all(self) -> None:
        """Close every session, in-flight ones included; a close that fails is not the run's failure."""
        async with self._lock:
            entries, self._entries = list(self._entries.values()), {}
        for entry in entries:
            try:
                await asyncio.to_thread(entry.communicator.close, entry.session)
            except Exception:  # noqa: BLE001
                pass
