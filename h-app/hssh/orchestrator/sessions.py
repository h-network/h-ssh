"""Session manager: opens, reuses and closes sessions; pooling across calls is its option (section 3.2)."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Hashable

from hssh.communicators.base import Communicator, Session
from hssh.drivers import Driver
from hssh.model import Credentials, HostKeyPolicy, Target, Timeouts

DEFAULT_IDLE_TIMEOUT = 300.0


def session_key(driver: Driver, target: Target, creds: Credentials) -> Hashable:
    return (driver.name, target.host, target.port, creds.username)


@dataclass
class _Entry:
    communicator: Communicator
    session: Session
    last_used: float = field(default_factory=time.monotonic)
    in_use: bool = False


class SessionManager:
    """One open session per (driver, host, port, user). Without pooling, release() closes; with it, the session waits for the next acquire() until idle_timeout."""

    def __init__(self, pool: bool = False, idle_timeout: float = DEFAULT_IDLE_TIMEOUT) -> None:
        self.pool = pool
        self.idle_timeout = idle_timeout
        self._entries: dict[Hashable, _Entry] = {}
        self._lock = asyncio.Lock()

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
        """Give the session back: closed unless pooling keeps it; `discard` closes it regardless."""
        key = session_key(driver, target, creds)
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return
            entry.in_use = False
            entry.last_used = time.monotonic()
            if self.pool and not discard:
                return
            del self._entries[key]
        await asyncio.to_thread(entry.communicator.close, entry.session)

    async def close_idle(self, now: float | None = None) -> int:
        """Close pooled sessions idle longer than idle_timeout; returns how many."""
        ...

    async def close_all(self) -> None:
        """Close every session, in-flight ones included, without waiting on their operations."""
        ...
