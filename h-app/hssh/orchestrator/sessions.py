"""Session manager: opens, reuses and closes sessions; pooling across calls is its option (section 3.2)."""

from __future__ import annotations

import asyncio
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Hashable

from hssh.communicators.base import Communicator, Session
from hssh.drivers import Driver
from hssh.model import Credentials, Fault, FaultKind, HostKeyPolicy, OperationResult, Target, Timeouts
from hssh.orchestrator.defaults import (ALIVE_SECONDS, DEFAULT_TIMEOUTS, FDS_BASE, FDS_PER_SESSION, FDS_PER_WORKER,
                                        open_file_limit)
from hssh.orchestrator.lifecycle import failed, now, operation

CLOSE_WAIT = 1.0
_SECRET = secrets.token_bytes(32)


class LoginRefused(Exception):
    """The gate refused a further login inside a borrow; the reason is the message."""


def session_key(driver: Driver, target: Target, creds: Credentials, host_key_policy: HostKeyPolicy = "off") -> Hashable:
    """One session is its driver, host, the port the connection uses, user, host-key policy and credential; the credential as a process-secret HMAC, so the key never holds it."""
    port = target.port if target.port is not None else driver.communicator.default_port
    credential = hmac.new(_SECRET, (creds.password or creds.key_file or "").encode(), "sha256").hexdigest()
    return (driver.name, target.host, port, creds.username, host_key_policy, credential)


@dataclass
class _Entry:
    communicator: Communicator
    session: Session | None = None
    in_use: bool = True
    idle_since: float = field(default_factory=time.monotonic)


@dataclass
class _Close:
    """One close or discard running beside the work: which target and driver it belongs to, and its fault once done."""

    target: str
    driver: str
    thread: threading.Thread | None = None
    fault: OperationResult | None = None


class SessionManager:
    """One session per key. Without pooling, release() closes; with it, the session waits for the next acquire() until close_all(). A borrow owns its session until its release cleanup is done; a second borrower of the same key waits instead of logging in again."""

    def __init__(self, pool: bool = False) -> None:
        self.pool = pool
        self.workers = 0
        self._entries: dict[Hashable, _Entry] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._waiting = asyncio.Condition()
        self._closes: list[_Close] = []

    def _cond(self) -> asyncio.Condition:
        """The borrowers' condition for the running loop: a manager kept across asyncio.run() calls gets a fresh one per loop, the old loop's waiters being gone with it."""
        loop = asyncio.get_running_loop()
        if loop is not self._loop:
            self._loop, self._waiting = loop, asyncio.Condition()
        return self._waiting

    def pooled(self, driver: Driver, target: Target, creds: Credentials, host_key_policy: HostKeyPolicy = "off") -> bool:
        """Whether an idle session to `target` is waiting, so the next acquire() is no login."""
        entry = self._entries.get(session_key(driver, target, creds, host_key_policy))
        return entry is not None and not entry.in_use and entry.session is not None

    async def acquire(self, driver: Driver, target: Target, creds: Credentials, timeouts: Timeouts,
                      host_key_policy: HostKeyPolicy, login: Callable[[], str | None] = lambda: None) -> Session:
        """A session to `target`: a kept idle one once reuse() vouches for it, else communicator.open() on the thread pool; a key in use is waited for. `login` is asked before an open that replaces a kept session: a reason refuses it (LoginRefused)."""
        key = session_key(driver, target, creds, host_key_policy)
        comm = driver.communicator
        async with self._cond():
            while (entry := self._entries.get(key)) is not None and entry.in_use:
                await self._cond().wait()
            if entry is None:
                entry = self._entries[key] = _Entry(comm)
            entry.in_use = True
        if entry.session is not None:
            idle = int(time.monotonic() - entry.idle_since)
            vouched = await operation("reuse", lambda: comm.reuse(entry.session, timeouts, idle), ALIVE_SECONDS)
            if vouched.outcome is True:
                return entry.session
            self._start(_Close(target.name, driver.name), comm.discard, entry.session)
            entry.session = None
            if (reason := login()) is not None:
                await self._drop(key)
                raise LoginRefused(reason)
        await self._make_room()
        try:
            entry.session = await asyncio.to_thread(comm.open, target, creds, timeouts, host_key_policy)
        except BaseException:
            await self._drop(key)
            raise
        return entry.session

    async def release(self, driver: Driver, target: Target, creds: Credentials, discard: bool = False, *,
                      timeouts: Timeouts | None = None, host_key_policy: HostKeyPolicy = "off") -> None:
        """Give the session back. Without pooling it is closed; `discard` tears it down with no cleanup. A kept session is cleaned by communicator.release() under two command timeouts first, and only then idle and offered to the next borrower; a cleanup fault discards it. Closes run on helper threads; wait_for_closes() joins them."""
        key = session_key(driver, target, creds, host_key_policy)
        entry = self._entries.get(key)
        if entry is None or entry.session is None:
            await self._drop(key)
            return
        close = _Close(target.name, driver.name)
        if discard:
            await self._drop(key)
            self._start(close, entry.communicator.discard, entry.session)
            return
        if not self.pool:
            await self._drop(key)
            self._start(close, entry.communicator.close, entry.session)
            return
        command = (timeouts or DEFAULT_TIMEOUTS).command
        cleaned = await operation("release", lambda: entry.communicator.release(entry.session), 2 * command)
        if failed(cleaned):
            await self._drop(key)
            close.fault = cleaned
            self._start(close, entry.communicator.discard, entry.session)
            return
        async with self._cond():
            entry.in_use = False
            entry.idle_since = time.monotonic()
            self._cond().notify_all()

    async def _drop(self, key: Hashable) -> None:
        async with self._cond():
            self._entries.pop(key, None)
            self._cond().notify_all()

    def _start(self, close: _Close, how: Callable[[Session], None], session: Session) -> None:
        self._closes.append(close)
        close.thread = threading.Thread(target=self._close, args=(close, how, session), name="hssh-close", daemon=True)
        try:
            close.thread.start()
        except RuntimeError:
            close.thread = None
            self._close(close, how, session)

    @staticmethod
    def _close(close: _Close, how: Callable[[Session], None], session: Session) -> None:
        """communicator.close() or .discard(), a fault kept as the target's trailing operation unless one is there already."""
        started, t0 = now(), time.monotonic()
        try:
            how(session)
        except Fault as f:
            close.fault = close.fault or OperationResult("close", f, started, int((time.monotonic() - t0) * 1000))
        except Exception as e:  # noqa: BLE001 - a communicator bug in close is a warning, never the run's end
            fault = Fault(FaultKind.LOCAL, f"{type(e).__name__}: {e}", True)
            close.fault = close.fault or OperationResult("close", fault, started, int((time.monotonic() - t0) * 1000))

    def wait_for_closes(self, timeout: float = CLOSE_WAIT) -> dict[str, tuple[str, OperationResult]]:
        """Join the closes still in flight, `timeout` seconds in all; one not done by then goes away with the process. Returns the close faults by target name, with the driver name."""
        deadline = time.monotonic() + timeout
        closes, self._closes = self._closes, []
        for close in closes:
            if close.thread is not None:
                close.thread.join(max(0.0, deadline - time.monotonic()))
        return {c.target: (c.driver, c.fault) for c in closes if c.fault is not None}

    async def _make_room(self) -> None:
        """Before an open: the least recently used idle sessions closed while the open-file limit cannot hold every kept one beside the workers."""
        limit = open_file_limit()
        if limit is None:
            return
        allowed = max(0, (limit - FDS_BASE - self.workers * FDS_PER_WORKER) // FDS_PER_SESSION)
        async with self._cond():
            idle = sorted(((e.idle_since, k) for k, e in self._entries.items() if not e.in_use and e.session is not None))
            for _, key in idle[:max(0, len(idle) - allowed)]:
                entry = self._entries.pop(key)
                self._start(_Close("", ""), entry.communicator.close, entry.session)

    async def close_all(self, timeout: float = CLOSE_WAIT) -> None:
        """Close every kept session, side by side, and wait `timeout` in all; one in use is torn down. Faults are not the run's."""
        async with self._cond():
            entries, self._entries = list(self._entries.values()), {}
            self._cond().notify_all()
        for entry in entries:
            if entry.session is not None:
                how = entry.communicator.discard if entry.in_use else entry.communicator.close
                self._start(_Close("", ""), how, entry.session)
        try:
            await asyncio.to_thread(self.wait_for_closes, timeout)
        except RuntimeError:
            self.wait_for_closes(timeout)
