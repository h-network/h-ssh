"""Per-device admission and login limits, with persistent cooldowns."""

from __future__ import annotations

import fcntl
import json
import math
import os
import tempfile
import threading
import time
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path

from hssh.audit import private_dir, private_file
from hssh.model import SafetySettings, Target


def _key(target: Target) -> str:
    return target.host if target.port is None else f"{target.host}|{target.port}"


def _expiry(key: str, value: object) -> float | None:
    if value is None:
        return None
    try:
        expires = float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else math.nan
    except OverflowError:
        expires = math.nan
    if not math.isfinite(expires):
        raise ValueError(f"cooldown of {key!r} is not a finite number")
    return expires


class SafetyGate:
    def __init__(self, settings: SafetySettings) -> None:
        for name in ("rate_limit", "cooldown_seconds"):
            value = getattr(settings, name)
            try:
                if type(value) is not int or value < 0:
                    raise ValueError(f"{name} must be a non-negative integer")
                _expiry(name, value)
            except ValueError as error:
                raise OSError(f"invalid safety settings: {error}") from error
        self.settings = settings
        self._path = Path.cwd() / settings.safety_file if settings.safety_file is not None else None
        self._lock = threading.RLock()
        self._active: set[str] = set()
        self._attempts: dict[str, list[float]] = {}
        self._cooldowns: dict[str, float] = {}
        self._failure: str | None = None
        self._closed = False
        self._sync(persist=True)

    def _ready(self) -> None:
        if self._closed:
            raise OSError("safety gate is closed")
        if self._failure is not None:
            raise OSError(self._failure)

    def _reason(self, target: Target, now: float) -> str | None:
        keys = {_key(target), target.host}
        if target.port is None:
            keys.update(key for key in self._cooldowns if key.startswith(f"{target.host}|"))
        expires = max((self._cooldowns.get(key, now) for key in keys), default=now)
        if expires > now:
            return f"cooldown active ({math.ceil(expires - now)}s remaining)"
        return None

    def check_device(self, target: Target, *, login: bool = True) -> tuple[bool, str]:
        """Admission reserves the device; only a new login consumes the per-minute budget."""
        with self._lock:
            self._sync()
            if reason := self._reason(target, time.time()):
                return False, reason
            key = _key(target)
            if key in self._active:
                return False, "active connection"
            if login:
                now = time.monotonic()
                attempts = [when for when in self._attempts.get(key, []) if now - when < 60]
                self._attempts[key] = attempts
                if len(attempts) >= self.settings.rate_limit:
                    return False, f"rate limited {len(attempts)}/{self.settings.rate_limit}"
                attempts.append(now)
            self._active.add(key)
            return True, "ok"

    def holds(self, targets: Sequence[Target]) -> dict[str, str]:
        """Return cooldown reasons by target name without reserving or counting logins."""
        with self._lock:
            self._sync()
            now = time.time()
            return {target.name: reason for target in targets if (reason := self._reason(target, now))}

    def release_device(self, target: Target) -> None:
        with self._lock:
            self._active.discard(_key(target))

    def set_cooldown(self, target: Target) -> None:
        with self._lock:
            self._ready()
            key = _key(target)
            self._active.discard(key)
            expires = time.time() + self.settings.cooldown_seconds
            self._cooldowns[key] = max(expires, self._cooldowns.get(key, expires))
            self._sync(persist=True)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._sync(persist=True)
            finally:
                self._closed = True
                self._active.clear()
                self._attempts.clear()

    @contextmanager
    def _file_lock(self):
        private_dir(self._path.parent)
        with private_file(str(self._path) + ".lock", os.O_RDWR | os.O_CREAT) as fd:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield

    def _read(self) -> dict[str, float]:
        corrupt = str(self._path) + ".corrupt"
        if os.path.lexists(corrupt):
            raise OSError(f"corrupt safety state preserved at {corrupt}; inspect and repair it before a new run")
        try:
            with private_file(str(self._path), os.O_RDONLY) as fd:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
                    text = stream.read()
            data = json.loads(text) if text else {}
            if not isinstance(data, dict):
                raise ValueError("safety state must be a JSON object")
            cooldowns = {}
            for key, value in data.items():
                expires = _expiry(key, value)
                if expires is not None:
                    cooldowns[key] = expires
            return cooldowns
        except FileNotFoundError:
            return {}
        except (ValueError, RecursionError) as error:
            os.replace(self._path, corrupt)
            raise OSError(f"invalid safety state preserved at {corrupt}: {error}") from error

    def _write(self, cooldowns: dict[str, float]) -> None:
        fd, temporary = tempfile.mkstemp(dir=self._path.parent, prefix=self._path.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                fd = None
                os.fchmod(stream.fileno(), 0o600)
                json.dump(cooldowns, stream, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._path)
            directory = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _sync(self, *, persist: bool = False) -> None:
        self._ready()
        if self._path is None:
            now = time.time()
            self._cooldowns = {key: expires for key, expires in self._cooldowns.items() if expires > now}
            return
        try:
            with self._file_lock():
                merged = self._read()
                now = time.time()
                for key, expires in self._cooldowns.items():
                    merged[key] = max(expires, merged.get(key, expires))
                merged = {key: expires for key, expires in merged.items() if expires > now}
                if persist:
                    self._write(merged)
                self._cooldowns = merged
        except (OSError, ValueError) as error:
            self._failure = f"safety file {self._path}: {error}; gate unavailable (fail-closed)"
            raise OSError(self._failure) from error
