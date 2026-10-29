"""Per-device safety gate: rate limiting and cooldown for h-ssh runner.

Two-tier design:
  Tier 1 (in-memory): active set, sliding window attempt tracker, thread safety.
  Tier 2 (file-based): atomic cooldown persistence with lockfile, merge-under-lock,
                       tempfile + os.replace, 0600 permissions, and fail-closed corrupt protection.

A device is its host and the port its transport uses, as everywhere in
h-ssh (#145): two routers behind one address on two ports are two devices.
Both tiers key on it, `host|port` in the file; a caller that names no port
keys on the host alone, as every key was before, and such an entry in the
file holds every port of that host. Asked about the host alone, the gate
answers for the host as a whole: held while any port of it is cooling.
"""

from contextlib import contextmanager
import fcntl
import json
import logging
import math
import os
import stat
from pathlib import Path
import tempfile
import threading
import time

from .audit import private_dir
from typing import Generator, Optional

logger = logging.getLogger(__name__)


def _key(host: str, port: Optional[int]) -> str:
    """A device's key in both tiers: `host|port`; the host alone without a port."""
    return host if port is None else f"{host}|{port}"


def _expiry(host, value) -> Optional[float]:
    """A cooldown's end as the safety file holds it: a finite number, or
    null for none. Anything else (Infinity, NaN or 1e400, which json.load
    takes; "never", "inf", an object) is not h-ssh's writing, and the file
    is corrupt: int() of an inf raised OverflowError out of check_device,
    and a word passed as no cooldown and was erased by the next save (#152)."""
    if value is None:
        return None
    try:
        expires = float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else math.nan
    except OverflowError:       # an int too large for a float (10**400): no number h-ssh wrote
        expires = math.nan
    if not math.isfinite(expires):
        raise ValueError(f"cooldown of {host!r} is {value!r:.40}, not a finite number")
    return expires


class SafetyGate:
    """Per-device rate limiting and cross-invocation cooldown.

    Args:
        safety_file: Path to JSON cooldown file. None = in-memory only.
        rate_limit: Max logins per device within rate_window (default 10).
        cooldown_seconds: Seconds to block a device after failure (default 120).
        rate_window: Sliding window duration in seconds (default 60.0).
    """

    def __init__(
        self,
        safety_file: Optional[str] = None,
        rate_limit: int = 10,
        cooldown_seconds: int = 120,
        rate_window: float = 60.0,
    ):
        for what, value in (("rate_limit", rate_limit), ("cooldown_seconds", cooldown_seconds),
                            ("rate_window", rate_window)):
            # inf was taken, and a cooldown of time.time() + inf wrote `Infinity`
            # into the file, which is not JSON and crashed the next run (#152).
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError(f"SafetyGate {what} must be a finite number, not {value!r}")
        self._safety_file = safety_file
        self._rate_limit = rate_limit
        self._cooldown_seconds = cooldown_seconds
        self._rate_window = rate_window

        # Thread safety lock
        self._lock = threading.RLock()

        # Tier 1: in-memory state
        self._active: set[str] = set()
        self._attempt_timestamps: dict[str, list[float]] = {}

        # Tier 2: file-based state
        self._cooldowns: dict[str, float] = {}
        self._corrupt = False

        if self._safety_file:
            self._probe()
            self._load_cooldowns()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def rate_limit(self) -> int:
        """The logins a device may have within rate_window."""
        return self._rate_limit

    @property
    def rate_window(self) -> float:
        return self._rate_window

    def check_device(self, host: str, port: Optional[int] = None, *, login: bool = True) -> tuple[bool, str]:
        """Check whether a device, `host` and `port`, is safe to contact.
        Without a port it is the host as a whole, which a cooldown on any
        port of it turns away.

        Returns (allowed, reason). The device is added to _active BEFORE
        returning True — crash before release_device() keeps it blocked
        (fail-closed).

        The rate limit counts logins (#145): `login` False is an attempt
        that opens no session of its own, one that rides a session already
        open to the device (a job's later entry on its pooled NETCONF
        session) or contacts no device at all (a dry run of a read). It is
        turned away by a cooldown or an active mark as any other, never by
        the rate limit, and is not counted.
        """
        key = _key(host, port)
        with self._lock:
            # Re-read cooldowns from disk to catch external changes and check corruption
            if self._safety_file:
                self._load_cooldowns()
                if self._corrupt:
                    return False, (f"safety file corrupted (fail-closed): check and remove "
                                   f"{self._safety_file}.corrupt to clear it")

            # Tier 2: cooldown check
            now = time.time()
            expires = self._cooldown_ends(host, port, now)
            if expires is not None:
                remaining = int(expires - now)
                return False, f"cooldown active ({remaining}s remaining)"

            # Tier 1: active connection in this invocation
            if key in self._active:
                return False, "active connection"

            # Tier 1: sliding window rate limit, on the logins
            if login:
                timestamps = [
                    ts for ts in self._attempt_timestamps.get(key, [])
                    if (now - ts) < self._rate_window
                ]
                self._attempt_timestamps[key] = timestamps

                count = len(timestamps)
                if count >= self._rate_limit:
                    return False, f"rate limited {count}/{self._rate_limit}"
                timestamps.append(now)

            # Allow and mark active (fail-closed)
            self._active.add(key)
            return True, "ok"

    def holds(self, devices) -> dict:
        """{device: why} for each of `devices`, (host, port) pairs (or a
        host alone, the host as a whole), that check_device() would turn
        away now for a reason that outlasts this run: a cooldown, a corrupt
        safety file. Nothing is recorded; the probe asks before it
        connects, so a box in cooldown gets no connection from it either."""
        with self._lock:
            if self._safety_file:
                self._load_cooldowns()
                if self._corrupt:
                    why = (f"safety file corrupted (fail-closed): check and remove "
                           f"{self._safety_file}.corrupt to clear it")
                    return {device: why for device in devices}
            now = time.time()
            held = {}
            for device in devices:
                host, port = device if isinstance(device, tuple) else (device, None)
                expires = self._cooldown_ends(host, port, now)
                if expires is not None:
                    held[device] = f"cooldown active ({int(expires - now)}s remaining)"
            return held

    def release_device(self, host: str, port: Optional[int] = None) -> None:
        """Release a device from the active set after a successful operation."""
        with self._lock:
            self._active.discard(_key(host, port))

    def set_cooldown(self, host: str, port: Optional[int] = None) -> None:
        """Set a cooldown on a device after a failure. Persists to file."""
        key = _key(host, port)
        with self._lock:
            self._active.discard(key)
            expires = time.time() + self._cooldown_seconds
            self._cooldowns[key] = expires
            if self._safety_file:
                self._save_cooldowns()

    def _cooldown_ends(self, host: str, port: Optional[int], now: float) -> Optional[float]:
        """When the device's cooldown ends; None when none is running. Its
        own entry counts, and one kept under the host alone (by a caller
        that names no port, or an h-ssh before #145), which holds every
        port of the host. Without a port the device is the host as a
        whole, held while any port of it is cooling, so a caller that names
        none still sees the cooldowns h-ssh keeps as `host|port`. The
        latest of them."""
        keys = {_key(host, port), host}
        if port is None:
            keys.update(k for k in self._cooldowns if k.startswith(f"{host}|"))
        ends = [self._cooldowns[k] for k in keys if now < self._cooldowns.get(k, now)]
        return max(ends) if ends else None

    def close(self) -> None:
        """Prune expired cooldowns and persist to file."""
        with self._lock:
            if self._corrupt:
                return
            self._prune_expired()
            if self._safety_file:
                self._save_cooldowns()

    # ------------------------------------------------------------------
    # File persistence (Tier 2)
    # ------------------------------------------------------------------

    def _probe(self) -> None:
        """A gate that was asked for must exist: the directory creatable, the
        lock file and the state file creatable as regular files (0600) and
        the lock takeable. Raises OSError naming the reason, so the run
        refuses to start instead of continuing unguarded on a warning."""
        path = Path(self._safety_file)
        try:
            private_dir(path.parent)
        except OSError as e:
            raise OSError(f"safety file {self._safety_file}: cannot create its directory ({e.strerror})") from e
        for p in (Path(f"{self._safety_file}.lock"), path):
            try:
                fd = os.open(str(p), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except OSError as e:
                raise OSError(f"safety file {p}: cannot be created or opened ({e.strerror})") from e
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError(f"safety file {p}: not a regular file")
                if p.suffix == ".lock":
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except BlockingIOError:
                        pass            # another run holds it: the lock works
                    except OSError as e:
                        raise OSError(f"safety file {p}: cannot be locked ({e.strerror})") from e
            finally:
                os.close(fd)

    @contextmanager
    def _file_lock(self) -> Generator[None, None, None]:
        """Acquire an exclusive advisory flock on the safety lockfile.

        Exactly one yield, outside any except: an error raised in the locked
        body must come back as itself (a second yield would turn it into
        contextlib's RuntimeError). A lock that cannot be taken is logged and
        the body runs without it.
        """
        fd = None
        if self._safety_file:
            lock_path = Path(f"{self._safety_file}.lock")
            try:
                private_dir(lock_path.parent)
                fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError(f"{lock_path} is not a regular file")
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError as e:
                logger.warning("Could not lock safety file %s: %s (continuing without file lock)", lock_path, e)
                if fd is not None:
                    os.close(fd)
                    fd = None
        try:
            yield
        finally:
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _mark_corrupt(self, path: Path) -> None:
        """Mark as corrupt and move corrupt file aside to .corrupt."""
        self._corrupt = True
        try:
            if path.exists():
                corrupt_path = Path(f"{self._safety_file}.corrupt")
                os.replace(str(path), str(corrupt_path))
        except OSError:
            pass

    def _load_cooldowns(self) -> None:
        """Load cooldown data from file, merging with in-memory entries."""
        if not self._safety_file:
            return

        corrupt_path = Path(f"{self._safety_file}.corrupt")
        if corrupt_path.exists():
            self._corrupt = True
            return

        path = Path(self._safety_file)
        if not path.exists():
            self._corrupt = False
            return

        try:
            # 0-byte file is treated as empty dictionary
            if path.stat().st_size == 0:
                self._corrupt = False
                return

            with open(path, "r", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                try:
                    data = json.load(f)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

            if not isinstance(data, dict):
                self._mark_corrupt(path)
                logger.error("Safety file %s has invalid non-dictionary structure", self._safety_file)
                return

            self._corrupt = False
            now = time.time()
            disk_cooldowns = {}
            for host, expires in data.items():
                expires = _expiry(host, expires)      # a ValueError: corrupt, below
                if expires is not None and expires > now:
                    disk_cooldowns[str(host)] = expires

            # Merge: disk entries and memory entries
            for host, expires in disk_cooldowns.items():
                if host not in self._cooldowns or expires > self._cooldowns[host]:
                    self._cooldowns[host] = expires

        except (json.JSONDecodeError, ValueError) as e:
            self._mark_corrupt(path)
            logger.error("Could not parse safety file %s: %s (fail-closed)", self._safety_file, e)
        except OSError as e:
            logger.warning("Could not read safety file %s: %s (continuing in-memory only)", self._safety_file, e)

    def _save_cooldowns(self) -> None:
        """Persist cooldown data to file with exclusive lock, merge, and atomic replace."""
        if self._corrupt:
            return

        path = Path(self._safety_file)
        try:
            private_dir(path.parent)
        except OSError as e:
            logger.warning("Could not create directory for safety file %s: %s", self._safety_file, e)
            return

        with self._file_lock():
            now = time.time()
            # Read current on-disk entries to merge. The stat is in the try
            # too: a file that cannot be stat'ed is a read failure like any
            # other, logged and worked around, not an error out of the lock.
            merged: dict[str, float] = {}
            try:
                if path.exists() and path.stat().st_size > 0:
                    with open(path, "r", encoding="utf-8") as f:
                        disk_data = json.load(f)
                        if not isinstance(disk_data, dict):
                            raise ValueError("invalid non-dictionary structure")
                        for h, exp in disk_data.items():
                            exp = _expiry(h, exp)
                            if exp is not None and exp > now:
                                merged[str(h)] = exp
            except ValueError as e:
                # Not h-ssh's writing (unparsable, or a cooldown that is no
                # finite number): kept as .corrupt, never written over.
                self._mark_corrupt(path)
                logger.error("Could not parse safety file %s: %s (fail-closed)", self._safety_file, e)
                return
            except Exception as e:
                logger.warning("Could not read safety file %s: %s (writing in-memory cooldowns only)", self._safety_file, e)

            # Merge with in-memory cooldowns
            for h, exp in self._cooldowns.items():
                if exp > now:
                    if h not in merged or exp > merged[h]:
                        merged[h] = exp

            self._cooldowns = merged

            # Write via temporary file and atomic replace
            temp_fd = None
            temp_path = None
            try:
                temp_fd, temp_path = tempfile.mkstemp(
                    dir=str(path.parent), prefix="safety_", suffix=".tmp"
                )
                with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                    temp_fd = None  # os.fdopen took ownership
                    json.dump(merged, f, allow_nan=False)    # Infinity and NaN are not JSON: never written
                    f.flush()
                    os.fsync(f.fileno())

                os.chmod(temp_path, 0o600)
                os.replace(temp_path, str(path))
            except (OSError, ValueError) as e:
                logger.warning("Could not write safety file %s: %s (continuing in-memory only)", self._safety_file, e)
                if temp_fd is not None:
                    try:
                        os.close(temp_fd)
                    except OSError:
                        pass
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass

    def _prune_expired(self) -> None:
        """Remove expired cooldown entries."""
        now = time.time()
        self._cooldowns = {
            host: expires
            for host, expires in self._cooldowns.items()
            if expires > now
        }
