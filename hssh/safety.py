"""Per-device safety gate: rate limiting and cooldown for h-ssh runner.

Two-tier design:
  Tier 1 (in-memory): active set, sliding window attempt tracker, thread safety.
  Tier 2 (file-based): atomic cooldown persistence with lockfile, merge-under-lock,
                       tempfile + os.replace, 0600 permissions, and fail-closed corrupt protection.
"""

from contextlib import contextmanager
import fcntl
import json
import logging
import os
from pathlib import Path
import tempfile
import threading
import time
from typing import Generator, Optional

logger = logging.getLogger(__name__)


class SafetyGate:
    """Per-device rate limiting and cross-invocation cooldown.

    Args:
        safety_file: Path to JSON cooldown file. None = in-memory only.
        rate_limit: Max attempts per device within rate_window (default 10).
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
        self._safety_file = safety_file
        self._rate_limit = rate_limit
        self._cooldown_seconds = cooldown_seconds
        self._rate_window = rate_window

        # Thread safety lock
        self._lock = threading.RLock()

        # Tier 1: in-memory state
        self._active: set[str] = set()
        self._attempt_count: dict[str, int] = {}
        self._attempt_timestamps: dict[str, list[float]] = {}

        # Tier 2: file-based state
        self._cooldowns: dict[str, float] = {}
        self._corrupt = False

        if self._safety_file:
            self._load_cooldowns()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_device(self, host: str) -> tuple[bool, str]:
        """Check whether a device is safe to contact.

        Returns (allowed, reason). Host is added to _active BEFORE returning
        True — crash before release_device() keeps it blocked (fail-closed).
        """
        with self._lock:
            # Re-read cooldowns from disk to catch external changes and check corruption
            if self._safety_file:
                self._load_cooldowns()
                if self._corrupt:
                    return False, "safety file corrupted (fail-closed)"

            # Tier 2: cooldown check
            now = time.time()
            expires = self._cooldowns.get(host)
            if expires is not None:
                if now < expires:
                    remaining = int(expires - now)
                    return False, f"cooldown active ({remaining}s remaining)"
                else:
                    del self._cooldowns[host]

            # Tier 1: active connection in this invocation
            if host in self._active:
                return False, "active connection"

            # Tier 1: sliding window rate limit
            timestamps = [
                ts for ts in self._attempt_timestamps.get(host, [])
                if (now - ts) < self._rate_window
            ]
            self._attempt_timestamps[host] = timestamps

            count = len(timestamps)
            legacy_count = self._attempt_count.get(host, 0)
            effective_count = max(count, legacy_count)

            if effective_count >= self._rate_limit:
                return False, f"rate limited {effective_count}/{self._rate_limit}"

            # Allow and mark active (fail-closed)
            self._active.add(host)
            self._attempt_count[host] = legacy_count + 1
            self._attempt_timestamps[host].append(now)
            return True, "ok"

    def release_device(self, host: str) -> None:
        """Release a device from the active set after a successful operation."""
        with self._lock:
            self._active.discard(host)

    def set_cooldown(self, host: str) -> None:
        """Set a cooldown on a device after a failure. Persists to file."""
        with self._lock:
            self._active.discard(host)
            expires = time.time() + self._cooldown_seconds
            self._cooldowns[host] = expires
            if self._safety_file:
                self._save_cooldowns()

    def close(self) -> None:
        """Prune expired cooldowns and persist to file."""
        with self._lock:
            self._prune_expired()
            if self._safety_file:
                self._save_cooldowns()

    # ------------------------------------------------------------------
    # File persistence (Tier 2)
    # ------------------------------------------------------------------

    @contextmanager
    def _file_lock(self) -> Generator[None, None, None]:
        """Acquire an exclusive advisory flock on the safety lockfile."""
        if not self._safety_file:
            yield
            return

        lock_path = Path(f"{self._safety_file}.lock")
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        except OSError as e:
            logger.warning("Could not lock safety file %s: %s (continuing without file lock)", lock_path, e)
            yield

    def _load_cooldowns(self) -> None:
        """Load cooldown data from file, merging with in-memory entries."""
        path = Path(self._safety_file)
        if not path.exists():
            self._corrupt = False
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                try:
                    data = json.load(f)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

            self._corrupt = False
            now = time.time()
            if isinstance(data, dict):
                disk_cooldowns = {
                    host: float(expires)
                    for host, expires in data.items()
                    if float(expires) > now
                }
                # Merge: disk entries and memory entries
                for host, expires in disk_cooldowns.items():
                    if host not in self._cooldowns or expires > self._cooldowns[host]:
                        self._cooldowns[host] = expires
            else:
                self._corrupt = True
                logger.error("Safety file %s has invalid non-dictionary structure", self._safety_file)

        except (json.JSONDecodeError, ValueError) as e:
            self._corrupt = True
            logger.error("Could not parse safety file %s: %s (fail-closed)", self._safety_file, e)
        except OSError as e:
            logger.warning("Could not read safety file %s: %s (continuing in-memory only)", self._safety_file, e)

    def _save_cooldowns(self) -> None:
        """Persist cooldown data to file with exclusive lock, merge, and atomic replace."""
        path = Path(self._safety_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning("Could not create directory for safety file %s: %s", self._safety_file, e)
            return

        with self._file_lock():
            now = time.time()
            # Read current on-disk entries to merge
            merged: dict[str, float] = {}
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        disk_data = json.load(f)
                        if isinstance(disk_data, dict):
                            for h, exp in disk_data.items():
                                if float(exp) > now:
                                    merged[h] = float(exp)
                except Exception:
                    pass

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
                    json.dump(merged, f)
                    f.flush()
                    os.fsync(f.fileno())

                os.chmod(temp_path, 0o600)
                os.replace(temp_path, str(path))
            except OSError as e:
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
