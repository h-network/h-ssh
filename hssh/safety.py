"""Per-device safety gate: rate limiting and cooldown for h-ssh runner.

Two-tier design:
  Tier 1 (in-memory): active set, attempt counter, rate limit per device per invocation.
  Tier 2 (file-based): cooldown timestamps in JSON with fcntl.flock for cross-process safety.
"""

import fcntl
import json
import logging
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class SafetyGate:
    """Per-device rate limiting and cross-invocation cooldown.

    Args:
        safety_file: Path to JSON cooldown file. None = in-memory only.
        rate_limit: Max attempts per device per invocation (default 10).
        cooldown_seconds: Seconds to block a device after failure (default 120).
    """

    def __init__(
        self,
        safety_file: Optional[str] = None,
        rate_limit: int = 10,
        cooldown_seconds: int = 120,
    ):
        self._safety_file = safety_file
        self._rate_limit = rate_limit
        self._cooldown_seconds = cooldown_seconds

        # Tier 1: in-memory state (per invocation)
        self._active: set[str] = set()
        self._attempt_count: dict[str, int] = {}

        # Tier 2: load existing cooldowns from file
        self._cooldowns: dict[str, float] = {}
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
        # Tier 2: file-based cooldown check
        now = time.time()
        expires = self._cooldowns.get(host)
        if expires is not None:
            if now < expires:
                remaining = int(expires - now)
                return False, f"cooldown active ({remaining}s remaining)"
            else:
                # Expired — prune it
                del self._cooldowns[host]

        # Tier 1: already connected in this invocation?
        if host in self._active:
            return False, "active connection"

        # Tier 1: rate limit
        count = self._attempt_count.get(host, 0)
        if count >= self._rate_limit:
            return False, f"rate limited {count}/{self._rate_limit}"

        # Allow — add to active set BEFORE returning (fail-closed)
        self._active.add(host)
        self._attempt_count[host] = count + 1
        return True, "ok"

    def release_device(self, host: str) -> None:
        """Release a device from the active set after a successful operation."""
        self._active.discard(host)

    def set_cooldown(self, host: str) -> None:
        """Set a cooldown on a device after a failure. Persists to file."""
        self._active.discard(host)
        expires = time.time() + self._cooldown_seconds
        self._cooldowns[host] = expires
        if self._safety_file:
            self._save_cooldowns()

    def close(self) -> None:
        """Prune expired cooldowns and persist to file."""
        self._prune_expired()
        if self._safety_file:
            self._save_cooldowns()

    # ------------------------------------------------------------------
    # File persistence (Tier 2)
    # ------------------------------------------------------------------

    def _load_cooldowns(self) -> None:
        """Load cooldown data from file, pruning expired entries."""
        path = Path(self._safety_file)
        if not path.exists():
            return
        try:
            with open(path, "r") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                try:
                    data = json.load(f)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
            now = time.time()
            self._cooldowns = {
                host: expires
                for host, expires in data.items()
                if expires > now
            }
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Could not read safety file %s: %s (continuing in-memory only)", self._safety_file, e)

    def _save_cooldowns(self) -> None:
        """Persist cooldown data to file with exclusive lock."""
        path = Path(self._safety_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    json.dump(self._cooldowns, f)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
        except OSError as e:
            logger.warning("Could not write safety file %s: %s (continuing in-memory only)", self._safety_file, e)

    def _prune_expired(self) -> None:
        """Remove expired cooldown entries."""
        now = time.time()
        self._cooldowns = {
            host: expires
            for host, expires in self._cooldowns.items()
            if expires > now
        }
