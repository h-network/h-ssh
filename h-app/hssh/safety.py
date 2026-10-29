"""Safety-gate skeleton; admission and cooldown persistence are not implemented."""

from __future__ import annotations

from collections.abc import Sequence

from hssh.model import SafetySettings, Target


class SafetyGate:
    def __init__(self, settings: SafetySettings) -> None:
        self.settings = settings
        raise NotImplementedError

    def check_device(self, target: Target, *, login: bool = True) -> tuple[bool, str]:
        """On admission, reserve the device until release and count a new login."""
        raise NotImplementedError

    def holds(self, targets: Sequence[Target]) -> dict[str, str]:
        """Return target names and cooldown reasons without reserving devices."""
        raise NotImplementedError

    def release_device(self, target: Target) -> None:
        raise NotImplementedError

    def set_cooldown(self, target: Target) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
