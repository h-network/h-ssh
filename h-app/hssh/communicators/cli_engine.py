from typing import Protocol

from hssh.dialects.base import Dialect
from hssh.model import Result, Timeouts


class Channel(Protocol):
    """recv raises TimeoutError on timeout and ConnectionError on disconnect; send holds one absolute time.monotonic() deadline over the whole write."""

    def recv(self, n: int, timeout: float) -> bytes: ...

    def send(self, data: bytes, deadline: float) -> None: ...

    def close(self) -> None: ...


class CliEngine:
    """One interactive session; transport wrappers interpret channel errors."""

    def __init__(
        self,
        channel: Channel,
        dialect: Dialect,
        timeouts: Timeouts,
        *,
        echoes: bool = False,
        initial: str = "",
    ) -> None:
        self.channel = channel
        self.dialect = dialect
        self.timeouts = timeouts
        self.echoes = echoes
        self.initial = initial
        self.prompt_pattern = dialect.prompt_pattern

    def login(self, deadline: float) -> None:
        """Read to the first prompt and learn it, by the absolute time.monotonic() deadline; the session arrives authenticated."""
        raise NotImplementedError("CLI login and prompt detection")

    def disable_paging(self) -> None:
        raise NotImplementedError("CLI paging control")

    def show(self, command: str) -> Result:
        raise NotImplementedError("CLI command execution")

    def load(self, lines: list[str]) -> Result:
        raise NotImplementedError("Line-by-line configuration")

    def diff(self) -> Result:
        raise NotImplementedError("Dialect diff command")

    def commit(self, confirmed_minutes: int | None, comment: str | None) -> Result:
        raise NotImplementedError("Dialect commit command")

    def confirm(self) -> Result:
        raise NotImplementedError("Dialect confirm command")

    def commit_history(self) -> Result:
        raise NotImplementedError("Dialect commit-history command")

    def close(self) -> None:
        raise NotImplementedError("Discard uncommitted changes and close the channel")
