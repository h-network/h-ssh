import codecs
import re
import time
from typing import Protocol

from hssh.dialects.base import Dialect
from hssh.model import Fault, FaultKind, Result, Timeouts

_SETTLE = 0.15
_REFUSAL_SETTLE = 0.3
_MATCH_LIMIT = 1024
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")


class Channel(Protocol):
    """Reads use a relative timeout; writes share one absolute monotonic deadline."""

    def recv(self, n: int, timeout: float) -> bytes: ...

    def send(self, data: bytes, deadline: float) -> None: ...

    def close(self) -> None: ...


class _Terminal:
    def __init__(self) -> None:
        self.line: list[str] = []
        self.column = 0
        self.escape = ""
        self.parameters = ""

    def clear_line(self) -> None:
        self.line.clear()
        self.column = 0

    def tail(self) -> str:
        return "".join(self.line) if len(self.line) <= _MATCH_LIMIT else ""

    def feed(self, text: str) -> list[str]:
        lines = []
        for char in text:
            if self.escape:
                if self.escape == "osc":
                    if char == "\x07":
                        self.escape = ""
                    elif char == "\x1b":
                        self.escape = "osc-end"
                elif self.escape == "osc-end":
                    self.escape = "" if char == "\\" else "osc"
                elif self.escape == "csi":
                    if "@" <= char <= "~":
                        self._csi(char)
                        self.escape = ""
                    elif len(self.parameters) < 32:
                        self.parameters += char
                elif self.escape == "charset":
                    self.escape = ""
                elif char == "[":
                    self.escape, self.parameters = "csi", ""
                elif char == "]":
                    self.escape = "osc"
                elif char in "()":
                    self.escape = "charset"
                else:
                    self.escape = ""
                continue
            if char == "\x1b":
                self.escape = "esc"
            elif char == "\n":
                lines.append("".join(self.line))
                self.clear_line()
            elif char == "\r":
                self.column = 0
            elif char == "\b":
                self.column = max(0, self.column - 1)
            elif char not in "\x00\x07\x0e\x0f":
                if self.column < len(self.line):
                    self.line[self.column] = char
                else:
                    self.line.append(char)
                self.column += 1
        return lines

    def _csi(self, final: str) -> None:
        amount = int(self.parameters) if self.parameters.isdecimal() else 0
        if final == "K":
            if amount == 2:
                self.clear_line()
            elif amount == 0:
                del self.line[self.column:]
        elif final == "D":
            self.column = max(0, self.column - (amount or 1))
        elif final == "C":
            self.column = min(len(self.line), self.column + (amount or 1))
        elif final == "G":
            self.column = min(len(self.line), max(0, amount - 1))


class CliEngine:
    """One interactive session; transport wrappers diagnose setup failures."""

    def __init__(self, channel: Channel, dialect: Dialect, timeouts: Timeouts, *,
                 echoes: bool = False, initial: str = "") -> None:
        self.channel = channel
        self.dialect = dialect
        self.timeouts = timeouts
        self.echoes = echoes
        self.initial = initial
        self.prompt_pattern = dialect.prompt_pattern
        self.ready = False
        self._closed = False
        self._synchronized = False
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._terminal = _Terminal()

    def _prompt(self, line: str, learning: bool = False) -> bool:
        pattern = self.dialect.prompt_pattern if learning else self.prompt_pattern
        return bool(line.strip()) and pattern.fullmatch(line.strip()) is not None

    def _learn_prompt(self, line: str) -> None:
        match = self.dialect.prompt_name_pattern.match(line.strip())
        if match is None:
            raise ConnectionError("cannot identify the CLI prompt")
        self.prompt_pattern = re.compile(
            r"\A" + re.escape(match.group(1)) + "(?:" + self.dialect.prompt_tail_pattern.pattern + r")\Z"
        )

    def _echo(self, line: str, command: str) -> bool:
        shown = line.strip()
        if shown.endswith(command):
            before = shown[:-len(command)].strip()
            if not before or self._prompt(before, learning=True):
                return True
        _, dots, tail = shown.rpartition("...")
        if dots and len(tail) >= 8 and command.endswith(tail):
            return True
        if self._synchronized:
            actual, typed = shown.split(), command.split()
            return bool(actual) and len(actual) <= len(typed) and all(a.startswith(t) for a, t in zip(actual, typed))
        return False

    def _refusal(self, lines: list[str]) -> str | None:
        for line in lines:
            text = line.strip()
            if not text or set(text) == {"^"}:
                continue
            if any(p.search(text) for p in self.dialect.warning_patterns):
                continue
            if any(p.search(text) for p in self.dialect.refusal_patterns):
                return text
            return None
        return None

    def _output(self, lines: list[str]) -> str:
        context = self.dialect.context_pattern
        while context and lines and context.fullmatch(lines[-1].strip()):
            lines.pop()
        return "\n".join(lines)

    def _read(self, deadline: float, command: str = "", *, learning: bool = False) -> tuple[str, str]:
        lines: list[str] = []
        waiting_echo = self.echoes and bool(command)
        judged = refused = False
        initial, self.initial = self.initial, ""

        def consume(text: str) -> None:
            nonlocal waiting_echo, judged, refused
            for line in self._terminal.feed(text):
                if waiting_echo:
                    if self._echo(line, command):
                        waiting_echo = False
                        lines.clear()
                else:
                    lines.append(line)
                    text = line.strip()
                    if not judged and text and set(text) != {"^"}:
                        if not any(p.search(text) for p in self.dialect.warning_patterns):
                            judged = True
                            refused = any(p.search(text) for p in self.dialect.refusal_patterns)

        consume(initial)
        while True:
            tail = self._terminal.tail()
            prompt = not waiting_echo and self._prompt(tail, learning)
            pager = (not waiting_echo and self.dialect.pager_pattern is not None
                     and bool(tail.strip()) and self.dialect.pager_pattern.fullmatch(tail) is not None)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if prompt:
                    self._terminal.clear_line()
                    return self._output(lines), tail
                raise TimeoutError("no complete CLI prompt before the operation deadline")
            quiet = _REFUSAL_SETTLE if prompt and refused else _SETTLE
            wait = min(remaining, quiet) if prompt or pager else remaining
            try:
                data = self.channel.recv(65536, wait)
                if not data:
                    raise ConnectionError("CLI channel closed by peer")
            except TimeoutError:
                if prompt:
                    self._terminal.clear_line()
                    return self._output(lines), tail
                if pager:
                    self.channel.send(self.dialect.pager_reply, deadline)
                    self._terminal.clear_line()
                    continue
                raise
            consume(self._decoder.decode(data))

    def _exchange(self, command: str, deadline: float) -> str:
        self._terminal.clear_line()
        self.channel.send(self.dialect.encode_line(command), deadline)
        learning = not self._synchronized
        output, prompt = self._read(deadline, command, learning=learning)
        if learning:
            self._learn_prompt(prompt)
            self._synchronized = True
        refusal = self._refusal(output.split("\n"))
        if refusal:
            raise Fault(FaultKind.REFUSED, refusal, True)
        return output

    def login(self, deadline: float) -> None:
        try:
            halfway = time.monotonic() + max(0.0, deadline - time.monotonic()) / 2
            try:
                _, prompt = self._read(halfway, learning=True)
            except TimeoutError:
                self.channel.send(b"\n", deadline)
                _, prompt = self._read(deadline, learning=True)
            self._learn_prompt(prompt)
            if self.dialect.paging_off_command:
                self._exchange(self.dialect.paging_off_command, deadline)
            self.ready = True
        except BaseException:
            self.ready = False
            raise

    def disable_paging(self) -> None:
        if self.dialect.paging_off_command:
            self.show(self.dialect.paging_off_command)

    def show(self, command: str) -> Result:
        if not command.strip() or _CONTROL.search(command):
            raise Fault(FaultKind.LOCAL, "a CLI command must be nonempty text without controls or Tab", False)
        if not self.ready:
            raise Fault(FaultKind.SESSION_LOST, "CLI session is not synchronized", True)
        try:
            return Result(self._exchange(command.strip(), time.monotonic() + self.timeouts.command))
        except TimeoutError as error:
            self.ready = False
            raise Fault(FaultKind.TIMEOUT, str(error), True) from error
        except (ConnectionError, OSError) as error:
            self.ready = False
            raise Fault(FaultKind.SESSION_LOST, str(error), True) from error

    def probe(self, deadline: float) -> bool:
        if not self.ready:
            return False
        try:
            self._exchange("", deadline)
            return True
        except (Fault, OSError):
            self.ready = False
            return False

    def release(self) -> None:
        if not self.ready:
            raise Fault(FaultKind.SESSION_LOST, "CLI session is not synchronized", True)

    def close(self) -> None:
        self.ready = False
        if not self._closed:
            self._closed = True
            self.channel.close()

    def discard(self) -> None:
        try:
            self.close()
        except Exception:
            pass

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
