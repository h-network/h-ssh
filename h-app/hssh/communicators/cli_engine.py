import codecs
import re
import time
from typing import Protocol

from hssh.dialects.base import Dialect
from hssh.dialects.generic import _CONTROL
from hssh.model import Fault, FaultKind, Result, Timeouts

_SETTLE = 0.15
_REFUSAL_SETTLE = 0.3
_MATCH_LIMIT = 1024


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
                 echoes: bool = False) -> None:
        self.channel = channel
        self.dialect = dialect
        self.timeouts = timeouts
        self.echoes = echoes
        self.prompt_pattern = dialect.prompt_pattern
        self._login_prompt_pattern = re.compile(
            dialect.prompt_pattern.pattern.removeprefix("^").removeprefix(r"\A"),
            dialect.prompt_pattern.flags,
        )
        self.ready = False
        self._closed = False
        self._synchronized = False
        self._configured = False
        self._dirty = False
        self._commit_sent = False
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._terminal = _Terminal()

    def _prompt(self, line: str, learning: bool = False, *, login: bool = False) -> bool:
        if login:
            return bool(line.strip()) and self._login_prompt_pattern.search(line.strip()) is not None
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

    def _read(self, deadline: float, command: str = "", *, learning: bool = False,
              login: bool = False) -> tuple[str, str]:
        lines: list[str] = []
        waiting_echo = self.echoes and bool(command)
        judged = refused = False

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

        while True:
            tail = self._terminal.tail()
            prompt = not waiting_echo and self._prompt(tail, learning, login=login)
            pager = (not waiting_echo and self.dialect.pager_pattern is not None
                     and bool(tail.strip()) and self.dialect.pager_pattern.fullmatch(tail) is not None)
            if prompt and not login and not self._output(lines.copy()).strip():
                self._terminal.clear_line()
                return self._output(lines), tail
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if prompt:
                    self._terminal.clear_line()
                    return self._output(lines), tail
                raise TimeoutError("no complete CLI prompt before the operation deadline")
            quiet = _REFUSAL_SETTLE if prompt and refused and not login else _SETTLE
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
                _, prompt = self._read(halfway, login=True)
            except TimeoutError:
                self.channel.send(b"\n", deadline)
                _, prompt = self._read(deadline, login=True)
            if self._prompt(prompt, learning=True):
                self._learn_prompt(prompt)
            self.ready = True
        except BaseException:
            self.ready = False
            raise

    def _command(self, command: str, timeout: int | None = None, *, edit: bool = False) -> str:
        if not command.strip() or _CONTROL.search(command):
            raise Fault(FaultKind.LOCAL, "a CLI command must be nonempty text without controls or Tab", False)
        if not self.ready:
            raise Fault(FaultKind.SESSION_LOST, "CLI session is not synchronized", True)
        try:
            output = self._exchange(command.strip(), time.monotonic() + (self.timeouts.command if timeout is None else timeout))
            if edit:
                for line in output.splitlines():
                    if refusal := self._refusal([line]):
                        raise Fault(FaultKind.REFUSED, refusal, True)
            return output
        except TimeoutError as error:
            self.ready = False
            raise Fault(FaultKind.TIMEOUT, str(error), True) from error
        except (ConnectionError, OSError) as error:
            self.ready = False
            raise Fault(FaultKind.SESSION_LOST, str(error), True) from error
        except Fault:
            raise
        except BaseException:
            self.ready = False
            raise

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
        if not self.ready or self._commit_sent:
            self.discard()
            raise Fault(FaultKind.SESSION_LOST, "CLI session is not synchronized", True)
        try:
            if self._configured:
                if self._dirty:
                    for command in self.dialect.discard_commands:
                        self._command(command, edit=True)
                    self._dirty = False
                self._command(self.dialect.config_exit_command, edit=True)
                self._configured = False
        except BaseException:
            self.discard()
            raise

    def close(self) -> None:
        try:
            if self.ready and not self._commit_sent:
                self.release()
        finally:
            self.discard()

    def discard(self) -> None:
        self.ready = False
        if not self._closed:
            self._closed = True
            try:
                self.channel.close()
            except Exception:
                pass

    def _enter(self) -> None:
        if not self.dialect.has_candidate or not self.dialect.config_enter_command or not self.dialect.config_exit_command:
            raise Fault(FaultKind.UNSUPPORTED, "this dialect has no candidate configuration", False)
        if not self._configured:
            self._command(self.dialect.config_enter_command, edit=True)
            self._configured = True

    def load(self, lines: list[str]) -> Result:
        if refusal := self.dialect.check_edit(lines):
            raise Fault(FaultKind.LOCAL, refusal, False)
        self._enter()
        replies = []
        for number, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith(self.dialect.comment_prefixes):
                continue
            self._dirty = True
            try:
                output = self._command(line, edit=True)
            except Fault as error:
                raise Fault(error.kind, f"line {number} {line!r}: {error.detail}", error.reached_device) from error
            if output.strip():
                replies.append(f"{line!r}: {output}")
        return Result("\n".join(replies))

    def diff(self) -> Result:
        if self.dialect.diff_command is None:
            raise Fault(FaultKind.UNSUPPORTED, "this dialect has no candidate diff", False)
        self._enter()
        output = self._command(self.dialect.diff_command)
        changed = bool(output.strip())
        return Result(output if changed else "", data=changed)

    def commit(self, confirmed_minutes: int | None, comment: str | None) -> Result:
        command = self.dialect.build_commit(confirmed_minutes, comment)
        self._enter()
        if not self.ready:
            raise Fault(FaultKind.SESSION_LOST, "CLI session is not synchronized", True)
        # A partial write can commit; only an explicit refusal permits rollback.
        self._commit_sent = True
        try:
            output = self._command(command, self.timeouts.commit, edit=True)
        except Fault as error:
            if error.kind is FaultKind.REFUSED:
                self._commit_sent = False
                raise Fault(FaultKind.COMMIT_FAILED, error.detail, True) from error
            self.ready = False
            raise Fault(FaultKind.OUTCOME_UNKNOWN, error.detail, True) from error
        except BaseException as error:
            self.ready = False
            if isinstance(error, Exception):
                raise Fault(FaultKind.OUTCOME_UNKNOWN, str(error), True) from error
            raise
        self._dirty = self._commit_sent = False
        return Result(output)

    def confirm(self) -> Result:
        self._enter()
        if not self.commit_history().data.pending:
            raise Fault(FaultKind.REFUSED, "nothing to confirm", True)
        return self.commit(None, None)

    def commit_history(self) -> Result:
        command = self.dialect.config_history_command if self._configured else self.dialect.history_command
        if command is None:
            raise Fault(FaultKind.UNSUPPORTED, "this dialect has no commit history command in this mode", False)
        output = self._command(command)
        return Result(output, data=self.dialect.parse_commit_history(output))
