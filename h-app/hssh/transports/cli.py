"""Typing at a device CLI: login, the prompt, one command and its reply,
paging, and the edit sequences a dialect's CliSyntax describes.

The engine knows nothing about sockets or SSH. It reads and writes a
`Channel`: anything with recv(n, timeout) -> bytes (TimeoutError when nothing
arrived in time, ConnectionError when the peer is gone), send(bytes) and
close(). The telnet transport is one channel; a paramiko shell is another;
the tests use one made of a script.

Every reader here either returns a complete reply or raises. What has
arrived when a deadline passes is never handed back as the device's answer.
"""

import re
import time
from typing import Callable, Optional

from ..core import check_confirm_minutes, control_character, control_line, refusal_line
from ..dialects.base import CliSyntax, Dialect
from ..drivers import results as R
from ..errors import AmbiguousCommitError, NotAppliedError, NothingToConfirmError

# ANSI escape code stripper
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07|\x1b[()][0-9A-B]|\x0f|\x00')

# --More-- patterns for pagination
MORE_PATTERNS = [
    re.compile(r'---?\(more( \d+%)?\)---?', re.IGNORECASE),
    re.compile(r'--More--'),
    re.compile(r'\[yes,no\]'),
]

# Login prompts. "Last login:" is what a successful login prints, so a read
# that happens to end there must not pass for the device asking again.
LOGIN_RE = re.compile(r'(?<!Last )(Username|Login|login|User Name)\s*:\s*$', re.IGNORECASE)
PASSWORD_RE = re.compile(r'(Password|password)\s*:\s*$', re.IGNORECASE)

# What a device says alongside the login prompt it shows again when it did not
# take the credentials; quoted in the error, the re-prompt itself is the tell.
_LOGIN_REJECTED = ("login incorrect", "bad password", "login invalid",
                   "authentication failed", "access denied", "permission denied")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from output."""
    return _ANSI_RE.sub('', text)


def is_echo(line: str, cmd: str) -> bool:
    """The device's echo of what was typed ends with the command itself; a
    reply line that merely mentions the command is not it."""
    return line.strip().endswith(cmd.strip())


def complaint(output: str, dialect: Dialect) -> str:
    """The line in which the device refused what was typed: the dialect's
    own refusal where the reply has one, else the first line that is neither
    blank nor a caret marker. A CLI that checks a line as it is typed (Junos
    on a pty) refuses the bad word when the space after it arrives, redraws
    the prompt and the line, then refuses the Enter too: the reply is two
    complaints, a prompt and a redraw with backspaces, and the complaint is
    one line of it."""
    found = refusal_line(output, dialect=dialect)
    if found:
        return found
    for ln in output.splitlines():
        if ln.strip() and set(ln.strip()) != {"^"}:
            return ln.strip()
    return output.strip()


def refuse_control_characters(payload: str) -> None:
    """A CLI acts on a control character as it is typed: ^C drops the line
    typed so far, ^U kills it, DEL rubs out the character before it, a Tab
    completes the word. What is left of the line then runs as typed: `set
    system host-name x`, ^C, `commit comment y` commits for good, dry run or
    not. Every line the engine types is plain text, line breaks only between
    lines; a C0 or C1 control character, DEL or a Tab is refused before the
    device is contacted."""
    found = control_line(payload, tabs=False)
    if found:
        _, line, what = found
        raise ValueError(f"{line!r} has {what}, which a CLI takes as a key, not as text; "
                         "nothing was sent to the device")


def refuse_command(cmd: str) -> None:
    """A command Cli.run would not type, a control character or a Tab in it
    (a CLI completes the word on a Tab), refused before the device is
    contacted: the same refusal comes on every attempt."""
    what = control_character(cmd, tabs=False)
    if what:
        raise ValueError(f"{cmd!r} has {what}, which a CLI takes as a key, not as text; "
                         "nothing was sent to the device")


def refuse_comment(comment: Optional[str]) -> None:
    """confirm()'s comment goes on the commit line in double quotes: a line
    break in it runs what follows as commands of their own (`rollback 1`, a
    second commit), another control character or a Tab is a key to the CLI,
    and a double quote ends the comment, the rest read as more of the
    commit. Refused before the device is contacted."""
    if not comment:
        return
    what = control_character(comment, tabs=False)
    if what:
        raise ValueError(f"the comment {comment!r} has {what}, which a CLI takes as a key, not as text; "
                         "nothing was sent to the device")
    if '"' in comment:
        raise ValueError(f"the comment {comment!r} has a double quote, which would end it on the commit line; "
                         "nothing was sent to the device")


def credential_fault(user: Optional[str], passwd: Optional[str]) -> Optional[str]:
    """What keeps a username or password from being typed at a login prompt,
    or None. A line break ends the answer there, and what follows it runs as
    commands once the login succeeds, a `commit` too; ^C, ^U, DEL and the
    other control characters are keys to the prompt. A Tab is text in a
    password, which the prompt does not complete; a username has none.
    Neither is quoted: what follows a line break in a username may well be
    the password."""
    what = control_character(user or "", tabs=False)
    if what:
        return f"the username has {what}"
    what = control_character(passwd or "")
    if what:
        return f"the password has {what}"
    return None


def refuse_credentials(user: Optional[str], passwd: Optional[str]) -> None:
    """A username or password a login dialogue would type with a control
    character in it (credential_fault), refused before the device is
    contacted."""
    fault = credential_fault(user, passwd)
    if fault:
        raise ValueError(f"{fault}, which a login prompt takes as a key, not as text; "
                         "nothing was sent to the device")


# The shortest word a Junos CLI completes to `commit` in configuration mode:
# it takes a unique prefix of a command, and `co` is `copy` as well.
_COMMIT_SHORTEST = 3


def refuse_commit_lines(payload: str) -> None:
    """`commit` typed inside configure mode would commit (and confirm any
    pending timer) halfway through a payload. A confirm is `-eC "commit"`
    on its own, which confirm() handles; here it is refused before the
    device is contacted. The word is the line's first, whatever whitespace
    follows it, with a closing ';' taken off: `commit;` is a commit to the
    set-syntax guard too (dialects.junos.check_edit), and for a library
    caller this is the only rail. The CLI completes `com`, `comm` and
    `commi` to `commit` as it does `sh` to `show`, so they are refused too."""
    for line in payload.strip().splitlines():
        words = line.split()
        word = words[0].rstrip(";") if words else ""
        if len(word) >= _COMMIT_SHORTEST and "commit".startswith(word):
            said = "'commit'" if word == "commit" else f"{word!r} is 'commit' to a Junos CLI, and 'commit'"
            raise ValueError(f"{said} is not configuration; a pending commit-confirmed is confirmed "
                             "with -eC \"commit\" alone. Nothing was sent to the device")


def pending_in(history: str, dialect: Dialect) -> bool:
    """The latest entry of `show system commit` while a commit confirmed waits:
    "0   2026-10-22 08:00:00 UTC by lab via cli commit confirmed, rollback in 5mins"."""
    return any(re.match(r"^\s*0\s+", line) and dialect.commit_pending.search(line)
               for line in history.splitlines())


class Cli:
    """One CLI session on a channel, in a dialect.

    `login()` first: it reads the banner, answers a login/password dialogue
    if the device holds one, and learns this device's own prompt. Then
    `run()` for a command, `edit_lines()`/`edit_candidate()` for an edit,
    `confirm()` for a pending commit-confirmed. `close()` ends it."""

    def __init__(self, channel, dialect: Dialect, session_timeout: int, initial: str = ""):
        self.channel = channel
        self.dialect = dialect
        self.cli: CliSyntax = dialect.cli
        self.session_timeout = session_timeout
        self.prompt_re = self.cli.prompt
        self._initial = initial      # what the channel already read while opening (telnet negotiation)

    # --- the wire -------------------------------------------------------------

    def _send(self, data: str) -> None:
        # Strict: a character that cannot be encoded is never replaced by a
        # '?', which a Junos CLI takes as a request for help (#139).
        self.channel.send(data.encode("utf-8"))

    def _read_until(self, done: Callable[[str], bool], timeout: int, buffer: str = "") -> str:
        """Read until done(text) matches the cleaned buffer.

        What has arrived when the deadline passes is not an answer: that
        raises TimeoutError, and the peer closing or the channel failing
        raises ConnectionError. A caller never gets a partial read back as
        the reply."""
        buf = buffer
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            clean = strip_ansi(buf)
            if done(clean):
                return clean
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                chunk = self.channel.recv(4096, min(remaining, 2.0)).decode("utf-8", errors="replace")
            except TimeoutError:
                continue
            if not chunk:
                raise ConnectionError("connection closed by the device")
            buf += chunk
            clean = strip_ansi(buf)
            # Handle --More-- pagination: the marker goes, what followed it in
            # the same chunk stays.
            for more_re in MORE_PATTERNS:
                m = more_re.search(clean)
                if m:
                    self._send(" ")
                    buf = clean[:m.start()] + clean[m.end():]
                    clean = strip_ansi(buf)
                    break
            if done(clean):
                return clean
        seen = [l.strip() for l in strip_ansi(buf).splitlines() if l.strip()]
        tail = f"; last line: {seen[-1][:80]!r}" if seen else ""
        raise TimeoutError(f"no prompt within {timeout}s{tail}")

    def _settle(self, buffer: str, seconds: float) -> str:
        """What else arrives within `seconds`, for a reply whose prompt may
        not have been the last: a CLI that refused a line as it was typed
        redraws the prompt and the line, then refuses the Enter after it."""
        buf = buffer
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return buf
            try:
                chunk = self.channel.recv(4096, remaining).decode("utf-8", errors="replace")
            except (TimeoutError, OSError):
                return buf
            if not chunk:
                return buf
            buf += chunk

    def read_until_prompt(self, timeout: int, buffer: str = "") -> str:
        return self._read_until(self.prompt_re.search, timeout, buffer)

    def _read_until_prompt_or_login(self, timeout: int, buffer: str = "") -> str:
        return self._read_until(
            lambda clean: LOGIN_RE.search(clean) or PASSWORD_RE.search(clean) or self.prompt_re.search(clean),
            timeout, buffer)

    # --- login ----------------------------------------------------------------

    @staticmethod
    def _check_login(reply: str) -> None:
        """The reply to the credentials must be a CLI prompt. Another login or
        password prompt means the device did not take them; the show command
        sent next would be read as a username."""
        if not (LOGIN_RE.search(reply) or PASSWORD_RE.search(reply)):
            return
        lines = [l.strip() for l in reply.splitlines() if l.strip()]
        said = next((l for l in lines if any(w in l.lower() for w in _LOGIN_REJECTED)), None)
        detail = f": {said}" if said else " (the device asked for credentials again)"
        raise NotAppliedError(f"login failed{detail}")

    @staticmethod
    def _refuse_typing(user: Optional[str], passwd: Optional[str]) -> None:
        """The login dialogue types a credential as it is: one the prompt
        would take as keys is not typed (credential_fault)."""
        fault = credential_fault(user, passwd)
        if fault:
            raise ValueError(f"{fault}, which a login prompt takes as a key, not as text; it was not sent")

    def login(self, user: Optional[str], passwd: Optional[str]) -> None:
        """Get to a prompt. Raises NotAppliedError when the device rejects the
        credentials or shows no prompt within session_timeout, even after an
        Enter: no command was sent, and the runner treats a failed login as
        permanent. A username or password with a control character in it is
        a ValueError before either is typed. The channel is closed on any
        failure."""
        timeout = self.session_timeout
        try:
            try:
                initial = self._read_until_prompt_or_login(timeout, buffer=self._initial)
            except TimeoutError:
                # A console-server line left at a prompt, or at "Press RETURN to
                # get started.", prints nothing until Enter. One Enter, only once
                # the wait is up: typed ahead of a slow login prompt it would be
                # taken as an empty username.
                self._send("\n")
                initial = self._read_until_prompt_or_login(timeout)

            last = initial
            if LOGIN_RE.search(initial):
                self._refuse_typing(user, passwd)
                self._send((user or "") + "\n")
                last = self._read_until_prompt_or_login(timeout)
                if PASSWORD_RE.search(last):
                    self._send((passwd or "") + "\n")
                    last = self._read_until_prompt_or_login(timeout)
                self._check_login(last)
            elif PASSWORD_RE.search(initial):
                self._refuse_typing(None, passwd)
                self._send((passwd or "") + "\n")
                last = self._read_until_prompt_or_login(timeout)
                self._check_login(last)
            self.prompt_re = self._learn_prompt(last)
        except Exception as e:
            self.close()
            if isinstance(e, TimeoutError):
                # Nothing was sent that the device acted on: permanent, no retry.
                # The message quotes the last line seen; a console that echoes
                # what was typed would put the password there.
                text = str(e).replace(passwd, "***") if passwd else str(e)
                raise NotAppliedError(f"login failed: {text}") from e
            # A connection dropped during the login dialogue is the retried
            # kind of failure, like any reset after connecting.
            raise

    def _learn_prompt(self, reply: str) -> re.Pattern:
        """The device's own prompt, from the first one seen after login: from
        then on only `user@host` (or `Router`, with its config-mode suffix) ends a
        reply, not any line that happens to end in `>` or `#`."""
        seen = [l.strip() for l in reply.splitlines() if l.strip()]
        if not seen:
            return self.prompt_re
        m = self.cli.prompt_name.search(seen[-1])
        return re.compile(re.escape(m.group(1)) + self.cli.prompt_tail) if m else self.prompt_re

    # --- commands ---------------------------------------------------------------

    def run(self, cmd: str, command_timeout: int) -> str:
        """Send a command and return output (stripped of echo and trailing prompt).

        The prompt is looked for on the last line only, and never on the echo:
        a config line that itself ends in prompt-shaped text (`description
        noc@example.com>`) once satisfied the match on its echo, left the real
        reply in the socket, and shifted every later read by one reply, so a
        commit the device refused was reported as COMMIT OK.

        A command with a control character or a Tab in it is not typed: the
        CLI would take it as a key (refuse_control_characters)."""
        what = control_character(cmd, tabs=False)
        if what:
            raise ValueError(f"{cmd!r} has {what}, which a CLI takes as a key, not as text; it was not sent")
        self._send(cmd + "\n")
        prompt_re = self.prompt_re

        def done(clean: str) -> bool:
            lines = clean.splitlines()
            if not lines:
                return False
            if len(lines) == 1 and is_echo(lines[0], cmd):
                return False                      # only the echo so far
            return prompt_re.search(lines[-1]) is not None

        output = self._read_until(done, command_timeout)
        if self.dialect.refused.search(output):
            # A refusal may have been typed-time: the prompt that ended the
            # read was a redraw, and the Enter's own complaint is still coming.
            output = strip_ansi(self._settle(output, 0.3))

        lines = output.splitlines()
        if lines and is_echo(lines[0], cmd):
            lines = lines[1:]
        if lines and prompt_re.search(lines[-1]):
            lines = lines[:-1]
        if self.cli.context and lines and self.cli.context.match(lines[-1].strip()):
            lines = lines[:-1]            # the context banner is the prompt's, not the reply's
        return "\n".join(lines)

    def leave_quietly(self, *cmds: str) -> None:
        """Send what ends an edit whose verdict is already known: rollback 0
        when the candidate still holds the change, then exit. A device that no
        longer answers them is let be, as the NETCONF driver's unlock is: the
        session close that follows drops the exclusive candidate and its lock
        either way, and a commit that took the management address or the
        service with it cannot answer the exit."""
        try:
            for cmd in cmds:
                self.run(cmd, 10)
        except OSError:
            pass

    def close(self) -> None:
        try:
            self.channel.close()
        except Exception:
            pass

    # --- edits -------------------------------------------------------------------

    def edit_lines(self, payload: str) -> R.EditResult:
        """Config mode without a candidate: configure terminal -> commands -> end."""
        cli = self.cli
        refuse_control_characters(payload)
        self.run(cli.config_enter, 10)

        errors = []
        for line in payload.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("#"):
                continue
            # The reply without the echoed line, so the line's own text is not
            # mistaken for the device's complaint about it.
            output = self.run(line, 10)
            if "invalid" in output.lower() or "error" in output.lower() or "%" in output:
                errors.append(f"'{line}': {complaint(output, self.dialect)}")

        self.run(cli.config_exit, 10)

        if errors:
            raise RuntimeError("; ".join(errors))
        return R.EditResult(R.APPLIED, message="(config applied)")

    def edit_candidate(self, payload: str, dry_run: bool, confirmed_minutes: int = 0,
                       expected_diff: Optional[str] = None) -> R.EditResult:
        """Config mode with a candidate: configure exclusive -> commands -> show|compare -> commit/rollback.

        Exclusive mode keeps the candidate to this session, as the NETCONF
        driver's lock does: commit and rollback 0 never touch another user's
        pending changes, and the device refuses entry while someone else holds
        the lock - reported before any set line is sent. With `expected_diff`
        (what a dry run showed) the candidate is committed only if
        `show | compare` says the same again. An empty compare is NO CHANGES,
        the candidate discarded and no commit typed, as over NETCONF: a
        commit there would arm a timer over nothing, and on Junos confirm
        another user's pending commit confirmed.
        """
        d, cli = self.dialect, self.cli
        refuse_control_characters(payload)
        refuse_commit_lines(payload)
        reply = self.run(cli.config_enter, 10)
        if d.refused.search(reply):
            raise NotAppliedError(f"Failed to lock config: {reply.strip()}")

        errors = []
        for line in payload.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            output = self.run(line, 10)
            if d.refused.search(output):
                errors.append(f"'{line}': {complaint(output, d)}")

        diff = self.run(cli.compare, 30).strip()
        changed = expected_diff is not None and diff != expected_diff.strip()

        if dry_run or errors or changed or not diff:
            self.leave_quietly(cli.discard, cli.config_exit)
            if errors:
                raise RuntimeError("; ".join(errors))
            if changed:
                raise RuntimeError("diff changed since preview; nothing committed")
            return R.EditResult(R.DRY_RUN, diff=diff) if diff else R.EditResult(R.NO_CHANGES)

        if confirmed_minutes and confirmed_minutes > 0:
            commit_cmd = f"{cli.commit} confirmed {confirmed_minutes}"
        else:
            commit_cmd = cli.commit
        try:
            commit_output = self.run(commit_cmd, 60)
        except OSError as e:
            # The commit was sent. We cannot tell whether it landed: say so, and
            # neither claim it nor roll anything back.
            raise AmbiguousCommitError(
                f"commit outcome unknown ({type(e).__name__}: {e}); "
                "check the device before retrying") from e

        if d.refused.search(commit_output):
            # A refused commit leaves the change in our candidate; discard it so
            # the exit is clean and the lock goes with it.
            self.leave_quietly(cli.discard, cli.config_exit)
            raise RuntimeError(f"Commit failed: {commit_output.strip()}")

        self.leave_quietly(cli.config_exit)

        if confirmed_minutes and confirmed_minutes > 0:
            return R.EditResult(R.CONFIRMED, diff=diff, minutes=confirmed_minutes)
        return R.EditResult(R.COMMITTED, diff=diff)

    def confirm(self, command_timeout: int, comment: Optional[str] = None) -> R.EditResult:
        """Confirm a pending commit-confirmed: configure exclusive, a bare
        commit (`commit comment "…"` with a comment), exit. Nothing waiting
        means the timer expired or it was confirmed already; a commit now
        would hide that from the operator."""
        d, cli = self.dialect, self.cli
        refuse_comment(comment)
        history = self.run("show system commit", command_timeout)
        if not pending_in(history, d):
            raise NothingToConfirmError(
                "nothing to confirm: no commit-confirmed is pending on the device "
                "(the timer expired, or it was confirmed already); nothing was sent")
        reply = self.run(cli.config_enter, 10)
        if d.refused.search(reply):
            raise NotAppliedError(f"Failed to lock config: {reply.strip()}")
        commit_cmd = f'{cli.commit} comment "{comment}"' if comment else cli.commit
        try:
            out = self.run(commit_cmd, command_timeout)
        except OSError as e:
            raise AmbiguousCommitError(
                f"commit outcome unknown ({type(e).__name__}: {e}); check the device before retrying") from e
        if d.refused.search(out):
            self.leave_quietly(cli.config_exit)
            raise RuntimeError(f"Commit failed: {out.strip()}")
        self.leave_quietly(cli.config_exit)
        return R.EditResult(R.CONFIRMED_OK)


def edit_policy(dialect: Dialect, hint: str, dry_run: bool, commit_confirmed, expected_diff) -> None:
    """What a CLI without a candidate cannot do, refused before anything is
    sent: a dry run, a rollback timer, a diff check."""
    if not dialect.cli.has_candidate and (dry_run or commit_confirmed is not None or expected_diff is not None):
        raise ValueError(f"dry_run, commit_confirmed and expected_diff are not supported by "
                         f"{hint}; nothing was sent to the device")
    check_confirm_minutes(commit_confirmed)
