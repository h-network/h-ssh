"""Raw-socket telnet transport for console ports and legacy devices.

Uses raw sockets instead of telnetlib (deprecated in Python 3.11, removed in 3.13).
Handles login sequences, --More-- pagination, and per-vendor prompt detection.
Supports IOS, Junos, Arista (EOS) and NX-OS style prompts.
"""

import re
import socket
import time
from typing import List, Optional

from ..core import check_confirm_minutes
from .. import drivers
from ..dialects.base import CliSyntax, Dialect
from ..errors import AmbiguousCommitError, NotAppliedError, NothingToConfirmError

AVAILABLE = True  # Raw sockets, always available

# ANSI escape code stripper
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07|\x1b[()][0-9A-B]|\x0f|\x00')

def _dialect(vendor_hint: Optional[str]) -> Dialect:
    """The dialect behind a vendor_hint: telnet-junos is junos, telnet-ios is
    ios, plain telnet is none (an IOS-shaped prompt, as always). The hint is
    the shim-era way to name a dialect; #83 hands the object in."""
    try:
        return drivers.get(vendor_hint or "telnet").dialect
    except ValueError:
        return drivers.NONE


# The prompts by the flavour names telnet used, for the tests that read them.
# The IOS-style ones take the config-mode suffix too (Router(config)#,
# Switch(config-if-Et1/1)#): a reader that does not recognise it would wait
# out its timeout on every config line.
PROMPT_PATTERNS = {
    "ios": drivers.IOS.cli.prompt,
    "junos": drivers.JUNOS.cli.prompt,
    "arista": drivers.EOS.cli.prompt,
    "nxos": drivers.NXOS.cli.prompt,
}

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

def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from output."""
    return _ANSI_RE.sub('', text)


def _negotiate_telnet(sock: socket.socket) -> str:
    """Handle basic telnet IAC negotiation. Returns any non-IAC data as string."""
    try:
        sock.setblocking(False)
        time.sleep(0.3)
        try:
            data = sock.recv(4096)
        except (BlockingIOError, socket.error):
            data = b""
        sock.setblocking(True)

        i = 0
        responses = bytearray()
        non_iac = bytearray()
        while i < len(data):
            if data[i] == 0xFF and i + 2 < len(data):  # IAC
                cmd = data[i + 1]
                opt = data[i + 2]
                if cmd == 0xFB:    # WILL -> DONT
                    responses.extend([0xFF, 0xFE, opt])
                elif cmd == 0xFD:  # DO -> WONT
                    responses.extend([0xFF, 0xFC, opt])
                i += 3
            else:
                non_iac.append(data[i])
                i += 1
        if responses:
            sock.sendall(bytes(responses))
        return non_iac.decode("utf-8", errors="replace") if non_iac else ""
    except Exception:
        return ""
    finally:
        if sock:
            sock.setblocking(True)


def _send(sock: socket.socket, data: str) -> None:
    """Send data over the socket."""
    sock.sendall(data.encode("utf-8", errors="replace"))


def _read_until(sock: socket.socket, done, timeout: int, buffer: str = "") -> str:
    """Read from socket until done(text) matches the cleaned buffer.

    What has arrived when the deadline passes is not an answer: that raises
    TimeoutError, and the peer closing or the socket failing raises
    ConnectionError. A caller never gets a partial read back as the reply.
    """
    buf = buffer
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        clean = _strip_ansi(buf)
        if done(clean):
            return clean

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(remaining, 2.0))
        try:
            chunk = sock.recv(4096).decode("utf-8", errors="replace")
        except socket.timeout:
            continue
        except OSError as e:
            raise ConnectionError(f"connection lost: {e}") from e
        if not chunk:
            raise ConnectionError("connection closed by the device")
        buf += chunk
        clean = _strip_ansi(buf)

        # Handle --More-- pagination: the marker goes, what followed it in
        # the same chunk stays.
        for more_re in MORE_PATTERNS:
            m = more_re.search(clean)
            if m:
                _send(sock, " ")
                buf = clean[:m.start()] + clean[m.end():]
                clean = _strip_ansi(buf)
                break

        if done(clean):
            return clean

    seen = [l.strip() for l in _strip_ansi(buf).splitlines() if l.strip()]
    tail = f"; last line: {seen[-1][:80]!r}" if seen else ""
    raise TimeoutError(f"no prompt within {timeout}s{tail}")


def _read_until_prompt(sock: socket.socket, prompt_re: re.Pattern,
                       timeout: int, buffer: str = "") -> str:
    """Read from socket until a CLI prompt is detected."""
    return _read_until(sock, prompt_re.search, timeout, buffer)


def _read_until_prompt_or_login(sock: socket.socket, prompt_re: re.Pattern,
                                timeout: int, buffer: str = "") -> str:
    """Read until CLI prompt, login prompt, or password prompt."""
    return _read_until(
        sock,
        lambda clean: LOGIN_RE.search(clean) or PASSWORD_RE.search(clean) or prompt_re.search(clean),
        timeout, buffer)


def _check_login(reply: str) -> None:
    """The reply to the credentials must be a CLI prompt. Another login or
    password prompt means the device did not take them; the show command sent
    next would be read as a username."""
    if not (LOGIN_RE.search(reply) or PASSWORD_RE.search(reply)):
        return
    lines = [l.strip() for l in reply.splitlines() if l.strip()]
    said = next((l for l in lines if any(m in l.lower() for m in _LOGIN_REJECTED)), None)
    raise NotAppliedError(
        f"login failed: {said}" if said else "login failed: the device asked for credentials again")


def _connect_and_login(host: str, user: Optional[str], passwd: Optional[str],
                       port: int, session_timeout: int,
                       cli: CliSyntax) -> tuple:
    """Open raw socket, negotiate telnet, handle login against the dialect's
    CLI shape.

    Returns (socket, prompt_re) tuple. Raises NotAppliedError when the device
    rejects the credentials or shows no prompt within session_timeout, even
    after an Enter: no command was sent, and the runner treats a failed login
    as permanent.
    """
    prompt_re = cli.prompt
    sock = socket.create_connection((host, port), timeout=session_timeout)
    sock.settimeout(session_timeout)

    try:
        buffer = _negotiate_telnet(sock)
        try:
            initial = _read_until_prompt_or_login(sock, prompt_re, timeout=session_timeout, buffer=buffer)
        except TimeoutError:
            # A console-server line left at a prompt, or at "Press RETURN to
            # get started.", prints nothing until Enter. One Enter, only once
            # the wait is up: typed ahead of a slow login prompt it would be
            # taken as an empty username.
            _send(sock, "\n")
            initial = _read_until_prompt_or_login(sock, prompt_re, timeout=session_timeout)

        last = initial
        if LOGIN_RE.search(initial):
            _send(sock, (user or "") + "\n")
            last = _read_until_prompt_or_login(sock, prompt_re, timeout=session_timeout)
            if PASSWORD_RE.search(last):
                _send(sock, (passwd or "") + "\n")
                last = _read_until_prompt_or_login(sock, prompt_re, timeout=session_timeout)
            _check_login(last)
        elif PASSWORD_RE.search(initial):
            _send(sock, (passwd or "") + "\n")
            last = _read_until_prompt_or_login(sock, prompt_re, timeout=session_timeout)
            _check_login(last)
        prompt_re = _learn_prompt(last, prompt_re, cli)
    except Exception as e:
        sock.close()
        if isinstance(e, TimeoutError):
            # Nothing was sent that the device acted on: permanent, no retry.
            # The message quotes the last line seen; a console that echoes
            # what was typed would put the password there.
            text = str(e).replace(passwd, "***") if passwd else str(e)
            raise NotAppliedError(f"login failed: {text}") from e
        # A connection dropped during the login dialogue is the retried
        # kind of failure, like any reset after connecting.
        raise

    return sock, prompt_re


def _is_echo(line: str, cmd: str) -> bool:
    """The device's echo of what was typed ends with the command itself; a
    reply line that merely mentions the command is not it."""
    return line.strip().endswith(cmd.strip())


def _send_command(sock: socket.socket, prompt_re: re.Pattern,
                  cmd: str, command_timeout: int) -> str:
    """Send a command and return output (stripped of echo and trailing prompt).

    The prompt is looked for on the last line only, and never on the echo:
    a config line that itself ends in prompt-shaped text (`description
    noc@example.com>`) once satisfied the match on its echo, left the real
    reply in the socket, and shifted every later read by one reply, so a
    commit the device refused was reported as COMMIT OK."""
    _send(sock, cmd + "\n")

    def done(clean: str) -> bool:
        lines = clean.splitlines()
        if not lines:
            return False
        if len(lines) == 1 and _is_echo(lines[0], cmd):
            return False                      # only the echo so far
        return prompt_re.search(lines[-1]) is not None

    output = _read_until(sock, done, timeout=command_timeout)

    lines = output.splitlines()
    if lines and _is_echo(lines[0], cmd):
        lines = lines[1:]
    if lines and prompt_re.search(lines[-1]):
        lines = lines[:-1]
    return "\n".join(lines)


def _learn_prompt(reply: str, prompt_re: re.Pattern, cli: CliSyntax) -> re.Pattern:
    """The device's own prompt, from the first one seen after login: from
    then on only `user@host` (or `Router`, with its config-mode suffix) ends a
    reply, not any line that happens to end in `>` or `#`."""
    seen = [l.strip() for l in reply.splitlines() if l.strip()]
    if not seen:
        return prompt_re
    m = cli.prompt_name.search(seen[-1])
    return re.compile(re.escape(m.group(1)) + cli.prompt_tail) if m else prompt_re


def _edit_ios(sock: socket.socket, prompt_re: re.Pattern, payload: str, cli: CliSyntax) -> str:
    """Config mode without a candidate: configure terminal -> commands -> end."""
    _send_command(sock, prompt_re, cli.config_enter, 10)

    errors = []
    for line in payload.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        # The reply without the echoed line, so the line's own text is not
        # mistaken for the device's complaint about it.
        output = _send_command(sock, prompt_re, line, 10)
        if "invalid" in output.lower() or "error" in output.lower() or "%" in output:
            errors.append(f"'{line}': {output.strip()}")

    _send_command(sock, prompt_re, cli.config_exit, 10)

    if errors:
        raise RuntimeError("; ".join(errors))
    return "(config applied)"


def _leave_quietly(sock: socket.socket, prompt_re: re.Pattern, *cmds: str) -> None:
    """Send what ends a Junos edit whose verdict is already known: rollback 0
    when the candidate still holds the change, then exit. A device that no
    longer answers them is let be, as the NETCONF driver's unlock is: the
    session close that follows drops the exclusive candidate and its lock
    either way, and a commit that took the management address or the telnet
    service with it cannot answer the exit."""
    try:
        for cmd in cmds:
            _send_command(sock, prompt_re, cmd, 10)
    except OSError:
        pass


def _refuse_commit_lines(payload: str) -> None:
    """`commit` typed inside configure mode would commit (and confirm any
    pending timer) halfway through a payload. A confirm is `-eC "commit"`
    on its own, which confirm() handles; here it is refused before the
    device is contacted."""
    for line in payload.strip().splitlines():
        if line.strip().split(" ")[0] == "commit":
            raise ValueError("'commit' is not configuration; a pending commit-confirmed is confirmed "
                             "with -eC \"commit\" alone. Nothing was sent to the device")


def _edit_junos(sock: socket.socket, prompt_re: re.Pattern, d: Dialect,
                payload: str, dry_run: bool, confirmed_minutes: int = 0,
                expected_diff: Optional[str] = None) -> str:
    """Config mode with a candidate: configure exclusive -> commands -> show|compare -> commit/rollback.

    Exclusive mode keeps the candidate to this session, as the NETCONF
    driver's lock does: commit and rollback 0 never touch another user's
    pending changes, and the device refuses entry while someone else holds
    the lock - reported before any set line is sent. With `expected_diff`
    (what a dry run showed) the candidate is committed only if
    `show | compare` says the same again.
    """
    cli = d.cli
    _refuse_commit_lines(payload)
    reply = _send_command(sock, prompt_re, cli.config_enter, 10)
    if d.refused.search(reply):
        raise NotAppliedError(f"Failed to lock config: {reply.strip()}")

    errors = []
    for line in payload.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        output = _send_command(sock, prompt_re, line, 10)
        if d.refused.search(output):
            errors.append(f"'{line}': {output.strip()}")

    diff = _send_command(sock, prompt_re, cli.compare, 30).strip()
    changed = expected_diff is not None and diff != expected_diff.strip()

    if dry_run or errors or changed:
        _leave_quietly(sock, prompt_re, cli.discard, cli.config_exit)
        if errors:
            raise RuntimeError("; ".join(errors))
        if changed:
            raise RuntimeError("diff changed since preview; nothing committed")
        return f"DRY-RUN\n\nDIFF:\n{diff}" if diff else "NO CHANGES"

    if confirmed_minutes and confirmed_minutes > 0:
        commit_cmd = f"{cli.commit} confirmed {confirmed_minutes}"
    else:
        commit_cmd = cli.commit
    try:
        commit_output = _send_command(sock, prompt_re, commit_cmd, 60)
    except OSError as e:
        # The commit was sent. We cannot tell whether it landed: say so, and
        # neither claim it nor roll anything back.
        raise AmbiguousCommitError(
            f"commit outcome unknown ({type(e).__name__}: {e}); "
            "check the device before retrying") from e

    if d.refused.search(commit_output):
        # A refused commit leaves the change in our candidate; discard it so
        # the exit is clean and the lock goes with it.
        _leave_quietly(sock, prompt_re, cli.discard, cli.config_exit)
        raise RuntimeError(f"Commit failed: {commit_output.strip()}")

    _leave_quietly(sock, prompt_re, cli.config_exit)

    if confirmed_minutes and confirmed_minutes > 0:
        return f"COMMIT CONFIRMED ({confirmed_minutes} minutes)\n\nDIFF:\n{diff}" if diff else "NO CHANGES"
    return f"COMMIT OK\n\nDIFF:\n{diff}" if diff else "NO CHANGES"


def _pending(history: str, d: Dialect) -> bool:
    """The latest entry of `show system commit` while a commit confirmed waits:
    "0   2026-10-22 08:00:00 UTC by lab via cli commit confirmed, rollback in 5mins"."""
    return any(re.match(r"^\s*0\s+", line) and d.commit_pending.search(line)
               for line in history.splitlines())


def confirm(host: str, user: str, passwd: str,
            session_timeout: int, command_timeout: int,
            port: int = None, vendor_hint: str = "telnet-junos",
            comment: Optional[str] = None) -> str:
    """Confirm a pending commit-confirmed on a telnet-junos device: configure
    exclusive, a bare `commit` (`commit comment "…"` with a comment), exit.
    Without this the runner handed the word `commit` to the edit path, which
    committed twice and reported someone else's diff."""
    d = _dialect(vendor_hint)
    if d.commit_pending is None or not d.cli.has_candidate:
        raise ValueError(f"confirm is only for telnet-junos, not {vendor_hint}; nothing was sent")
    sock, prompt_re = _connect_and_login(host, user, passwd, port if port is not None else 23,
                                         session_timeout, d.cli)
    try:
        # Nothing waiting means the timer expired or it was confirmed
        # already; a commit now would hide that from the operator.
        history = _send_command(sock, prompt_re, "show system commit", command_timeout)
        if not _pending(history, d):
            raise NothingToConfirmError(
                "nothing to confirm: no commit-confirmed is pending on the device "
                "(the timer expired, or it was confirmed already); nothing was sent")
        reply = _send_command(sock, prompt_re, d.cli.config_enter, 10)
        if d.refused.search(reply):
            raise NotAppliedError(f"Failed to lock config: {reply.strip()}")
        commit_cmd = f'commit comment "{comment}"' if comment else "commit"
        try:
            out = _send_command(sock, prompt_re, commit_cmd, command_timeout)
        except OSError as e:
            raise AmbiguousCommitError(
                f"commit outcome unknown ({type(e).__name__}: {e}); check the device before retrying") from e
        if d.refused.search(out):
            _leave_quietly(sock, prompt_re, d.cli.config_exit)
            raise RuntimeError(f"Commit failed: {out.strip()}")
        _leave_quietly(sock, prompt_re, d.cli.config_exit)
        return "COMMIT CONFIRMED OK"
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Public functional API (matches vendor module interface)
# ---------------------------------------------------------------------------

def show(host: str, user: str, passwd: str, cmd: str,
         session_timeout: int, command_timeout: int,
         port: int = None, vendor_hint: str = "telnet") -> str:
    """Send a single show command via raw-socket telnet."""
    effective_port = port if port is not None else 23
    sock, prompt_re = _connect_and_login(host, user, passwd, effective_port,
                                         session_timeout, _dialect(vendor_hint).cli)
    try:
        return _send_command(sock, prompt_re, cmd, command_timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def edit(host: str, user: str, passwd: str, payload: str,
         session_timeout: int, command_timeout: int,
         commit_confirmed: int = None, port: int = None,
         vendor_hint: str = "telnet", dry_run: bool = False,
         expected_diff: Optional[str] = None) -> str:
    """Send configuration commands via raw-socket telnet.

    dry_run, commit_confirmed and expected_diff exist for Junos only (the
    candidate is diffed and rolled back, armed with a timer, or checked
    against the diff a dry run showed). An IOS-style flavour cannot honour
    them, so asking is a ValueError before anything is sent, never a dry
    run that lands or a commit with no timer.
    """
    effective_port = port if port is not None else 23
    d = _dialect(vendor_hint)
    if not d.cli.has_candidate and (dry_run or commit_confirmed is not None or expected_diff is not None):
        raise ValueError(f"dry_run, commit_confirmed and expected_diff are not supported by "
                         f"{vendor_hint}; nothing was sent to the device")
    check_confirm_minutes(commit_confirmed)
    if d.cli.has_candidate:
        _refuse_commit_lines(payload)

    sock, prompt_re = _connect_and_login(host, user, passwd, effective_port,
                                         session_timeout, d.cli)
    try:
        if d.cli.has_candidate:
            return _edit_junos(sock, prompt_re, d, payload, dry_run=dry_run,
                               confirmed_minutes=commit_confirmed or 0,
                               expected_diff=expected_diff)
        else:
            return _edit_ios(sock, prompt_re, payload, d.cli)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = "telnet") -> List[dict]:
    """Execute multiple show commands on a single telnet connection."""
    effective_port = port if port is not None else 23
    sock, prompt_re = _connect_and_login(host, user, passwd, effective_port,
                                         session_timeout, _dialect(vendor_hint).cli)
    try:
        results = []
        for cmd in cmds:
            try:
                output = _send_command(sock, prompt_re, cmd, command_timeout)
                results.append({"command": cmd, "ok": True, "output": output})
            except Exception as e:
                results.append({"command": cmd, "ok": False, "error": str(e)})
        return results
    finally:
        try:
            sock.close()
        except Exception:
            pass
