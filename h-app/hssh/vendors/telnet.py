"""Raw-socket telnet transport for console ports and legacy devices: the CLI
engine (hssh.transports.cli) on a telnet channel (hssh.transports.telnet),
in the dialect the vendor_hint names. Frozen: it inherits dialects and
fixes and gets nothing of its own.
"""

import re
import socket
from typing import List, Optional

from .. import drivers
from ..dialects.base import Dialect
from ..drivers import results as R
from ..transports.cli import (Cli, LOGIN_RE, PASSWORD_RE, MORE_PATTERNS, strip_ansi as _strip_ansi,  # noqa: F401
                              edit_policy, refuse_commit_lines as _refuse_commit_lines)
from ..transports.telnet import TelnetChannel, negotiate as _negotiate_telnet  # noqa: F401

AVAILABLE = True  # Raw sockets, always available


def _dialect(vendor_hint: Optional[str]) -> Dialect:
    """The dialect behind a vendor_hint: telnet-junos is junos, telnet-ios is
    ios, plain telnet is none (an IOS-shaped prompt, as always). The hint is
    the shim-era way to name a dialect; #84 hands the object in."""
    try:
        return drivers.get(vendor_hint or "telnet").dialect
    except ValueError:
        return drivers.NONE


# The prompts by the flavour names telnet used, for the tests that read them.
PROMPT_PATTERNS = {
    "ios": drivers.IOS.cli.prompt,
    "junos": drivers.JUNOS.cli.prompt,
    "arista": drivers.EOS.cli.prompt,
    "nxos": drivers.NXOS.cli.prompt,
}


def _read_until_prompt(sock: socket.socket, prompt_re: re.Pattern, timeout: int, buffer: str = "") -> str:
    """Read from a socket until a CLI prompt is detected (the engine's reader on a bare socket)."""
    session = Cli(TelnetChannel(sock), drivers.NONE, timeout)
    session.prompt_re = prompt_re
    return session.read_until_prompt(timeout, buffer)


def _connect_and_login(host: str, user: Optional[str], passwd: Optional[str],
                       port: int, session_timeout: int, dialect: Dialect) -> Cli:
    """Open the socket, negotiate telnet, log in: a CLI session at a prompt.
    Raises NotAppliedError when the device rejects the credentials or shows no
    prompt within session_timeout, even after an Enter."""
    channel = TelnetChannel.connect(host, port, session_timeout)
    session = Cli(channel, dialect, session_timeout, initial=channel.initial)
    session.login(user, passwd)
    return session


def confirm(host: str, user: str, passwd: str,
            session_timeout: int, command_timeout: int,
            port: int = None, vendor_hint: str = "telnet-junos",
            comment: Optional[str] = None) -> R.EditResult:
    """Confirm a pending commit-confirmed on a telnet-junos device: configure
    exclusive, a bare `commit` (`commit comment "…"` with a comment), exit.
    Without this the runner handed the word `commit` to the edit path, which
    committed twice and reported someone else's diff."""
    d = _dialect(vendor_hint)
    if d.commit_pending is None or not d.cli.has_candidate:
        raise ValueError(f"confirm is only for telnet-junos, not {vendor_hint}; nothing was sent")
    session = _connect_and_login(host, user, passwd, port if port is not None else 23, session_timeout, d)
    try:
        return session.confirm(command_timeout, comment)
    finally:
        session.close()


def show(host: str, user: str, passwd: str, cmd: str,
         session_timeout: int, command_timeout: int,
         port: int = None, vendor_hint: str = "telnet") -> str:
    """Send a single show command via raw-socket telnet."""
    session = _connect_and_login(host, user, passwd, port if port is not None else 23,
                                 session_timeout, _dialect(vendor_hint))
    try:
        return session.run(cmd, command_timeout)
    finally:
        session.close()


def edit(host: str, user: str, passwd: str, payload: str,
         session_timeout: int, command_timeout: int,
         commit_confirmed: int = None, port: int = None,
         vendor_hint: str = "telnet", dry_run: bool = False,
         expected_diff: Optional[str] = None) -> R.EditResult:
    """Send configuration commands via raw-socket telnet.

    dry_run, commit_confirmed and expected_diff exist for a dialect with a
    candidate configuration only (Junos: the candidate is diffed and rolled
    back, armed with a timer, or checked against the diff a dry run showed).
    An IOS-style flavour cannot honour them, so asking is a ValueError
    before anything is sent, never a dry run that lands or a commit with no
    timer.
    """
    d = _dialect(vendor_hint)
    edit_policy(d, vendor_hint, dry_run, commit_confirmed, expected_diff)
    if d.cli.has_candidate:
        _refuse_commit_lines(payload)
    session = _connect_and_login(host, user, passwd, port if port is not None else 23, session_timeout, d)
    try:
        if d.cli.has_candidate:
            return session.edit_candidate(payload, dry_run=dry_run, confirmed_minutes=commit_confirmed or 0,
                                          expected_diff=expected_diff)
        return session.edit_lines(payload)
    finally:
        session.close()


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = "telnet") -> R.BatchResult:
    """Execute multiple show commands on a single telnet connection."""
    session = _connect_and_login(host, user, passwd, port if port is not None else 23,
                                 session_timeout, _dialect(vendor_hint))
    try:
        results = []
        for cmd in cmds:
            try:
                output = session.run(cmd, command_timeout)
                results.append({"command": cmd, "ok": True, "output": output})
            except Exception as e:
                results.append({"command": cmd, "ok": False, "error": str(e)})
        return R.BatchResult(results)
    finally:
        session.close()
