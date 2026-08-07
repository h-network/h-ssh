"""Raw-socket telnet transport for console ports and legacy devices.

Uses raw sockets instead of telnetlib (deprecated in Python 3.11, removed in 3.13).
Handles login sequences, --More-- pagination, and per-vendor prompt detection.
Supports IOS, Junos, Arista, and NX-OS style prompts.
"""

import re
import socket
import time
from typing import List, Optional

AVAILABLE = True  # Raw sockets, always available

# ANSI escape code stripper
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07|\x1b[()][0-9A-B]|\x0f|\x00')

# Per-vendor prompt patterns
PROMPT_PATTERNS = {
    "ios":    re.compile(r'[\w\-\.]+[>#]\s*$'),
    "junos":  re.compile(r'[\w\-\.]+@[\w\-\.]+[>%#]\s*$'),
    "arista": re.compile(r'[\w\-\.]+[>#]\s*$'),
    "nxos":   re.compile(r'[\w\-\.]+[>#]\s*$'),
}

# --More-- patterns for pagination
MORE_PATTERNS = [
    re.compile(r'---?\(more( \d+%)?\)---?', re.IGNORECASE),
    re.compile(r'--More--'),
    re.compile(r'\[yes,no\]'),
]

# Login prompts
LOGIN_RE = re.compile(r'(Username|Login|login|User Name)\s*:\s*$', re.IGNORECASE)
PASSWORD_RE = re.compile(r'(Password|password)\s*:\s*$', re.IGNORECASE)


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


def _read_until_prompt(sock: socket.socket, prompt_re: re.Pattern,
                       timeout: int, buffer: str = "") -> str:
    """Read from socket until a CLI prompt is detected."""
    buf = buffer
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        clean = _strip_ansi(buf)
        if prompt_re.search(clean):
            return clean

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(remaining, 2.0))
        try:
            chunk = sock.recv(4096).decode("utf-8", errors="replace")
            if not chunk:
                break
            buf += chunk
            clean = _strip_ansi(buf)

            # Handle --More-- pagination
            for more_re in MORE_PATTERNS:
                if more_re.search(clean):
                    _send(sock, " ")
                    buf = clean[:more_re.search(clean).start()]
                    break

            if prompt_re.search(clean):
                return clean
        except socket.timeout:
            clean = _strip_ansi(buf)
            if prompt_re.search(clean):
                return clean
            continue
        except (OSError, ConnectionError):
            break
    return _strip_ansi(buf)


def _read_until_prompt_or_login(sock: socket.socket, prompt_re: re.Pattern,
                                timeout: int, buffer: str = "") -> str:
    """Read until CLI prompt, login prompt, or password prompt."""
    buf = buffer
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        clean = _strip_ansi(buf)
        if LOGIN_RE.search(clean) or PASSWORD_RE.search(clean):
            return clean
        if prompt_re.search(clean):
            return clean

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(remaining, 2.0))
        try:
            chunk = sock.recv(4096).decode("utf-8", errors="replace")
            if not chunk:
                break
            buf += chunk
            clean = _strip_ansi(buf)
            if LOGIN_RE.search(clean) or PASSWORD_RE.search(clean):
                return clean
            if prompt_re.search(clean):
                return clean
        except socket.timeout:
            clean = _strip_ansi(buf)
            if LOGIN_RE.search(clean) or PASSWORD_RE.search(clean):
                return clean
            if prompt_re.search(clean):
                return clean
            continue
        except (OSError, ConnectionError):
            break
    return _strip_ansi(buf)


def _connect_and_login(host: str, user: Optional[str], passwd: Optional[str],
                       port: int, session_timeout: int,
                       vendor_hint: str = "ios") -> tuple:
    """Open raw socket, negotiate telnet, handle login.

    Returns (socket, prompt_re) tuple.
    """
    prompt_re = PROMPT_PATTERNS.get(vendor_hint, PROMPT_PATTERNS["ios"])
    sock = socket.create_connection((host, port), timeout=session_timeout)
    sock.settimeout(session_timeout)

    buffer = _negotiate_telnet(sock)
    initial = _read_until_prompt_or_login(sock, prompt_re, timeout=session_timeout, buffer=buffer)

    if LOGIN_RE.search(initial):
        _send(sock, (user or "") + "\n")
        resp = _read_until_prompt_or_login(sock, prompt_re, timeout=session_timeout)
        if PASSWORD_RE.search(resp):
            _send(sock, (passwd or "") + "\n")
            _read_until_prompt(sock, prompt_re, timeout=session_timeout)
    elif PASSWORD_RE.search(initial):
        _send(sock, (passwd or "") + "\n")
        _read_until_prompt(sock, prompt_re, timeout=session_timeout)

    return sock, prompt_re


def _send_command(sock: socket.socket, prompt_re: re.Pattern,
                  cmd: str, command_timeout: int) -> str:
    """Send a command and return output (stripped of echo and trailing prompt)."""
    _send(sock, cmd + "\n")
    output = _read_until_prompt(sock, prompt_re, timeout=command_timeout)

    lines = output.splitlines()
    # Strip command echo
    if lines and cmd.strip() in lines[0]:
        lines = lines[1:]
    # Strip trailing prompt
    if lines and prompt_re.search(lines[-1]):
        lines = lines[:-1]
    return "\n".join(lines)


def _edit_ios(sock: socket.socket, prompt_re: re.Pattern,
              payload: str, dry_run: bool) -> str:
    """IOS config mode: configure terminal -> commands -> end."""
    _send(sock, "configure terminal\n")
    _read_until_prompt(sock, prompt_re, timeout=10)

    errors = []
    for line in payload.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        _send(sock, line + "\n")
        output = _read_until_prompt(sock, prompt_re, timeout=10)
        if "invalid" in output.lower() or "error" in output.lower() or "%" in output:
            errors.append(f"'{line}': {output.strip()}")

    _send(sock, "end\n")
    _read_until_prompt(sock, prompt_re, timeout=10)

    if errors:
        raise RuntimeError("; ".join(errors))
    return "(config applied)"


def _edit_junos(sock: socket.socket, prompt_re: re.Pattern,
                payload: str, dry_run: bool, confirmed_minutes: int = 0) -> str:
    """Junos config mode: configure -> commands -> show|compare -> commit/rollback."""
    _send(sock, "configure\n")
    _read_until_prompt(sock, prompt_re, timeout=10)

    errors = []
    for line in payload.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        _send(sock, line + "\n")
        output = _read_until_prompt(sock, prompt_re, timeout=10)
        if "error" in output.lower() or "syntax error" in output.lower():
            errors.append(f"'{line}': {output.strip()}")

    # Get diff
    _send(sock, "show | compare\n")
    diff_output = _read_until_prompt(sock, prompt_re, timeout=30)
    diff_lines = diff_output.splitlines()
    if diff_lines and "show | compare" in diff_lines[0]:
        diff_lines = diff_lines[1:]
    if diff_lines and prompt_re.search(diff_lines[-1]):
        diff_lines = diff_lines[:-1]
    diff = "\n".join(diff_lines).strip()

    if dry_run or errors:
        _send(sock, "rollback 0\n")
        _read_until_prompt(sock, prompt_re, timeout=10)
        _send(sock, "exit\n")
        _read_until_prompt(sock, prompt_re, timeout=10)
        if errors:
            raise RuntimeError("; ".join(errors))
        return f"DRY-RUN\n\nDIFF:\n{diff}" if diff else "NO CHANGES"

    if confirmed_minutes and confirmed_minutes > 0:
        _send(sock, f"commit confirmed {confirmed_minutes}\n")
    else:
        _send(sock, "commit\n")
    commit_output = _read_until_prompt(sock, prompt_re, timeout=60)

    _send(sock, "exit\n")
    _read_until_prompt(sock, prompt_re, timeout=10)

    if "error" in commit_output.lower() or "failed" in commit_output.lower():
        raise RuntimeError(f"Commit failed: {commit_output.strip()}")

    if confirmed_minutes and confirmed_minutes > 0:
        return f"COMMIT CONFIRMED ({confirmed_minutes} minutes)\n\nDIFF:\n{diff}" if diff else "NO CHANGES"
    return f"COMMIT OK\n\nDIFF:\n{diff}" if diff else "NO CHANGES"


# ---------------------------------------------------------------------------
# Public functional API (matches vendor module interface)
# ---------------------------------------------------------------------------

def show(host: str, user: str, passwd: str, cmd: str,
         session_timeout: int, command_timeout: int,
         port: int = None, vendor_hint: str = "telnet") -> str:
    """Send a single show command via raw-socket telnet."""
    effective_port = port if port is not None else 23
    sub_vendor = vendor_hint.replace("telnet-", "") if vendor_hint.startswith("telnet") else vendor_hint
    if sub_vendor == "telnet":
        sub_vendor = "ios"

    sock, prompt_re = _connect_and_login(host, user, passwd, effective_port,
                                         session_timeout, sub_vendor)
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
         vendor_hint: str = "telnet") -> str:
    """Send configuration commands via raw-socket telnet."""
    effective_port = port if port is not None else 23
    sub_vendor = vendor_hint.replace("telnet-", "") if vendor_hint.startswith("telnet") else vendor_hint
    if sub_vendor == "telnet":
        sub_vendor = "ios"

    sock, prompt_re = _connect_and_login(host, user, passwd, effective_port,
                                         session_timeout, sub_vendor)
    try:
        if sub_vendor == "junos":
            return _edit_junos(sock, prompt_re, payload, dry_run=False,
                               confirmed_minutes=commit_confirmed or 0)
        else:
            return _edit_ios(sock, prompt_re, payload, dry_run=False)
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
    sub_vendor = vendor_hint.replace("telnet-", "") if vendor_hint.startswith("telnet") else vendor_hint
    if sub_vendor == "telnet":
        sub_vendor = "ios"

    sock, prompt_re = _connect_and_login(host, user, passwd, effective_port,
                                         session_timeout, sub_vendor)
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
