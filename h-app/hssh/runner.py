"""Task runner for executing commands on devices."""

import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, List, NamedTuple, Optional, Tuple

from .errors import NotAppliedError
from .audit import secure_write
from .core import Target, check_confirm_minutes, path_inside, read_set_file_for_device, read_command_file_lines
from .safety import SafetyGate
from . import drivers
from .drivers import results as R

MAX_RETRIES = 3
RETRY_BACKOFF = [1, 3]  # seconds between attempt 1->2, 2->3

# Failures that the same call cannot fix. Retrying them costs a full timeout
# each and, for the auth cases, spends real login attempts against a device
# that may well lock the account out.
_PERMANENT = (
    # Unreachable is unreachable for the duration of a run. A connect-phase
    # failure has already spent the full ConnectTimeout; spending it twice more
    # is what makes one dead device dominate a fleet run.
    "connect to host",
    # PyEZ reports the connect phase by exception class, and the junos driver
    # wraps every one of them: "NETCONF connect failed: ConnectTimeoutError(host)".
    # The prefix covers the whole connect phase, so the class names need no
    # entry of their own. ConnectClosedError and RpcTimeoutError only ever
    # arrive bare, after the session was up, so they fall through and are
    # retried: the next attempt may succeed.
    "netconf connect failed",
    "connection timed out",
    "connection refused",
    "no route to host",
    "network is unreachable",
    "unable to connect to port",
    "authentication failed",
    "login failed",  # telnet: the device asked for credentials again
    "permission denied",
    "host key verification",
    "cannot resolve",
    "could not resolve",
    "no such file",
    "unknown vendor",
    "not supported by",
    "no username",
    "openssh >= ",
    "rejected the operational command",
    "no rpc equivalent",
    "no 'ssh' binary",
    # A device that rejected the command will reject it again: EOS says
    # "invalid command [Invalid input (at token ...)]", IOS "% Invalid input".
    # A bare "invalid" also caught paramiko's "Invalid SSH banner" and the
    # OS's "Invalid argument", which are transport trouble, not a verdict.
    "invalid command",
    "invalid input",
    "syntax error",
    # The text transports' own verdict on a reply (#88): the same command
    # gets the same refusal.
    "was refused by the device",
    # The request itself is wrong: the same call cannot come out differently,
    # and each retry costs a full session timeout per device on a fleet.
    "no structured binding",                 # --structured on a command without one (junos)
    "no authentication methods available",   # paramiko: no password, no key, no agent
    "contains invalid characters",           # OpenSSH refuses the user or host name
    "malformed known_hosts line",            # the pin file cannot be parsed
    "locked by another h-ssh run",           # ssh: the pin file, past the session timeout
    "no ssh session",                        # openssh: the session never opened within --session-timeout
)

# Failures that happen before any session exists: nothing reached the device.
_CONNECT_PHASE = (
    "netconf connect failed",
    "connect to host",
    "connection refused",
    "no route to host",
    "network is unreachable",
    "unable to connect to port",
    "ssh protocol banner",
    "connection timed out",
    "no ssh session",
    "key exchange did not finish",          # the paramiko transports: banner, then no key exchange
)


def is_permanent_failure(exc) -> bool:
    """True when another identical attempt cannot plausibly succeed."""
    text = str(exc).lower()
    return any(marker in text for marker in _PERMANENT)


def is_connect_failure(exc_or_text) -> bool:
    """True when the failure happened while connecting, before any session
    existed: nothing reached the device. paramiko's bare socket timeout is
    the whole message 'timed out'; a command timeout always says more."""
    text = str(exc_or_text).strip().lower()
    return text == "timed out" or any(marker in text for marker in _CONNECT_PHASE)


def _is_local_error(exc) -> bool:
    """True for failures raised before any device I/O: validation and missing files."""
    return isinstance(exc, (ValueError, FileNotFoundError))


def _say(text: str) -> None:
    """One progress line from a worker thread, written in one piece: print()
    writes the text and the newline separately, and two threads interleave."""
    try:
        sys.stdout.write(f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
        sys.stdout.flush()
    except (BrokenPipeError, ValueError, AttributeError):
        # The reader went away (`| head`) or stdout is closed: the device's
        # result is not an error because nobody is watching the progress.
        pass


def _backoff(attempt: int) -> int:
    """Seconds before attempt+1. Falls back to the last step once the table runs out."""
    if attempt <= len(RETRY_BACKOFF):
        return RETRY_BACKOFF[attempt - 1]
    return RETRY_BACKOFF[-1] if RETRY_BACKOFF else 1


def _retry_loop(fn, name, quiet, max_attempts, should_retry, *args, **kwargs):
    attempts = max(1, int(max_attempts))
    last_err = None
    for attempt in range(1, attempts + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            last_err = e
            if is_permanent_failure(e) or not should_retry(e):
                raise
            if attempt < attempts:
                delay = _backoff(attempt)
                if not quiet:
                    _say(f"{name:16s} RETRY {attempt}/{attempts - 1} in {delay}s ({e})")
                time.sleep(delay)
    raise last_err


def _with_retry(fn, name, quiet, max_attempts, *args, **kwargs):
    """Call fn until it succeeds, up to max_attempts. Permanent failures stop at one."""
    return _retry_loop(fn, name, quiet, max_attempts, lambda e: True, *args, **kwargs)


class RunResult(tuple):
    """What one target's run came to. It is the (name, ok, text, duration_ms)
    tuple it always was, compared, hashed, serialised and unpacked as one;
    `result` is the driver's typed answer (an EditResult, BatchResult or
    CommitStatus, a show's text or data) and `error` the failure in one line
    (what follows the last "ERROR:" in the text), so nothing has to be read
    back out of the text."""

    def __new__(cls, name: str, ok: bool, text: str, duration_ms: int, result: Any = None,
                error: Optional[str] = None):
        self = super().__new__(cls, (name, ok, text, duration_ms))
        self.result = result
        self.error = error
        return self

    def __getnewargs__(self):
        return (self[0], self[1], self[2], self[3], self.result, self.error)

    name = property(lambda self: self[0])
    ok = property(lambda self: self[1])
    text = property(lambda self: self[2])
    duration_ms = property(lambda self: self[3])

    def __repr__(self):
        return (f"RunResult(name={self[0]!r}, ok={self[1]!r}, duration_ms={self[3]!r}, "
                f"result={type(self.result).__name__ if self.result is not None else None}, error={self.error!r})")


def error_line(text: str) -> Optional[str]:
    """The failure as the CLI always read it: what follows the last line
    starting with "ERROR:", stripped; None when there is no such line."""
    for ln in reversed(text.splitlines()):
        if ln.startswith("ERROR:"):
            return ln[len("ERROR:"):].strip()
    return None


class Bound(NamedTuple):
    """The driver a target resolved to: the module that does the work, the
    name the operator used (for messages), what it may be asked, and the
    vendor_hint its functions take."""
    mod: object
    vendor: str
    caps: frozenset
    hint: str
    dialect: object


def bind(vendor: str) -> Bound:
    """Resolve a target's vendor name through the driver registry. What the
    run may ask is the driver's `supports`; a module standing in for the
    driver's own (a test double) is believed on the functions it has, with
    the by-name policies (dry run, commit confirmed, comment) still the
    registry's. Everything else must refuse rather than quietly do something
    weaker: an edit that cannot really validate a candidate and discard it,
    a commit that cannot really arm a rollback timer."""
    driver = drivers.get(vendor)
    mod = drivers.module_of(driver)
    return Bound(mod, vendor, drivers.supports_of(driver, mod), driver.name, driver.dialect)


def _comment_kwargs(b: Bound, comment):
    """{"comment": ...} for drivers that take one; refused elsewhere rather
    than silently dropped."""
    if comment is None:
        return {}
    if "comment" not in b.caps:
        raise ValueError(f"--comment is not supported by the '{b.vendor}' transport")
    return {"comment": comment}


def _expected_diff_kwargs(b: Bound, expected_diff):
    """{"expected_diff": ...} for the drivers that diff a candidate before
    committing it (the ones that can dry-run); refused elsewhere, since a
    transport that cannot show a diff cannot check one either."""
    if expected_diff is None:
        return {}
    if "dry_run" not in b.caps:
        raise ValueError(
            f"expected_diff is not supported by the '{b.vendor}' transport; "
            "nothing was sent to the device")
    return {"expected_diff": expected_diff}


def _check_edit_policy(b: Bound, commit_confirmed, dry_run):
    check_confirm_minutes(commit_confirmed)
    if commit_confirmed and "commit_confirmed" not in b.caps:
        raise ValueError(
            f"--commit-confirmed is not supported by the '{b.vendor}' transport; "
            "the change would be applied with no rollback timer")
    if dry_run and "dry_run" not in b.caps:
        raise ValueError(
            f"--dry-run is not supported by the '{b.vendor}' transport for edits; "
            "nothing was sent to the device")


def _apply_rollback(b: Bound, name, quiet, max_attempts, host, user, passwd,
                    n, session_timeout, command_timeout, commit_confirmed, port, dry_run=False,
                    comment=None, expected_diff=None):
    """Return to rollback n. Same rules as an edit: refused where the transport
    cannot really do it, retried only when nothing reached the device, and
    with `expected_diff` committed only if the device shows that diff again."""
    if "rollback" not in b.caps:
        raise ValueError(f"--rollback is not supported by the '{b.vendor}' transport")
    _check_edit_policy(b, commit_confirmed, dry_run)
    return _retry_loop(
        b.mod.rollback, name, quiet, max_attempts,
        lambda e: isinstance(e, NotAppliedError),
        host, user, passwd, n, session_timeout, command_timeout,
        port=port, vendor_hint=b.hint, dry_run=dry_run, commit_confirmed=commit_confirmed,
        **_comment_kwargs(b, comment), **_expected_diff_kwargs(b, expected_diff))


def _apply_edit(b: Bound, name, quiet, max_attempts, host, user, passwd,
                payload, session_timeout, command_timeout, commit_confirmed,
                port, dry_run=False, comment=None, expected_diff=None):
    """Push configuration. An edit is not idempotent, so it is only retried when
    the driver says nothing reached the device (NotAppliedError); any other
    failure, and above all a timeout around a commit, is reported, not repeated.
    `expected_diff` is the diff a dry run showed: the driver commits only if
    the candidate produces it again."""
    _check_edit_policy(b, commit_confirmed, dry_run)
    kwargs = {"port": port, "vendor_hint": b.hint, **_comment_kwargs(b, comment),
              **_expected_diff_kwargs(b, expected_diff)}
    if dry_run:
        kwargs["dry_run"] = True
    return _retry_loop(
        b.mod.edit, name, quiet, max_attempts,
        lambda e: isinstance(e, NotAppliedError),
        host, user, passwd, payload, session_timeout, command_timeout,
        commit_confirmed, **kwargs)


def _rpc_call(b: Bound, batch=False):
    """The transport's rpc() (rpc_batch() for a batch), or a refusal. Only a
    driver that can ask the router for a command's own JSON or XML has one;
    a text transport must say so rather than hand back the text as before."""
    fn = getattr(b.mod, "rpc_batch" if batch else "rpc", None) if "rpc" in b.caps else None
    if fn is None:
        raise ValueError(
            f"--format json/xml is not supported by the '{b.vendor}' transport; "
            "nothing was sent to the device")
    return fn


def _run_for_target_sync(
    t: Target,
    transport: str,
    mode: str,
    show_cmd: Optional[str],
    edit_cmd: Optional[str],
    config_dir: Optional[str],
    broadcast_file: Optional[str],
    user: str,
    passwd: str,
    session_timeout: int,
    command_timeout: int,
    dry_run: bool,
    commit_confirmed: Optional[int],
    save_dir: Optional[str],
    quiet: bool = False,
    batch_cmds: Optional[List[str]] = None,
    safety_gate: Optional[SafetyGate] = None,
    structured: bool = False,
    structured_binding: Optional[dict] = None,
    max_attempts: int = MAX_RETRIES,
    rollback: Optional[int] = None,
    comment: Optional[str] = None,
    fmt: str = "text",
    expected_diff: Optional[str] = None,
    payload_text: Optional[str] = None,
) -> RunResult:
    """
    Execute task on a single target device (internal sync implementation).
    Returns: (device_name, success, output_text, duration_ms)
    """
    start_time = time.time()
    name = t.name
    host = t.host
    vendor = t.vendor

    # Safety gate: check before contacting device
    if safety_gate is not None:
        allowed, reason = safety_gate.check_device(host)
        if not allowed:
            duration_ms = int((time.time() - start_time) * 1000)
            err_out = f"DEVICE: {name}\nHOST:   {host}\nMODE:   {mode}\nVENDOR: {vendor}\n\nERROR: safety gate blocked: {reason}\n"
            return RunResult(name, False, err_out, duration_ms, error=error_line(err_out))

    if not quiet:
        _say(f"{name:16s} STARTED")

    b = bind(vendor)

    output = []
    output.append(f"DEVICE: {name}")
    output.append(f"HOST:   {host}")
    output.append(f"MODE:   {mode}")
    output.append(f"VENDOR: {vendor}")
    output.append("")
    typed = None   # the driver's answer, typed, for RunResult.result

    try:
        if mode == "show":
            if not show_cmd:
                raise ValueError("No show command provided.")
            # A show that is not a read (`request system reboot`, `clear bgp
            # neighbor`) is sent once: a timeout after it must not mean two
            # more reboots. --format turns the text into an RPC and sends it
            # with no gate at all, so there it is refused outright.
            read = b.dialect.is_read(show_cmd)
            attempts = max_attempts if read else 1
            if dry_run:
                result = f"DRY-RUN show: {show_cmd}"
            elif fmt != "text":
                if not read:
                    raise ValueError(
                        f"--format {fmt} runs reads only (show …, get-*); {show_cmd!r} would act on "
                        "the device with no confirmation. Nothing was sent.")
                # The router's own JSON or XML for the command, through its
                # RPC translation. Only the NETCONF driver can do that; a
                # transport that cannot refuses here, before any device I/O.
                data = _with_retry(_rpc_call(b), name, quiet, max_attempts,
                                   host, user, passwd, show_cmd, session_timeout, command_timeout,
                                   port=t.port, vendor_hint=b.hint, fmt=fmt)
                typed = data
                result = data if fmt == "xml" else json.dumps(data, indent=2)
            elif structured and "show_structured" in b.caps:
                # A driver without show_structured (ssh, openssh, telnet)
                # falls through to the text path below.
                data = _with_retry(b.mod.show_structured, name, quiet, attempts,
                                   host, user, passwd, show_cmd,
                                   session_timeout, command_timeout,
                                   port=t.port, vendor_hint=b.hint,
                                   binding=structured_binding)
                typed = data
                result = json.dumps(data, indent=2, default=str)
            else:
                if not read and not quiet:
                    _say(f"{name:16s} NOTE {show_cmd!r} is not a read: sent once, never retried")
                result = _with_retry(b.mod.show, name, quiet, attempts,
                                     host, user, passwd, show_cmd, session_timeout, command_timeout,
                                     port=t.port, vendor_hint=b.hint)
            if typed is None:
                typed = result
            output.append(result.rstrip())

        elif mode == "edit-cmd":
            if not edit_cmd:
                raise ValueError("No edit command provided.")
            payload = edit_cmd.strip() + "\n"
            if payload.strip() in ("commit", "commit;") and "confirm" in b.caps:
                # Only a literal -eC "commit" confirms a pending commit-confirmed;
                # the same word inside an -eD/-eB file is just (invalid) config.
                # A driver that cannot confirm gets it as an edit, and every
                # edit() refuses a commit line before the device is contacted.
                if dry_run:
                    raise ValueError("--dry-run cannot preview a commit confirmation")
                result = _retry_loop(b.mod.confirm, name, quiet, max_attempts,
                                     lambda e: isinstance(e, NotAppliedError),
                                     host, user, passwd, session_timeout, command_timeout,
                                     port=t.port, vendor_hint=b.hint,
                                     **_comment_kwargs(b, comment))
            else:
                result = _apply_edit(b, name, quiet, max_attempts,
                                     host, user, passwd, payload, session_timeout,
                                     command_timeout, commit_confirmed, t.port, dry_run, comment,
                                     expected_diff)
            typed = R.as_edit(result)
            output.append(typed.rstrip())

        elif mode == "edit-dir":
            if not config_dir:
                raise ValueError("No config directory provided for -eD.")
            # The CLI hands over the text it validated; a file re-read here
            # could differ from what the guard saw.
            payload = payload_text if payload_text is not None else read_set_file_for_device(config_dir, name)
            result = _apply_edit(b, name, quiet, max_attempts,
                                 host, user, passwd, payload, session_timeout,
                                 command_timeout, commit_confirmed, t.port, dry_run, comment,
                                 expected_diff)
            typed = R.as_edit(result)
            output.append(typed.rstrip())

        elif mode == "edit-broadcast":
            if not broadcast_file:
                raise ValueError("No broadcast file provided for -eB.")
            payload = payload_text if payload_text is not None else _read_broadcast_file(broadcast_file)
            result = _apply_edit(b, name, quiet, max_attempts,
                                 host, user, passwd, payload, session_timeout,
                                 command_timeout, commit_confirmed, t.port, dry_run, comment,
                                 expected_diff)
            typed = R.as_edit(result)
            output.append(typed.rstrip())

        elif mode == "commit-status":
            if "commit_status" not in b.caps:
                raise ValueError(f"--commit-status is not supported by the '{vendor}' transport")
            if dry_run:
                # A dry run contacts no device, for a read too.
                typed = R.CommitStatus()
                output.append("DRY-RUN commit-status (no session opened)")
                output.append(json.dumps([]))
            else:
                entries = _with_retry(b.mod.commit_status, name, quiet, max_attempts,
                                      host, user, passwd, session_timeout, command_timeout,
                                      port=t.port, vendor_hint=b.hint)
                typed = R.as_commits(entries)
                output.append(json.dumps(typed.to_list()))

        elif mode == "rollback":
            if rollback is None:
                raise ValueError("No rollback number provided for --rollback.")
            result = _apply_rollback(b, name, quiet, max_attempts,
                                     host, user, passwd, rollback, session_timeout,
                                     command_timeout, commit_confirmed, t.port, dry_run, comment,
                                     expected_diff)
            typed = R.as_edit(result)
            output.append(typed.rstrip())

        elif mode == "show-batch":
            if batch_cmds and not all(b.dialect.is_read(c) for c in batch_cmds):
                max_attempts = 1
            if not batch_cmds:
                raise ValueError("No batch commands provided.")
            if dry_run:
                cmd_results = [{"command": c, "ok": True, "output": f"DRY-RUN show: {c}"} for c in batch_cmds]
            elif fmt != "text":
                cmd_results = _with_retry(_rpc_call(b, batch=True), name, quiet, max_attempts,
                                          host, user, passwd, batch_cmds, session_timeout, command_timeout,
                                          port=t.port, vendor_hint=b.hint, fmt=fmt)
            else:
                cmd_results = _with_retry(b.mod.show_batch, name, quiet, max_attempts,
                                          host, user, passwd, batch_cmds, session_timeout, command_timeout,
                                          port=t.port, vendor_hint=b.hint)
            batch = R.as_batch(cmd_results)
            result_json = json.dumps(batch.to_list())
            duration_ms = int((time.time() - start_time) * 1000)
            if save_dir:
                secure_write(str(path_inside(save_dir, f"{name}.json")), result_json)
            if safety_gate is not None:
                safety_gate.release_device(host)
            return RunResult(name, batch.ok, result_json, duration_ms, result=batch, error=batch.first_error)

        else:
            raise ValueError(f"Unknown mode: {mode}")

        final_out = "\n".join(output).strip() + "\n"
        duration_ms = int((time.time() - start_time) * 1000)

        if save_dir:
            secure_write(str(path_inside(save_dir, f"{name}.output")), final_out)

        if safety_gate is not None:
            safety_gate.release_device(host)
        return RunResult(name, True, final_out, duration_ms, result=typed)

    except Exception as e:
        if safety_gate is not None:
            if _is_local_error(e):
                # Nothing reached the device (bad arguments, missing file, a
                # transport that refuses the request). Cooling the device for
                # that would punish it for our own mistake.
                safety_gate.release_device(host)
            else:
                safety_gate.set_cooldown(host)
        output.append(f"ERROR: {e}")
        final_out = "\n".join(output).strip() + "\n"
        duration_ms = int((time.time() - start_time) * 1000)
        if save_dir:
            secure_write(str(path_inside(save_dir, f"{name}.output")), final_out)
        return RunResult(name, False, final_out, duration_ms, error=error_line(final_out))


def run_for_target(
    t: Target,
    transport: str,
    mode: str,
    show_cmd: Optional[str],
    edit_cmd: Optional[str],
    config_dir: Optional[str],
    broadcast_file: Optional[str],
    user: str,
    passwd: str,
    session_timeout: int,
    command_timeout: int,
    dry_run: bool,
    commit_confirmed: Optional[int],
    save_dir: Optional[str],
    quiet: bool = False,
    batch_cmds: Optional[List[str]] = None,
    safety_gate: Optional[SafetyGate] = None,
    structured: bool = False,
    structured_binding: Optional[dict] = None,
    max_attempts: int = MAX_RETRIES,
    rollback: Optional[int] = None,
    comment: Optional[str] = None,
    fmt: str = "text",
    expected_diff: Optional[str] = None,
    payload_text: Optional[str] = None,
) -> RunResult:
    """
    Synchronous public API for library users. `expected_diff` is the diff a
    dry run showed; an edit or rollback is then committed only if the device
    produces it again.
    Returns: (device_name, success, output_text, duration_ms)
    """
    return _run_for_target_sync(
        t=t, transport=transport, mode=mode,
        show_cmd=show_cmd, edit_cmd=edit_cmd,
        config_dir=config_dir, broadcast_file=broadcast_file,
        user=user, passwd=passwd,
        session_timeout=session_timeout, command_timeout=command_timeout,
        dry_run=dry_run, commit_confirmed=commit_confirmed,
        save_dir=save_dir, quiet=quiet, batch_cmds=batch_cmds,
        safety_gate=safety_gate,
        structured=structured, structured_binding=structured_binding,
        max_attempts=max_attempts,
        rollback=rollback,
        comment=comment,
        fmt=fmt,
        expected_diff=expected_diff,
        payload_text=payload_text,
    )


async def run_for_target_async(
    t: Target,
    transport: str,
    mode: str,
    show_cmd: Optional[str],
    edit_cmd: Optional[str],
    config_dir: Optional[str],
    broadcast_file: Optional[str],
    user: str,
    passwd: str,
    session_timeout: int,
    command_timeout: int,
    dry_run: bool,
    commit_confirmed: Optional[int],
    save_dir: Optional[str],
    quiet: bool = False,
    batch_cmds: Optional[List[str]] = None,
    safety_gate: Optional[SafetyGate] = None,
    structured: bool = False,
    structured_binding: Optional[dict] = None,
    max_attempts: int = MAX_RETRIES,
    rollback: Optional[int] = None,
    comment: Optional[str] = None,
    fmt: str = "text",
    expected_diff: Optional[str] = None,
    payload_text: Optional[str] = None,
) -> RunResult:
    """
    Async public API. Offloads the sync vendor calls to a thread.
    Returns: (device_name, success, output_text, duration_ms)
    """
    return await asyncio.to_thread(
        _run_for_target_sync,
        t=t, transport=transport, mode=mode,
        show_cmd=show_cmd, edit_cmd=edit_cmd,
        config_dir=config_dir, broadcast_file=broadcast_file,
        user=user, passwd=passwd,
        session_timeout=session_timeout, command_timeout=command_timeout,
        dry_run=dry_run, commit_confirmed=commit_confirmed,
        save_dir=save_dir, quiet=quiet, batch_cmds=batch_cmds,
        safety_gate=safety_gate,
        structured=structured, structured_binding=structured_binding,
        max_attempts=max_attempts,
        rollback=rollback,
        comment=comment,
        fmt=fmt,
        expected_diff=expected_diff,
        payload_text=payload_text,
    )


def _read_broadcast_file(broadcast_file: str) -> str:
    """Read broadcast config file."""
    path = Path(broadcast_file)
    if not path.is_file():
        raise FileNotFoundError(f"Broadcast file not found: {broadcast_file}")
    return path.read_text(encoding="utf-8-sig")
