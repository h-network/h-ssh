"""Task runner for executing commands on devices."""

import asyncio
import json
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from .core import Target, read_set_file_for_device, read_command_file_lines
from .safety import SafetyGate
from . import vendors

MAX_RETRIES = 3
RETRY_BACKOFF = [1, 3]  # seconds between attempt 1->2, 2->3


def _with_retry(fn, name, quiet, *args, **kwargs):
    """Call fn with up to MAX_RETRIES attempts. Backoff between retries."""
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            last_err = e
            if attempt < MAX_RETRIES:
                delay = RETRY_BACKOFF[attempt - 1]
                if not quiet:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"[{timestamp}] {name:16s} RETRY {attempt}/{MAX_RETRIES - 1} in {delay}s ({e})")
                time.sleep(delay)
    raise last_err


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
) -> Tuple[str, bool, str, int]:
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
            return name, False, err_out, duration_ms

    if not quiet:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {name:16s} STARTED")

    # Resolve host if it's a name
    try:
        socket.gethostbyname(host)
    except Exception:
        pass

    # Get vendor module
    vendor_mod = vendors.get(vendor)

    output = []
    output.append(f"DEVICE: {name}")
    output.append(f"HOST:   {host}")
    output.append(f"MODE:   {mode}")
    output.append(f"VENDOR: {vendor}")
    output.append("")

    try:
        if mode == "show":
            if not show_cmd:
                raise ValueError("No show command provided.")
            if dry_run:
                result = f"DRY-RUN show: {show_cmd}"
            elif structured and hasattr(vendor_mod, "show_structured"):
                # Absence of show_structured on a vendor module is the whole
                # capability check — generic and telnet simply don't have one,
                # so they fall through to the text path below.
                data = _with_retry(vendor_mod.show_structured, name, quiet,
                                   host, user, passwd, show_cmd,
                                   session_timeout, command_timeout,
                                   port=t.port, vendor_hint=vendor,
                                   binding=structured_binding)
                result = json.dumps(data, indent=2, default=str)
            else:
                result = _with_retry(vendor_mod.show, name, quiet,
                                     host, user, passwd, show_cmd, session_timeout, command_timeout,
                                     port=t.port, vendor_hint=vendor)
            output.append(result.rstrip())

        elif mode == "edit-cmd":
            if not edit_cmd:
                raise ValueError("No edit command provided.")
            payload = edit_cmd.strip() + "\n"
            if dry_run:
                result = f"DRY-RUN edit: {edit_cmd}"
            else:
                result = _with_retry(vendor_mod.edit, name, quiet,
                                     host, user, passwd, payload, session_timeout, command_timeout,
                                     commit_confirmed, port=t.port, vendor_hint=vendor)
            output.append(result.rstrip())

        elif mode == "edit-dir":
            if not config_dir:
                raise ValueError("No config directory provided for -eD.")
            payload = _read_config_file(config_dir, name)
            if dry_run:
                result = f"DRY-RUN from {config_dir}/{name}.set:\n{payload}"
            else:
                result = _with_retry(vendor_mod.edit, name, quiet,
                                     host, user, passwd, payload, session_timeout, command_timeout,
                                     commit_confirmed, port=t.port, vendor_hint=vendor)
            output.append(result.rstrip())

        elif mode == "edit-broadcast":
            if not broadcast_file:
                raise ValueError("No broadcast file provided for -eB.")
            payload = _read_broadcast_file(broadcast_file)
            if dry_run:
                result = f"DRY-RUN broadcast from {broadcast_file}:\n{payload}"
            else:
                result = _with_retry(vendor_mod.edit, name, quiet,
                                     host, user, passwd, payload, session_timeout, command_timeout,
                                     commit_confirmed, port=t.port, vendor_hint=vendor)
            output.append(result.rstrip())

        elif mode == "show-batch":
            if not batch_cmds:
                raise ValueError("No batch commands provided.")
            if dry_run:
                cmd_results = [{"command": c, "ok": True, "output": f"DRY-RUN show: {c}"} for c in batch_cmds]
            else:
                cmd_results = _with_retry(vendor_mod.show_batch, name, quiet,
                                          host, user, passwd, batch_cmds, session_timeout, command_timeout,
                                          port=t.port, vendor_hint=vendor)
            all_ok = all(r["ok"] for r in cmd_results)
            result_json = json.dumps(cmd_results)
            duration_ms = int((time.time() - start_time) * 1000)
            if save_dir:
                out_path = Path(save_dir) / f"{name}.json"
                out_path.write_text(result_json, encoding="utf-8")
            if safety_gate is not None:
                safety_gate.release_device(host)
            return name, all_ok, result_json, duration_ms

        else:
            raise ValueError(f"Unknown mode: {mode}")

        final_out = "\n".join(output).strip() + "\n"
        duration_ms = int((time.time() - start_time) * 1000)

        if save_dir:
            out_path = Path(save_dir) / f"{name}.output"
            out_path.write_text(final_out, encoding="utf-8")

        if safety_gate is not None:
            safety_gate.release_device(host)
        return name, True, final_out, duration_ms

    except Exception as e:
        if safety_gate is not None:
            safety_gate.set_cooldown(host)
        output.append(f"ERROR: {e}")
        final_out = "\n".join(output).strip() + "\n"
        duration_ms = int((time.time() - start_time) * 1000)
        if save_dir:
            out_path = Path(save_dir) / f"{name}.output"
            out_path.write_text(final_out, encoding="utf-8")
        return name, False, final_out, duration_ms


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
) -> Tuple[str, bool, str, int]:
    """
    Synchronous public API for library users.
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
) -> Tuple[str, bool, str, int]:
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
    )


def _read_config_file(config_dir: str, dev_name: str) -> str:
    """Read per-device config file, strip comments."""
    path = Path(config_dir) / f"{dev_name}.set"
    if not path.is_file():
        raise FileNotFoundError(f"Missing config file for {dev_name}: {path}")
    lines = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        ln = ln.split("#", 1)[0].rstrip()
        if ln.strip():
            lines.append(ln)
    payload = "\n".join(lines).strip()
    if not payload:
        raise ValueError(f"Empty config after filtering: {path}")
    return payload + "\n"


def _read_broadcast_file(broadcast_file: str) -> str:
    """Read broadcast config file."""
    path = Path(broadcast_file)
    if not path.is_file():
        raise FileNotFoundError(f"Broadcast file not found: {broadcast_file}")
    return path.read_text(encoding="utf-8")
