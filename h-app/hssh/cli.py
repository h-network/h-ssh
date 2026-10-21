"""Command-line interface for h-ssh."""

import argparse
import asyncio
import concurrent.futures
import difflib
import getpass
import json
import os
import shlex
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

from .core import (
    Target, load_devices_csv, load_config, get_config_path,
    resolve_command, resolve_structured,
    get_available_commands, read_command_file_lines, parse_inline_target,
    load_jobs, resolve_target_port, validate_junos_set_syntax,
)
from .runner import run_for_target_async, COMMIT_CONFIRMED_VENDORS
from .safety import SafetyGate
from .audit import write_audit_entry
from .vendors import VENDORS


# Supported vendor names for validation: the vendors registry itself, under
# the name the CLI has always used, so one table cannot drift from the other.
VENDOR_MODULES = VENDORS

VENDOR_INSTALL = {
    "junos": "junos-eznc", "arista": "pyeapi", "ssh": "paramiko",
    "openssh": "the OpenSSH client ('ssh' on PATH)",
    "telnet": "(built-in)", "telnet-ios": "(built-in)",
    "telnet-junos": "(built-in)", "telnet-arista": "(built-in)",
    "telnet-nxos": "(built-in)",
}



_RESULT_HEADER_KEYS = ("DEVICE:", "HOST:", "MODE:", "VENDOR:")


def strip_result_header(out_text: str, command: str = None) -> str:
    """Return just what the device said.

    The runner prefixes each result with DEVICE/HOST/MODE/VENDOR and a blank
    line, and text transports echo the command as '$ cmd'. Both are framing for
    the human-readable view; --raw wants neither.
    """
    lines = out_text.splitlines()
    i = 0
    while i < len(lines) and lines[i].startswith(_RESULT_HEADER_KEYS):
        i += 1
    if i and i < len(lines) and not lines[i].strip():
        i += 1
    # Only drop the echo when it is exactly the command we sent, so device
    # output that happens to start with '$ ' survives intact.
    if command and i < len(lines) and lines[i] == "$ %s" % command:
        i += 1
    return "\n".join(lines[i:]).strip("\n")


def document_text(output) -> str:
    """One command's output as it is printed and diffed: a JSON reply (a dict,
    from --format json) pretty-printed, XML and text as they are."""
    if isinstance(output, str):
        return output
    return json.dumps(output, indent=2)



# A thread per in-flight device, so the ceiling is an operator's choice rather
# than a property of the machine. Capped because each one is an ssh process.
MAX_WORKERS = 256


def resolve_workers(requested: int) -> int:
    """Clamp --workers to something a thread pool can honour."""
    try:
        n = int(requested)
    except (TypeError, ValueError):
        return 8
    return max(1, min(n, MAX_WORKERS))



# Everything here may be set in ~/.h-ssh/config. The password may not: a config
# file on a shared host is the wrong home for a secret.
CONFIG_DEFAULTS = {
    "workers": 8,
    "session_timeout": 30,
    "command_timeout": 20,
    "retries": 2,
    "transport": "ssh",
}


def apply_config_defaults(args, config: dict) -> None:
    """Fill unset options from the config file, then from the built-in default.

    Precedence is flag, then environment (handled per option), then config file,
    then default. An option given on the command line is never overridden.
    """
    for key, fallback in CONFIG_DEFAULTS.items():
        if getattr(args, key, None) is not None:
            continue
        value = config.get(key, fallback)
        if isinstance(fallback, int):
            try:
                value = int(value)
            except (TypeError, ValueError):
                value = fallback
        setattr(args, key, value)


def format_edit_result(out_text: str) -> str:
    """The driver's verdict for one edit, indented under its status line.

    COMMIT OK, the diff, or the DRY-RUN verdict is what an edit run is for;
    a bare OK would hide the diff that --dry-run exists to show. This is the
    default view, so it drops the header and -v's frame and keeps two spaces
    of indent, the same as a FAIL line's ERROR.
    """
    body = strip_result_header(out_text)
    return "\n".join("  " + ln if ln.strip() else "" for ln in body.splitlines())


def build_confirm_command(user, target_specs, devices: str, transport: str) -> str:
    """The command that confirms this run's commit-confirmed.

    Rebuilt from the run's own arguments, so it reaches the same devices as
    the same user: the inline --target specs as typed, or else the inventory
    file. --transport is kept only when it names a transport that can
    confirm a commit.
    """
    cmd = ['./h-app/h-ssh.py -eC "commit"']
    if user:
        cmd.append("--user " + shlex.quote(user))
    if target_specs:
        cmd.extend("--target " + shlex.quote(spec) for spec in target_specs)
    else:
        cmd.append("--devices " + shlex.quote(devices))
    if transport in COMMIT_CONFIRMED_VENDORS:
        cmd.append("--transport " + transport)
    return " ".join(cmd)


def get_default_devices_path() -> str:
    """Get default devices CSV path, preferring ~/.h-ssh/devices.csv if it exists."""
    home_path = Path.home() / ".h-ssh" / "devices.csv"
    if home_path.exists():
        return str(home_path)
    return "devices.csv"


async def check_reachability(target, timeout: int = 2) -> tuple:
    """Quick reachability check for a target."""
    port = resolve_target_port(target)

    loop = asyncio.get_running_loop()
    try:
        await loop.getaddrinfo(target.host, None)
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return (target.name, True, "reachable")
        except asyncio.TimeoutError:
            return (target.name, False, "connection timeout")
        except ConnectionRefusedError:
            return (target.name, False, f"port {port} not responding")
        except OSError:
            return (target.name, False, f"port {port} not responding")
    except socket.gaierror:
        return (target.name, False, "hostname not found")
    except Exception as e:
        return (target.name, False, f"error: {e}")


async def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="Multi-vendor network automation tool.")

    parser.add_argument("--devices", default=get_default_devices_path(),
                        help="Devices CSV (default: ~/.h-ssh/devices.csv or ./devices.csv)")
    parser.add_argument("--transport", choices=["junos", "arista", "ssh", "openssh", "telnet"], default=None,
                        help="Transport for targets that don't declare one (default: ssh)")
    parser.add_argument("--structured", action="store_true",
                        help="Return structured data where the vendor supports it "
                             "(junos NETCONF, arista eAPI); falls back to text elsewhere")
    parser.add_argument("--user", type=str,
                        help="Username (or HSSH_USER env var, or 'user' in ~/.h-ssh/config)")
    parser.add_argument("--config", type=str,
                        help="Config file with defaults (default: ~/.h-ssh/config)")
    parser.add_argument("--password", type=str,
                        help="Password (or set HSSH_PASSWORD env var)")

    # Modes
    parser.add_argument("-sC", "--show-command", type=str,
                        help="Show command to run on all targets")
    parser.add_argument("-eC", "--edit-command", type=str,
                        help="Single config command (Junos expects 'set ...')")
    parser.add_argument("-eD", "--edit-dir", type=str,
                        help="Directory containing <NAME>.set files")
    parser.add_argument("-eB", "--edit-broadcast", type=str,
                        help="Multi-line config file for all devices (e.g., configs/all.set)")
    parser.add_argument("--batch", type=str,
                        help="File containing show commands to run in batch (one per line, # comments)")
    parser.add_argument("--job", type=str,
                        help="JSON job file with per-device commands (use - for stdin)")
    parser.add_argument("--rollback", type=int, metavar="N",
                        help="Return every target to rollback N (0-49), with the same gates as an edit (Junos only)")
    parser.add_argument("--commit-status", action="store_true",
                        help="Show the commit history as data: sequence, time, user, comment, pending commit-confirmed timer (Junos only)")
    parser.add_argument("--comment", type=str, metavar="TEXT",
                        help="Log this comment with the commit; it shows in 'show system commit' (Junos only)")
    parser.add_argument("--show-diff", action="store_true",
                        help="Edits: run a dry-run on every target, print the diffs, then ask once before committing")

    # Behavior
    parser.add_argument("--retries", type=int, default=None,
                        help="Retries per device after the first attempt (default: 2). "
                             "Permanent failures never retry.")
    parser.add_argument("--workers", type=int, default=None,
                        help="Parallel workers (default: 8)")
    parser.add_argument("--session-timeout", type=int, default=None,
                        help="Timeout for establishing connection/session (default: 30)")
    parser.add_argument("--command-timeout", type=int, default=None,
                        help="Timeout for individual commands/operations (default: 20)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Do not push, only show what would happen")
    parser.add_argument("--commit-confirmed", type=int, nargs="?", const=10, default=None,
                        help="Use commit confirmed with auto-rollback timer in minutes (default: 10, Junos only)")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip confirmation prompt for edit operations")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output for all operations")
    parser.add_argument("--diff", action="store_true",
                        help="Compare output across devices (show modes only, first device is baseline)")
    parser.add_argument("--raw", action="store_true",
                        help="Print only each device's output, no progress lines or headers")
    parser.add_argument("--list-commands", action="store_true",
                        help="List available command shortcuts for the selected transport")

    # Inline targets
    parser.add_argument("--target", type=str, action="append",
                        help="Inline target as name:host:vendor:port (repeatable, vendor defaults to junos)")

    # Output
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON array (suppresses human-readable output)")
    parser.add_argument("--format", choices=["text", "json", "xml"], default="text",
                        help="Show output as the router's own JSON or XML reply, through its RPC "
                             "translation of the command (junos only; default: text)")
    parser.add_argument("--save-output", type=str,
                        help="Create dir and save per-device output files inside it")
    parser.add_argument("--log", type=str,
                        help="Append per-device JSONL results to file")
    parser.add_argument("--audit-log", type=str,
                        default=os.environ.get("HSSH_AUDIT_LOG"),
                        help="Edit audit log path for JSONL audit trail (or set HSSH_AUDIT_LOG env var)")
    parser.add_argument("--safety-file", type=str,
                        default=os.environ.get("HSSH_SAFETY_FILE"),
                        help="Safety gate JSON file for per-device rate limiting and cooldown")

    args = parser.parse_args()

    # Resolved before anything reads them, so --list-commands and the banner
    # see the same values the run will use.
    file_config = load_config(args.config)
    apply_config_defaults(args, file_config)

    # Handle --list-commands
    if args.list_commands:
        commands = get_available_commands(args.transport)
        if commands:
            print(f"\nAvailable command shortcuts for '{args.transport}':")
            print(f"Usage: h-ssh -sC <shortcut>\n")
            for name, description in commands.items():
                resolved = resolve_command(name, args.transport)
                if description:
                    print(f"  {name:20s} -> {resolved}")
                    print(f"  {'':<20s}   {description}")
                else:
                    print(f"  {name:20s} -> {resolved}")
            print()
        else:
            print(f"\nNo command shortcuts found for '{args.transport}'.")
            print(f"Create shortcuts in: ~/.h-ssh/commands/{args.transport}.json")
            print(f"See h-app/commands/junos.json for format example.\n")
        return 0

    # Two different paths: a binding's few fields, or the router's whole reply.
    if args.structured and args.format != "text":
        print("ERROR: --structured and --format are mutually exclusive.", file=sys.stderr)
        return 2

    # ------ JOB MODE ------
    job_entries = None
    if args.job:
        if any([args.show_command, args.edit_command, args.edit_dir, args.edit_broadcast, args.batch, args.rollback is not None, args.commit_status]):
            print("ERROR: --job cannot be combined with -sC, -eC, -eD, -eB, --batch, --rollback, or --commit-status.", file=sys.stderr)
            return 2
        try:
            job_entries = load_jobs(args.job)
        except (ValueError, json.JSONDecodeError) as e:
            print(f"ERROR: Invalid job file: {e}", file=sys.stderr)
            return 2

        targets = [entry.target for entry in job_entries]
        has_edits = any(e.mode.startswith("edit") for e in job_entries)
        mode = "job"
        for je in job_entries:
            if je.target.vendor in ("junos", "telnet-junos") and je.mode.startswith("edit"):
                valid, err = validate_junos_set_syntax(je.command, allow_commit=True)
                if not valid:
                    print(f"ERROR: Junos job command for '{je.target.name}' only accepts set-style commands: {err}", file=sys.stderr)
                    return 2
    else:
        # Determine mode
        modes = [
            bool(args.show_command),
            bool(args.edit_command),
            bool(args.edit_dir),
            bool(args.edit_broadcast),
            bool(args.batch),
            args.rollback is not None,
            bool(args.commit_status),
        ]
        if sum(modes) != 1:
            print("ERROR: choose exactly one of -sC, -eC, -eD, -eB, --batch, --rollback, --commit-status, or --job.", file=sys.stderr)
            return 2
        if args.rollback is not None and not 0 <= args.rollback <= 49:
            print(f"ERROR: --rollback takes a number from 0 to 49, not {args.rollback}.", file=sys.stderr)
            return 2

        if args.edit_dir:
            if not Path(args.edit_dir).is_dir():
                print(f"ERROR: directory not found: {args.edit_dir}", file=sys.stderr)
                return 2

        if args.edit_broadcast:
            if not Path(args.edit_broadcast).is_file():
                print(f"ERROR: broadcast file not found: {args.edit_broadcast}", file=sys.stderr)
                return 2
        if args.batch:
            if not Path(args.batch).is_file():
                print(f"ERROR: batch file not found: {args.batch}", file=sys.stderr)
                return 2

        # Load targets
        if args.target:
            targets = []
            for spec in args.target:
                targets.append(parse_inline_target(spec))
        else:
            try:
                targets = load_devices_csv(args.devices)
            except Exception as e:
                print(f"ERROR loading devices: {e}", file=sys.stderr)
                return 2

        if not targets:
            print("ERROR: no devices found in inventory.", file=sys.stderr)
            return 2

        # Junos set-syntax check keys off the targets, not a global flag —
        # a mixed inventory can have some devices that care and some that don't.
        has_junos = any(t.vendor in ("junos", "telnet-junos") for t in targets)
        if has_junos:
            if args.edit_command:
                valid, err = validate_junos_set_syntax(args.edit_command, allow_commit=True)
                if not valid:
                    print(f"ERROR: Junos -eC only accepts 'set ...' commands: {err}", file=sys.stderr)
                    return 2
            elif args.edit_broadcast:
                try:
                    b_content = Path(args.edit_broadcast).read_text(encoding="utf-8")
                except Exception as e:
                    print(f"ERROR reading broadcast file '{args.edit_broadcast}': {e}", file=sys.stderr)
                    return 2
                valid, err = validate_junos_set_syntax(b_content, allow_commit=False)
                if not valid:
                    print(f"ERROR: Junos broadcast file '{args.edit_broadcast}' only accepts 'set ...' commands: {err}", file=sys.stderr)
                    return 2
            elif args.edit_dir:
                for t in targets:
                    if t.vendor in ("junos", "telnet-junos"):
                        set_file = Path(args.edit_dir) / f"{t.name}.set"
                        if set_file.is_file():
                            try:
                                d_content = set_file.read_text(encoding="utf-8")
                            except Exception as e:
                                print(f"ERROR reading config file '{set_file}': {e}", file=sys.stderr)
                                return 2
                            valid, err = validate_junos_set_syntax(d_content, allow_commit=False)
                            if not valid:
                                print(f"ERROR: Junos config file '{set_file}' only accepts 'set ...' commands: {err}", file=sys.stderr)
                                return 2

        # Mode label
        if args.show_command:
            mode = "show"
        elif args.edit_command:
            mode = "edit-cmd"
        elif args.edit_broadcast:
            mode = "edit-broadcast"
        elif args.batch:
            mode = "show-batch"
        elif args.rollback is not None:
            mode = "rollback"
        elif args.commit_status:
            mode = "commit-status"
        else:
            mode = "edit-dir"

        has_edits = mode.startswith("edit") or mode == "rollback"

    if args.comment is not None and not has_edits:
        print("ERROR: --comment goes with an edit (-eC, -eD, -eB, --rollback, or a job with edits).", file=sys.stderr)
        return 2
    if args.show_diff and (not has_edits or args.dry_run):
        print("ERROR: --show-diff goes with an edit that is not already a --dry-run.", file=sys.stderr)
        return 2

    # Validate vendor libraries for all targets
    for v in set(t.vendor for t in targets):
        mod = VENDOR_MODULES.get(v)
        if mod is None:
            print(f"ERROR: Unknown vendor '{v}'.", file=sys.stderr)
            return 2
        if not mod.AVAILABLE:
            install = VENDOR_INSTALL.get(v, v)
            print(f"ERROR: {install} not installed (required for vendor '{v}').", file=sys.stderr)
            return 2

    save_dir = None
    if args.save_output:
        save_dir = args.save_output
        Path(save_dir).mkdir(parents=True, exist_ok=True)

    # Credentials. Flag beats environment beats config file; the password is
    # never read from the config file, so a shell alias cannot leak it to disk.
    config = file_config
    user = args.user or os.environ.get("HSSH_USER") or config.get("user")
    passwd = args.password or os.environ.get("HSSH_PASSWORD")
    if args.raw and args.verbose:
        print("ERROR: --raw and -v are mutually exclusive.", file=sys.stderr)
        return 2
    if args.raw and args.json:
        print("ERROR: --raw and --json are mutually exclusive.", file=sys.stderr)
        return 2

    json_mode = args.json
    raw_mode = args.raw
    # Progress chatter only. Edit pre-flight and confirmation stay visible.
    show_progress = not (json_mode or raw_mode)

    if not user:
        if not sys.stdin.isatty():
            print("ERROR: No username provided and stdin is not a TTY. "
                  "Use --user, HSSH_USER, or set 'user' in %s." % get_config_path(),
                  file=sys.stderr)
            return 2
        default_user = getpass.getuser()
        user = input(f"Username [{default_user}]: ").strip() or default_user

    if not passwd:
        needs_password = any(t.vendor in ("arista",) for t in targets)
        if needs_password:
            if not sys.stdin.isatty():
                print("ERROR: Arista requires a password but stdin is not a TTY.", file=sys.stderr)
                return 2
            passwd = getpass.getpass("Password: ")
        elif sys.stdin.isatty():
            passwd = getpass.getpass("Password (press Enter to skip): ")
            if not passwd:
                passwd = None
        else:
            passwd = None

    # Command shortcuts are kept unresolved here and resolved per target, since
    # each target carries its own vendor and the template library is per vendor.
    # Resolving once against --transport sends one vendor's command to all of
    # them, which is wrong the moment an inventory is mixed.
    show_cmd = None
    edit_cmd = None
    batch_cmds = None
    if not job_entries:
        show_cmd = args.show_command
        edit_cmd = args.edit_command
        if args.batch:
            batch_cmds = read_command_file_lines(Path(args.batch))
            if not batch_cmds:
                print("ERROR: batch file is empty after filtering.", file=sys.stderr)
                return 2

        if not json_mode:
            # Report resolution once per vendor actually present, not per device.
            for vendor in sorted({t.vendor for t in targets}):
                for raw in [c for c in ([show_cmd, edit_cmd] + (batch_cmds or [])) if c]:
                    resolved = resolve_command(raw, vendor)
                    if resolved != raw:
                        print(f"Resolved '{raw}' -> '{resolved}' ({vendor})")

    if show_progress:
        if job_entries:
            print(f"\nMode: job | Targets: {len(targets)} | Workers: {args.workers}")
        else:
            print(f"\nTransport: {args.transport} | Mode: {mode} | Workers: {args.workers}")
            if args.target:
                print(f"Targets: {len(targets)} (inline)")
            else:
                print(f"Inventory: {args.devices}")
        if save_dir:
            print(f"Save output dir: {save_dir}")
        if batch_cmds:
            print(f"Batch: {len(batch_cmds)} commands from {args.batch}")
        print(f"Targets: {len(targets)}")

    target_map = {t.name: t for t in targets}

    # Pre-flight check and confirmation for edit operations
    if has_edits and not args.dry_run:
        if not json_mode:
            print("\nPre-flight check: Validating device reachability...")

        reachability_results = await asyncio.gather(
            *[check_reachability(t, timeout=5) for t in targets]
        )

        unreachable = []
        for name, reachable, msg in reachability_results:
            if not json_mode:
                status = "[PASS]" if reachable else "[FAIL]"
                host_display = target_map[name].host
                print(f"  {status} {name:16s} ({host_display}) - {msg}")
            if not reachable:
                unreachable.append(name)

        if unreachable:
            if args.audit_log:
                for unreach_name in unreachable:
                    ut = target_map.get(unreach_name)
                    if ut:
                        write_audit_entry(
                            path=args.audit_log,
                            device=ut.name,
                            host=ut.host,
                            vendor=ut.vendor,
                            mode=mode if 'mode' in locals() else "preflight",
                            payload="",
                            ok=False,
                            error="preflight reachability check failed (aborted)",
                        )
            if json_mode:
                err = {"error": f"{len(unreachable)} device(s) unreachable", "unreachable": unreachable}
                print(json.dumps(err))
            else:
                print(f"\nERROR: {len(unreachable)} device(s) unreachable: {', '.join(unreachable)}")
                print("Aborting to prevent partial deployment.")
            return 2

        if not json_mode:
            print(f"\nReady to execute on {len(targets)} device(s).")

        if args.show_diff:
            pass  # the diffs are shown first, the question comes after them
        elif not args.yes:
            if not sys.stdin.isatty():
                print("ERROR: Edit operation requires confirmation but stdin is not a TTY. Use -y to skip.", file=sys.stderr)
                return 2
            try:
                confirm = input("\nProceed with changes? [y/N]: ").strip().lower()
                if confirm not in ['y', 'yes']:
                    if args.audit_log:
                        for target in targets:
                            write_audit_entry(
                                path=args.audit_log,
                                device=target.name,
                                host=target.host,
                                vendor=target.vendor,
                                mode=mode,
                                payload="",
                                ok=False,
                                error="aborted by user confirmation",
                            )
                    print("Aborted by user.")
                    return 0
            except (KeyboardInterrupt, EOFError):
                if args.audit_log:
                    for target in targets:
                        write_audit_entry(
                            path=args.audit_log,
                            device=target.name,
                            host=target.host,
                            vendor=target.vendor,
                            mode=mode,
                            payload="",
                            ok=False,
                            error="aborted by user interrupt",
                        )
                print("\nAborted by user.")
                return 0
        elif not json_mode:
            print("(--yes flag provided, skipping confirmation)")

    if show_progress:
        print()

    failures = 0
    skipped = 0
    json_results = []
    run_start = time.time()

    safety_file = args.safety_file or os.environ.get("HSSH_SAFETY_FILE")
    safety_gate = SafetyGate(safety_file=safety_file) if safety_file else None

    # asyncio.to_thread runs on the loop's default executor, which sizes itself
    # min(32, cpu+4) — 6 threads on a 2-vCPU jump host. Without this, --workers
    # silently caps at that number and the semaphore below is the smaller lie:
    # devices queue behind threads, and blocked ones (a 30s connect timeout)
    # hold a thread the whole time, stalling everything behind them.
    workers = resolve_workers(args.workers)
    loop = asyncio.get_running_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="hssh"))

    sem = asyncio.Semaphore(workers)

    async def _bounded_run(t, mode_override=None, cmd_override=None, dry_run=None):
        async with sem:
            dry_run = args.dry_run if dry_run is None else dry_run
            # For job mode: each target has its own mode and command
            actual_mode = mode_override or mode
            actual_show_cmd = show_cmd
            actual_edit_cmd = edit_cmd
            if cmd_override is not None:
                if actual_mode == "show":
                    actual_show_cmd = cmd_override
                elif actual_mode.startswith("edit"):
                    actual_edit_cmd = cmd_override

            # Resolve shortcuts against this target's own vendor. Job-mode
            # entries go through here too, which they previously skipped.
            binding = None
            if actual_show_cmd:
                if args.structured:
                    binding = resolve_structured(actual_show_cmd, t.vendor)
                actual_show_cmd = resolve_command(actual_show_cmd, t.vendor)
            if actual_edit_cmd:
                actual_edit_cmd = resolve_command(actual_edit_cmd, t.vendor)
            target_batch_cmds = (
                [resolve_command(c, t.vendor) for c in batch_cmds]
                if batch_cmds else None
            )

            return await run_for_target_async(
                t=t,
                transport=t.vendor,
                mode=actual_mode,
                show_cmd=actual_show_cmd,
                edit_cmd=actual_edit_cmd,
                config_dir=args.edit_dir if not job_entries else None,
                broadcast_file=args.edit_broadcast if not job_entries else None,
                user=user,
                passwd=passwd,
                session_timeout=args.session_timeout,
                command_timeout=args.command_timeout,
                dry_run=dry_run,
                commit_confirmed=args.commit_confirmed,
                save_dir=save_dir,
                quiet=not show_progress,
                max_attempts=max(1, args.retries + 1),
                batch_cmds=target_batch_cmds,
                safety_gate=safety_gate,
                structured=args.structured,
                rollback=args.rollback,
                comment=args.comment,
                structured_binding=binding,
                fmt=args.format,
            )

    # --show-diff: every target's diff first, one question, then the real run.
    if args.show_diff and has_edits and not args.dry_run:
        previews = [asyncio.create_task(_bounded_run(e.target, e.mode, e.command, dry_run=True)) for e in job_entries] \
            if job_entries else [asyncio.create_task(_bounded_run(t, dry_run=True)) for t in targets]
        preview_failed = []
        for coro in asyncio.as_completed(previews):
            name, ok, out_text, _ = await coro
            print(f"\n--- {name}: {'diff' if ok else 'FAILED'} ---")
            print(out_text.rstrip())
            if not ok:
                preview_failed.append(name)
        if preview_failed:
            print(f"\nERROR: dry-run failed on {', '.join(preview_failed)}; nothing committed.", file=sys.stderr)
            return 1
        if not args.yes:
            if not sys.stdin.isatty():
                print("ERROR: --show-diff needs a terminal to ask, or -y.", file=sys.stderr)
                return 2
            try:
                answer = input("\nCommit these changes on all devices? [y/N]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                answer = ""
            if answer not in ("y", "yes"):
                print("Aborted by user.")
                return 0

    # Create tasks - either job mode or normal mode
    if job_entries:
        tasks = [
            asyncio.create_task(_bounded_run(entry.target, entry.mode, entry.command))
            for entry in job_entries
        ]
    else:
        tasks = [asyncio.create_task(_bounded_run(t)) for t in targets]

    interrupted = False
    for coro in asyncio.as_completed(tasks):
        try:
            name, ok, out_text, duration_ms = await coro
        except (asyncio.CancelledError, KeyboardInterrupt):
            # Ctrl-C: stop starting work, let what is in flight go, and report
            # the devices that did finish rather than losing the whole run.
            interrupted = True
            for task in tasks:
                task.cancel()
            break

        t = target_map[name]
        # A job entry runs in its own mode; everything else in the run's.
        dev_mode = mode
        if job_entries:
            dev_mode = next((je.mode for je in job_entries if je.target.name == name), mode)
        entry = {
            "device": name,
            "host": t.host,
            "vendor": t.vendor,
            "ok": ok,
            "duration_ms": duration_ms,
        }

        if mode == "commit-status":
            try:   # the runner's device header comes first; the data is the last line
                entry["commits"] = json.loads(out_text.strip().splitlines()[-1]) if ok else []
            except (json.JSONDecodeError, ValueError, TypeError, IndexError):
                entry["commits"] = []
            if ok and not json_mode:
                print(f"\n{name}:")
                for c in entry["commits"]:
                    pending = f"  [commit confirmed, rollback in {c['pending_rollback_minutes']} min]" if c.get("pending_rollback_minutes") is not None else ""
                    note = f"  {c['comment']}" if c.get("comment") else ""
                    print(f"  {c['seq']:>2}  {c['time']}  by {c['user']} via {c['client']}{pending}{note}")
            if not ok:
                for ln in reversed(out_text.splitlines()):
                    if ln.startswith("ERROR:"):
                        entry["error"] = ln[len("ERROR:"):].strip()
                        break
                else:
                    entry["error"] = out_text.strip() or "unknown error"
        elif mode == "show-batch":
            cmd_results = None
            try:
                cmd_results = json.loads(out_text)
            except (json.JSONDecodeError, ValueError, TypeError):
                cmd_results = None

            if isinstance(cmd_results, list):
                for cr in cmd_results:
                    # Only text carries the echo; a --format json reply is data.
                    if cr.get("ok") and isinstance(cr.get("output"), str):
                        cr["output"] = strip_result_header(cr["output"], cr["command"])
                entry["commands"] = cmd_results
                if not ok:
                    for cr in cmd_results:
                        if not cr.get("ok"):
                            entry["error"] = cr.get("error", "unknown error")
                            break
                    else:
                        entry["error"] = "unknown error"
            else:
                entry["commands"] = []
                for ln in reversed(out_text.splitlines()):
                    if ln.startswith("ERROR:"):
                        entry["error"] = ln[len("ERROR:"):].strip()
                        break
                else:
                    entry["error"] = out_text.strip() or "unknown error"
        elif ok:
            # Resolved per target, so a shortcut can differ device to device.
            resolved_cmd = resolve_command(show_cmd, t.vendor) if show_cmd else None
            if resolved_cmd:
                entry["command"] = resolved_cmd
            entry["output"] = strip_result_header(out_text, resolved_cmd)
            if args.format == "json" and dev_mode == "show" and not args.dry_run:
                # The runner printed the router's reply; --json carries it as data.
                try:
                    entry["output"] = json.loads(entry["output"])
                except (json.JSONDecodeError, ValueError, TypeError):
                    pass  # a driver that handed back something else: keep it as text
        else:
            for ln in reversed(out_text.splitlines()):
                if ln.startswith("ERROR:"):
                    entry["error"] = ln[len("ERROR:"):].strip()
                    break
            else:
                entry["error"] = "unknown error"
        json_results.append(entry)

        # Audit logging for operations
        if args.audit_log:
            audit_payload = ""
            if mode == "edit-cmd":
                audit_payload = resolve_command(edit_cmd, t.vendor) if edit_cmd else ""
            elif mode == "edit-dir":
                set_file = Path(args.edit_dir) / f"{name}.set"
                if set_file.is_file():
                    try:
                        audit_payload = set_file.read_text(encoding="utf-8")
                    except Exception:
                        audit_payload = f"<failed to read {set_file}>"
            elif mode == "edit-broadcast":
                if args.edit_broadcast and Path(args.edit_broadcast).is_file():
                    try:
                        audit_payload = Path(args.edit_broadcast).read_text(encoding="utf-8")
                    except Exception:
                        audit_payload = f"<failed to read {args.edit_broadcast}>"
            elif mode == "rollback":
                audit_payload = f"rollback {args.rollback}"
            elif mode == "commit-status":
                audit_payload = "show system commit"
            elif mode == "job":
                if job_entries:
                    for je in job_entries:
                        if je.target.name == name:
                            audit_payload = resolve_command(je.command, t.vendor) if je.command else ""
                            break
            elif mode == "show":
                audit_payload = resolve_command(show_cmd, t.vendor) if show_cmd else ""
            elif mode == "show-batch":
                audit_payload = (
                    json.dumps([resolve_command(c, t.vendor) for c in batch_cmds])
                    if batch_cmds else ""
                )

            is_show_op = dev_mode in ("show", "show-batch", "commit-status")
            audit_diff = entry.get("output", "") if (ok and not is_show_op) else None

            audit_ok = write_audit_entry(
                path=args.audit_log,
                device=name,
                host=t.host,
                vendor=t.vendor,
                mode=dev_mode,
                payload=audit_payload,
                ok=ok,
                diff=audit_diff,
                error=entry.get("error"),
                dry_run=args.dry_run,
                commit_confirmed=args.commit_confirmed,
                comment=args.comment,
            )
            if not audit_ok and (has_edits or not is_show_op):
                print(f"ERROR: Failed to write audit entry for {name}", file=sys.stderr)
                failures += 1

        if raw_mode:
            if mode == "show-batch":
                cmd_results = None
                try:
                    cmd_results = json.loads(out_text)
                except (json.JSONDecodeError, ValueError, TypeError):
                    cmd_results = None

                if isinstance(cmd_results, list):
                    print(f"{name}:")
                    for cr in cmd_results:
                        if cr.get("ok"):
                            print(strip_result_header(document_text(cr["output"]), cr["command"]))
                        else:
                            print(f"{name}: {cr.get('command')}: {cr.get('error')}", file=sys.stderr)
                    print()
                else:
                    detail = next((ln for ln in out_text.splitlines()
                                   if ln.startswith("ERROR:")), "failed")
                    print(f"{name}: {detail}", file=sys.stderr)
            elif ok:
                resolved_cmd = resolve_command(show_cmd, t.vendor) if show_cmd else None
                print(f"{name}:")
                print(strip_result_header(out_text, resolved_cmd))
                print()
            else:
                # stdout stays device output only, so failures go to stderr.
                detail = next((ln for ln in out_text.splitlines()
                               if ln.startswith("ERROR:")), "failed")
                print(f"{name}: {detail}", file=sys.stderr)

        if not json_mode and not raw_mode:
            timestamp = datetime.now().strftime("%H:%M:%S")
            if mode == "show-batch":
                cmd_results = None
                try:
                    cmd_results = json.loads(out_text)
                except (json.JSONDecodeError, ValueError, TypeError):
                    cmd_results = None

                if isinstance(cmd_results, list):
                    ok_count = sum(1 for r in cmd_results if r.get("ok"))
                    total = len(cmd_results)
                    if ok:
                        status = f"OK ({ok_count}/{total} commands)"
                    elif ok_count > 0:
                        status = f"PARTIAL ({ok_count}/{total} commands)"
                    else:
                        status = "FAIL"
                    print(f"[{timestamp}] {name:16s} {status}")
                    if args.verbose:
                        for cr in cmd_results:
                            print(f"\n--- {name}: {cr.get('command')} ---")
                            if cr.get("ok"):
                                print(document_text(cr.get("output", "")))
                            else:
                                print(f"  ERROR: {cr.get('error')}")
                            print(f"--- end ---")
                    elif not ok:
                        for cr in cmd_results:
                            if not cr.get("ok"):
                                print(f"  ERROR: {cr.get('command')}: {cr.get('error')}")
                else:
                    status = "FAIL"
                    print(f"[{timestamp}] {name:16s} {status}")
                    if args.verbose:
                        print(f"\n--- Output from {name} ---")
                        print(out_text)
                        print(f"--- End of {name} ---\n")
                    elif not ok:
                        for ln in reversed(out_text.splitlines()):
                            if ln.startswith("ERROR:"):
                                print(f"  {ln}")
                                break
            else:
                status = "OK" if ok else "FAIL"
                print(f"[{timestamp}] {name:16s} {status}")

                if args.verbose:
                    print(f"\n--- Output from {name} ---")
                    print(out_text)
                    print(f"--- End of {name} ---\n")
                elif ok and (dev_mode.startswith("edit") or dev_mode == "rollback"):
                    print(format_edit_result(out_text))
                elif not ok:
                    for ln in reversed(out_text.splitlines()):
                        if ln.startswith("ERROR:"):
                            print(f"  {ln}")
                            break

        if not ok:
            if entry.get("error", "").startswith("safety gate blocked"):
                skipped += 1
            else:
                failures += 1

    # Write structured JSONL log
    if args.log:
        try:
            log_path = Path(args.log)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            cmd = batch_cmds or show_cmd or edit_cmd or args.edit_broadcast or (args.edit_dir and f"dir:{args.edit_dir}") or "job"
            ts = datetime.now().isoformat()
            with open(log_path, "a") as f:
                for entry in json_results:
                    log_entry = {
                        "timestamp": ts,
                        "user": user,
                        "mode": mode,
                        "command": cmd,
                        "dry_run": args.dry_run,
                        **entry,
                    }
                    f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"WARNING: Could not write to log file: {e}", file=sys.stderr)

    # Cross-device diff (show modes only)
    if args.diff and mode in ["show", "show-batch"]:
        ok_results = [r for r in json_results if r["ok"]]
        if len(ok_results) >= 2:
            baseline = ok_results[0]
            baseline_name = baseline["device"]

            if mode == "show":
                baseline_lines = document_text(baseline["output"]).splitlines(keepends=True)
                for other in ok_results[1:]:
                    other_lines = document_text(other["output"]).splitlines(keepends=True)
                    diff_lines = list(difflib.unified_diff(
                        baseline_lines, other_lines,
                        fromfile=baseline_name, tofile=other["device"],
                    ))
                    diff_text = "".join(diff_lines).rstrip()
                    other["diff"] = diff_text if diff_text else "(identical)"
                baseline["diff"] = "(baseline)"

            elif mode == "show-batch":
                baseline_map = {c["command"]: document_text(c["output"]) for c in baseline["commands"] if c["ok"]}
                for other in ok_results[1:]:
                    cmd_diffs = []
                    for cr in other["commands"]:
                        if not cr["ok"]:
                            continue
                        bl = baseline_map.get(cr["command"], "")
                        diff_lines = list(difflib.unified_diff(
                            bl.splitlines(keepends=True),
                            document_text(cr["output"]).splitlines(keepends=True),
                            fromfile=baseline_name, tofile=other["device"],
                        ))
                        diff_text = "".join(diff_lines).rstrip()
                        cmd_diffs.append({
                            "command": cr["command"],
                            "diff": diff_text if diff_text else "(identical)",
                        })
                    other["diff"] = cmd_diffs
                baseline["diff"] = "(baseline)"

    if json_mode:
        print(json.dumps(json_results, indent=2))
    else:
        # Print diff output
        if args.diff and mode in ["show", "show-batch"]:
            ok_results = [r for r in json_results if r["ok"]]
            if len(ok_results) >= 2:
                baseline_name = ok_results[0]["device"]
                print(f"\n--- Diff (baseline: {baseline_name}) ---\n")
                for other in ok_results[1:]:
                    if mode == "show":
                        diff_text = other.get("diff", "")
                        print(f"  {baseline_name} vs {other['device']}:")
                        if diff_text == "(identical)":
                            print(f"    (identical)\n")
                        else:
                            for ln in diff_text.splitlines():
                                print(f"    {ln}")
                            print()
                    elif mode == "show-batch":
                        print(f"  {baseline_name} vs {other['device']}:")
                        for cd in other.get("diff", []):
                            print(f"    [{cd['command']}]")
                            if cd["diff"] == "(identical)":
                                print(f"      (identical)")
                            else:
                                for ln in cd["diff"].splitlines():
                                    print(f"      {ln}")
                        print()
                print("--- End diff ---")

        if interrupted:
            # Always reported, and always on stderr, so --raw stdout stays
            # device output and a truncated run can never look complete.
            print(f"Interrupted. Completed {len(json_results)} of {len(targets)} device(s).",
                  file=sys.stderr)

        if not raw_mode:
            print("")
            if failures:
                print(f"Done. Failures: {failures}")
            elif not interrupted:
                print("Done. All devices OK.")
        elif failures:
            # stdout is device output only; the verdict belongs on stderr.
            print(f"Done. Failures: {failures}", file=sys.stderr)

        if args.commit_confirmed and not args.dry_run and mode in ["edit-cmd", "edit-dir", "edit-broadcast", "rollback"]:
            print("")
            print("=" * 70)
            print(" " * 15 + "DON'T FORGET TO CONFIRM THE COMMIT!")
            print("=" * 70)
            print(f"Run this command to confirm within {args.commit_confirmed} minutes:")
            print("  " + build_confirm_command(user, args.target, args.devices, args.transport))
            print("\nOr the changes will automatically rollback!")
            print("=" * 70)
            print("")

    # Structured stderr summary
    elapsed_ms = int((time.time() - run_start) * 1000)
    ok_count = len(json_results) - failures - skipped
    stderr_mode = "batch" if mode == "show-batch" else ("job" if mode == "job" else mode.split("-")[0])
    summary = json.dumps({
        "targets": len(json_results),
        "ok": ok_count,
        "fail": failures,
        "skipped": skipped,
        "elapsed_ms": elapsed_ms,
        "mode": stderr_mode,
    })
    print(f"[h-ssh] {summary}", file=sys.stderr)

    if safety_gate is not None:
        safety_gate.close()

    if interrupted:
        return 130  # 128 + SIGINT, the shell convention
    return 1 if failures else 0


def main_sync() -> None:
    """Synchronous entry point for console_scripts."""
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
