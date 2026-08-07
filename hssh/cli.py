"""Command-line interface for h-ssh."""

import argparse
import asyncio
import difflib
import getpass
import json
import os
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

from .core import (
    Target, load_devices_csv, resolve_command, resolve_structured,
    get_available_commands, read_command_file_lines, parse_inline_target,
    load_jobs,
)
from .runner import run_for_target_async
from .safety import SafetyGate
from .audit import write_audit_entry
from .vendors import junos, arista, generic, telnet


# Supported vendor names for validation
VENDOR_MODULES = {
    "junos": junos, "arista": arista, "ssh": generic,
    "telnet": telnet, "telnet-ios": telnet, "telnet-junos": telnet,
    "telnet-arista": telnet, "telnet-nxos": telnet,
}

VENDOR_INSTALL = {
    "junos": "junos-eznc", "arista": "pyeapi", "ssh": "paramiko",
    "telnet": "(built-in)", "telnet-ios": "(built-in)",
    "telnet-junos": "(built-in)", "telnet-arista": "(built-in)",
    "telnet-nxos": "(built-in)",
}


def get_default_devices_path() -> str:
    """Get default devices CSV path, preferring ~/.h-ssh/devices.csv if it exists."""
    home_path = Path.home() / ".h-ssh" / "devices.csv"
    if home_path.exists():
        return str(home_path)
    return "devices.csv"


async def check_reachability(target, timeout: int = 2) -> tuple:
    """Quick reachability check for a target."""
    if target.port is not None:
        port = target.port
    elif target.vendor.startswith("telnet"):
        port = 23
    else:
        port = 22

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
    parser.add_argument("--transport", choices=["junos", "arista", "ssh", "telnet"], default="ssh",
                        help="Transport for targets that don't declare one (default: ssh)")
    parser.add_argument("--structured", action="store_true",
                        help="Return structured data where the vendor supports it "
                             "(junos NETCONF, arista eAPI); falls back to text elsewhere")
    parser.add_argument("--user", type=str,
                        help="Username (or set HSSH_USER env var)")
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

    # Behavior
    parser.add_argument("--workers", type=int, default=8,
                        help="Parallel workers (default: 8)")
    parser.add_argument("--session-timeout", type=int, default=30,
                        help="Timeout for establishing connection/session (default: 30)")
    parser.add_argument("--command-timeout", type=int, default=20,
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
    parser.add_argument("--list-commands", action="store_true",
                        help="List available command shortcuts for the selected transport")

    # Inline targets
    parser.add_argument("--target", type=str, action="append",
                        help="Inline target as name:host:vendor:port (repeatable, vendor defaults to junos)")

    # Output
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON array (suppresses human-readable output)")
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
            print(f"See commands/junos.json for format example.\n")
        return 0

    # ------ JOB MODE ------
    job_entries = None
    if args.job:
        if any([args.show_command, args.edit_command, args.edit_dir, args.edit_broadcast, args.batch]):
            print("ERROR: --job cannot be combined with -sC, -eC, -eD, -eB, or --batch.", file=sys.stderr)
            return 2
        try:
            job_entries = load_jobs(args.job)
        except (ValueError, json.JSONDecodeError) as e:
            print(f"ERROR: Invalid job file: {e}", file=sys.stderr)
            return 2

        targets = [entry.target for entry in job_entries]
        has_edits = any(e.mode.startswith("edit") for e in job_entries)
        mode = "job"
    else:
        # Determine mode
        modes = [
            bool(args.show_command),
            bool(args.edit_command),
            bool(args.edit_dir),
            bool(args.edit_broadcast),
            bool(args.batch),
        ]
        if sum(modes) != 1:
            print("ERROR: choose exactly one of -sC, -eC, -eD, -eB, --batch, or --job.", file=sys.stderr)
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
        if args.edit_command and any(t.vendor == "junos" for t in targets):
            if not args.edit_command.strip().startswith(("set ", "delete ", "commit")):
                print("ERROR: Junos -eC only accepts 'set ...' commands.", file=sys.stderr)
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
        else:
            mode = "edit-dir"

        has_edits = mode.startswith("edit")

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

    # Credentials
    user = args.user or os.environ.get("HSSH_USER")
    passwd = args.password or os.environ.get("HSSH_PASSWORD")
    json_mode = args.json

    if not user:
        if not sys.stdin.isatty():
            print("ERROR: No username provided and stdin is not a TTY. Use --user or HSSH_USER env var.", file=sys.stderr)
            return 2
        user = input("Username: ").strip()

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

    if not json_mode:
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
            if json_mode:
                err = {"error": f"{len(unreachable)} device(s) unreachable", "unreachable": unreachable}
                print(json.dumps(err))
            else:
                print(f"\nERROR: {len(unreachable)} device(s) unreachable: {', '.join(unreachable)}")
                print("Aborting to prevent partial deployment.")
            return 2

        if not json_mode:
            print(f"\nReady to execute on {len(targets)} device(s).")

        if not args.yes:
            if not sys.stdin.isatty():
                print("ERROR: Edit operation requires confirmation but stdin is not a TTY. Use -y to skip.", file=sys.stderr)
                return 2
            try:
                confirm = input("\nProceed with changes? [y/N]: ").strip().lower()
                if confirm not in ['y', 'yes']:
                    print("Aborted by user.")
                    return 0
            except (KeyboardInterrupt, EOFError):
                print("\nAborted by user.")
                return 0
        elif not json_mode:
            print("(--yes flag provided, skipping confirmation)")

    if not json_mode:
        print()

    failures = 0
    skipped = 0
    json_results = []
    run_start = time.time()

    safety_gate = None
    if args.safety_file:
        safety_gate = SafetyGate(safety_file=args.safety_file)

    sem = asyncio.Semaphore(args.workers)

    async def _bounded_run(t, mode_override=None, cmd_override=None):
        async with sem:
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
                dry_run=args.dry_run,
                commit_confirmed=args.commit_confirmed,
                save_dir=save_dir,
                quiet=json_mode,
                batch_cmds=target_batch_cmds,
                safety_gate=safety_gate,
                structured=args.structured,
                structured_binding=binding,
            )

    # Create tasks - either job mode or normal mode
    if job_entries:
        tasks = [
            asyncio.create_task(_bounded_run(entry.target, entry.mode, entry.command))
            for entry in job_entries
        ]
    else:
        tasks = [asyncio.create_task(_bounded_run(t)) for t in targets]

    for coro in asyncio.as_completed(tasks):
        name, ok, out_text, duration_ms = await coro

        t = target_map[name]
        entry = {
            "device": name,
            "host": t.host,
            "vendor": t.vendor,
            "ok": ok,
            "duration_ms": duration_ms,
        }

        if mode == "show-batch":
            cmd_results = json.loads(out_text)
            entry["commands"] = cmd_results
            if not ok:
                for cr in cmd_results:
                    if not cr["ok"]:
                        entry["error"] = cr["error"]
                        break
                else:
                    entry["error"] = "unknown error"
        elif ok:
            lines = out_text.strip().splitlines()
            content_lines = []
            past_header = False
            for ln in lines:
                if past_header:
                    content_lines.append(ln)
                elif ln.strip() == "":
                    past_header = True
            entry["output"] = "\n".join(content_lines).strip()
        else:
            for ln in reversed(out_text.splitlines()):
                if ln.startswith("ERROR:"):
                    entry["error"] = ln[len("ERROR:"):].strip()
                    break
            else:
                entry["error"] = "unknown error"
        json_results.append(entry)

        # Audit logging for edit operations
        if args.audit_log and mode != "show" and mode != "show-batch":
            job_cmd = ""
            if job_entries:
                for je in job_entries:
                    if je.target.name == name:
                        job_cmd = je.command
                        break
            write_audit_entry(
                path=args.audit_log,
                device=name, host=t.host, vendor=t.vendor,
                mode=entry.get("_mode", mode),
                payload=job_cmd or edit_cmd or args.edit_broadcast or "",
                ok=ok,
                diff=entry.get("output", ""),
                error=entry.get("error"),
                dry_run=args.dry_run,
                commit_confirmed=args.commit_confirmed,
            )

        if not json_mode:
            timestamp = datetime.now().strftime("%H:%M:%S")
            if mode == "show-batch":
                cmd_results = json.loads(out_text)
                ok_count = sum(1 for r in cmd_results if r["ok"])
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
                        print(f"\n--- {name}: {cr['command']} ---")
                        if cr["ok"]:
                            print(cr["output"])
                        else:
                            print(f"  ERROR: {cr['error']}")
                        print(f"--- end ---")
                elif not ok:
                    for cr in cmd_results:
                        if not cr["ok"]:
                            print(f"  ERROR: {cr['command']}: {cr['error']}")
            else:
                status = "OK" if ok else "FAIL"
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
                baseline_lines = baseline["output"].splitlines(keepends=True)
                for other in ok_results[1:]:
                    other_lines = other["output"].splitlines(keepends=True)
                    diff_lines = list(difflib.unified_diff(
                        baseline_lines, other_lines,
                        fromfile=baseline_name, tofile=other["device"],
                    ))
                    diff_text = "".join(diff_lines).rstrip()
                    other["diff"] = diff_text if diff_text else "(identical)"
                baseline["diff"] = "(baseline)"

            elif mode == "show-batch":
                baseline_map = {c["command"]: c["output"] for c in baseline["commands"] if c["ok"]}
                for other in ok_results[1:]:
                    cmd_diffs = []
                    for cr in other["commands"]:
                        if not cr["ok"]:
                            continue
                        bl = baseline_map.get(cr["command"], "")
                        diff_lines = list(difflib.unified_diff(
                            bl.splitlines(keepends=True),
                            cr["output"].splitlines(keepends=True),
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

        print("")
        if failures:
            print(f"Done. Failures: {failures}")
        else:
            print("Done. All devices OK.")

        if args.commit_confirmed and not args.dry_run and mode in ["edit-cmd", "edit-dir", "edit-broadcast"]:
            print("")
            print("=" * 70)
            print(" " * 15 + "DON'T FORGET TO CONFIRM THE COMMIT!")
            print("=" * 70)
            print(f"Run this command to confirm within {args.commit_confirmed} minutes:")
            confirm_cmd = "  ./h-ssh.py -eC \"commit\""
            if args.user:
                confirm_cmd += f" --user {args.user}"
            if args.devices != get_default_devices_path():
                confirm_cmd += f" --devices {args.devices}"
            if args.transport != "junos":
                confirm_cmd += f" --transport {args.transport}"
            print(confirm_cmd)
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

    return 1 if failures else 0


def main_sync() -> None:
    """Synchronous entry point for console_scripts."""
    sys.exit(asyncio.run(main()))
