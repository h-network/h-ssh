"""Command-line interface for h-ssh."""

import argparse
import asyncio
import concurrent.futures
import contextlib
import difflib
import getpass
import json
import logging
import os
import re
import shlex
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from .core import (
    Target, load_devices_csv, load_config, get_config_path,
    resolve_command, resolve_structured,
    get_available_commands, read_command_file_lines, parse_inline_target,
    load_jobs, parse_jobs, resolve_target_port, check_unique,
    check_confirm_minutes,

    path_inside,
)
from .runner import run_for_target_async, is_connect_failure, RunResult, error_line
from .drivers import results as R
from .runfile import load_run_file, validate_run, apply_run, edit_needs_timer
from .safety import SafetyGate
from . import pool
from .audit import write_audit_entry, redact_values, secure_append, probe_append
from .vendors import VENDORS
from . import drivers


# Supported vendor names for validation: the vendors registry itself, under
# the name the CLI has always used, so one table cannot drift from the other.
VENDOR_MODULES = VENDORS

# What to install when a target's transport reports itself unavailable.
VENDOR_INSTALL = {name: drivers.get(name).transport.install for name in drivers.names()}



_RESULT_HEADER_KEYS = ("DEVICE:", "HOST:", "MODE:", "VENDOR:")


# What a terminal would act on rather than show: C0 controls other than tab
# and newline, DEL, C1 controls, and every ESC sequence (CSI, OSC, the rest).
_TERMINAL_CONTROLS = re.compile(
    r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"   # CSI (7- or 8-bit) … final byte
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"   # OSC … BEL or ST
    r"|\x1b[@-Z\\-_]"                    # two-byte ESC sequences
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]")


def terminal_safe(text: str) -> str:
    """Device output as it may be shown on the operator's terminal: a device
    (or a description field) cannot repaint, hide or retitle anything.
    Files keep the raw bytes; this is for the screen only."""
    if not text:
        return text
    return _TERMINAL_CONTROLS.sub("", text)


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


# Descriptors one in-flight device costs: measured at ~6 for a NETCONF
# session (socket, ncclient's selector, paramiko's pipe), the heaviest case.
FDS_PER_WORKER = 6
FDS_BASE = 32


def fit_workers_to_open_files(workers: int):
    """(workers the open-file limit can carry, a note when that is fewer).
    The soft limit is raised towards the hard one first, which needs no
    privilege; only what is still short lowers the workers (L10)."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ImportError, ValueError, OSError):
        return workers, None
    need = workers * FDS_PER_WORKER + FDS_BASE
    if soft != resource.RLIM_INFINITY and soft < need:
        wanted = need if hard == resource.RLIM_INFINITY else min(need, hard)
        if wanted > soft:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
                soft = wanted
            except (ValueError, OSError):
                pass
    if soft == resource.RLIM_INFINITY or soft >= need:
        return workers, None
    fit = max(1, (soft - FDS_BASE) // FDS_PER_WORKER)
    return fit, (f"the open-file limit of {soft} (ulimit -n) carries {fit} workers at "
                 f"~{FDS_PER_WORKER} descriptors each, not {workers}; running {fit}")


def resolve_workers(requested: int) -> int:
    """Clamp --workers to something a thread pool can honour."""
    try:
        n = int(requested)
    except (TypeError, ValueError):
        return 8
    return max(1, min(n, MAX_WORKERS))


MAX_SECONDS = 86400


def _ranged_int(low: int, high: Optional[int], what: str):
    """An argparse type: an integer within [low, high], or one line naming the
    range. The value a flag accepts is the value a config file accepts, so
    the same ranges live in CONFIG_FLOORS / CONFIG_CEILINGS."""
    def convert(text: str) -> int:
        try:
            value = int(text)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError(f"{what} takes a whole number, not {text!r}")
        if value < low or (high is not None and value > high):
            span = f"a number from {low} to {high}" if high is not None else f"a number of {low} or more"
            raise argparse.ArgumentTypeError(f"{what} takes {span}, not {value}")
        return value
    return convert


def _tty(stream) -> bool:
    """Is this a terminal? False for a closed or absent stream (`>&-` leaves
    sys.stdout as None) instead of a traceback."""
    try:
        return bool(stream is not None and stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


class _Parser(argparse.ArgumentParser):
    """argparse's error() prints the whole usage block before the one line
    that matters; on a 30-flag tool that buries it. One line, exit 2."""
    def error(self, message):
        self.exit(2, f"{self.prog}: error: {message} (see --help)\n")



# Everything here may be set in ~/.h-ssh/config. The password may not: a config
# file on a shared host is the wrong home for a secret.
CONFIG_DEFAULTS = {
    "workers": 8,
    "session_timeout": 30,
    "command_timeout": 20,
    "retries": 2,
    "transport": "ssh",
}


TRANSPORT_CHOICES = ["junos", "ssh", "openssh", "telnet"]
# The floor a config-file value must reach; a flag has argparse for this.
CONFIG_FLOORS = {"workers": 1, "retries": 0, "session_timeout": 1, "command_timeout": 1}
CONFIG_CEILINGS = {"workers": MAX_WORKERS, "session_timeout": MAX_SECONDS, "command_timeout": MAX_SECONDS}


def apply_config_defaults(args, config: dict) -> None:
    """Fill unset options from the config file, then from the built-in default.

    Precedence is flag, then environment (handled per option), then config file,
    then default. An option given on the command line is never overridden. A
    file value is held to what the flag would accept: a transport from the
    list, numbers at or above their floor; anything else is a ValueError
    naming the key, not a silent default.
    """
    for key, fallback in CONFIG_DEFAULTS.items():
        if getattr(args, key, None) is not None:
            continue
        if key not in config:
            setattr(args, key, fallback)
            continue
        value = config[key]
        if isinstance(fallback, int):
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise ValueError(f"{key} = {value!r} is not a number")
            if value < CONFIG_FLOORS.get(key, 0):
                raise ValueError(f"{key} = {value} is below {CONFIG_FLOORS.get(key, 0)}")
            if key in CONFIG_CEILINGS and value > CONFIG_CEILINGS[key]:
                raise ValueError(f"{key} = {value} is above {CONFIG_CEILINGS[key]}")
        elif key == "transport":
            value = str(value).strip().lower()   # vendors are matched lowercase, as for targets
            if value not in TRANSPORT_CHOICES:
                raise ValueError(f"transport = {value!r} is not one of {', '.join(TRANSPORT_CHOICES)}")
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


def confirm_program() -> str:
    """How this run was started, for the confirm hint: the script as typed
    (./h-app/h-ssh.py, or its full path), or the console script's name for
    a pip install, where no checkout path exists."""
    prog = sys.argv[0] if sys.argv else ""
    if prog.endswith(".py"):
        return prog
    return os.path.basename(prog) or "h-ssh"


def target_spec(t: Target) -> str:
    """A target as the inline --target spec that parses back to it; an IPv6
    host goes back into its brackets."""
    host = f"[{t.host}]" if ":" in t.host else t.host
    spec = f"{t.name}:{host}:{t.vendor}"
    return f"{spec}:{t.port}" if t.port is not None else spec


def build_confirm_command(user, target_specs, devices: str, transport: str) -> str:
    """The command that confirms this run's commit-confirmed.

    Rebuilt from the run's own arguments, so it reaches the same devices as
    the same user, started the same way: the inline --target specs as typed
    (a job's edit targets, rebuilt), or else the inventory file. --transport
    is kept only when it names a transport that can confirm a commit.
    """
    cmd = [shlex.quote(confirm_program()) + ' -eC "commit"']
    if user:
        cmd.append("--user " + shlex.quote(user))
    if target_specs:
        cmd.extend("--target " + shlex.quote(spec) for spec in target_specs)
    else:
        cmd.append("--devices " + shlex.quote(devices))
    if "commit_confirmed" in drivers.get(transport).supports:
        cmd.append("--transport " + transport)
    return " ".join(cmd)


def get_default_devices_path() -> str:
    """Get default devices CSV path, preferring ~/.h-ssh/devices.csv if it exists."""
    home_path = Path.home() / ".h-ssh" / "devices.csv"
    if home_path.exists():
        return str(home_path)
    return "devices.csv"


def edit_guard(vendor: str):
    """The dialect whose `check_edit` an edit payload for this vendor must
    pass, or None: a dialect without a guard, or a vendor name the check
    further down will report as unknown."""
    try:
        dialect = drivers.get(vendor).dialect
    except ValueError:
        return None
    return dialect if dialect.check_edit else None


async def check_reachability(target, timeout: int = 2) -> tuple:
    """Quick reachability check for a target."""
    port = resolve_target_port(target)
    banner = drivers.get(target.vendor).transport.banner

    loop = asyncio.get_running_loop()
    try:
        await loop.getaddrinfo(target.host, None)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, port),
                timeout=timeout,
            )
            try:
                if banner:
                    # A port that accepts and closes (a NAT in front of a dead
                    # container, sshd at its connection limit) is not a device:
                    # the transport's banner is.
                    first = await asyncio.wait_for(reader.readline(), timeout=timeout)
                    if not first.startswith(banner):
                        return (target.name, False,
                                f"port {port} open but no {banner.decode('ascii', 'replace').rstrip('-')} banner")
            finally:
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


def is_confirm(payload: str) -> bool:
    """A literal `commit` (or `commit;`) as the whole edit payload confirms a
    pending commit-confirmed; the same word inside a config file is config."""
    return payload.strip() in ("commit", "commit;")

def confirm_minutes_arg(text: str) -> int:
    """--commit-confirmed N: Junos arms 1..65535 minutes; anything else is a
    usage error here, not a permanent commit behind a rollback banner."""
    try:
        minutes = int(text)
        check_confirm_minutes(minutes)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r}: --commit-confirmed takes 1..65535 minutes")
    return minutes


async def main() -> int:
    """Main CLI entry point."""
    # Device output is whatever the device sent; a byte the terminal's
    # encoding cannot show must not end the run with a traceback.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = _Parser(description="Multi-vendor network automation tool.")

    parser.add_argument("--devices", default=get_default_devices_path(),
                        help="Devices CSV (default: ~/.h-ssh/devices.csv or ./devices.csv)")
    parser.add_argument("--transport", choices=TRANSPORT_CHOICES, default=None,
                        help="Transport for targets that don't declare one (default: ssh)")
    parser.add_argument("--structured", action="store_true",
                        help="Return structured data where the vendor supports it "
                             "(junos NETCONF); falls back to text elsewhere")
    parser.add_argument("--user", type=str,
                        help="Username (or HSSH_USER env var, or 'user' in ~/.h-ssh/config)")
    parser.add_argument("--config", type=str,
                        help="Config file with defaults (default: ~/.h-ssh/config)")
    parser.add_argument("--password", type=str,
                        help="Password (visible in the process list; prefer HSSH_PASSWORD or the prompt)")

    # Modes
    parser.add_argument("-sC", "--show-command", type=str,
                        help="Show command to run on all targets")
    parser.add_argument("-eC", "--edit-command", type=str,
                        help="Single config command (Junos expects 'set ...')")
    parser.add_argument("-eD", "--edit-dir", type=str,
                        help="Directory containing <NAME>.set files")
    parser.add_argument("-eB", "--edit-broadcast", type=str,
                        help="Multi-line config file for all devices (e.g., configs/all.set)")
    parser.add_argument("--allow-missing", action="store_true",
                        help="-eD: skip devices that have no <NAME>.set instead of refusing the run "
                             "(they count as skipped: exit 3)")
    parser.add_argument("--batch", type=str,
                        help="File containing show commands to run in batch (one per line, # comments)")
    parser.add_argument("--job", type=str,
                        help="JSON job file with per-device commands (use - for stdin)")
    parser.add_argument("--run", type=str, metavar="FILE",
                        help="YAML or JSON run file: every key is a flag name (devices, show, commands, "
                             "edit, jobs, workers, ...); a flag on the command line wins over the file")
    parser.add_argument("--rollback", type=_ranged_int(0, 49, "--rollback"), metavar="N",
                        help="Return every target to rollback N (0-49), with the same gates as an edit (Junos only)")
    parser.add_argument("--commit-status", action="store_true",
                        help="Show the commit history as data: sequence, time, user, comment, pending commit-confirmed timer (Junos only)")
    parser.add_argument("--comment", type=str, metavar="TEXT",
                        help="Log this comment with the commit; it shows in 'show system commit' (Junos only)")
    parser.add_argument("--show-diff", action="store_true",
                        help="Edits: run a dry-run on every target, print the diffs, then ask once before "
                             "committing; a diff that changed by then is not committed")

    # Behavior
    parser.add_argument("--retries", type=_ranged_int(0, None, "--retries"), default=None,
                        help="Retries per device after the first attempt (default: 2). "
                             "Permanent failures never retry.")
    parser.add_argument("--workers", type=_ranged_int(1, MAX_WORKERS, "--workers"), default=None,
                        help="Parallel workers (default: 8)")
    parser.add_argument("--session-timeout", type=_ranged_int(1, MAX_SECONDS, "--session-timeout"), default=None,
                        help="Timeout for establishing connection/session (default: 30)")
    parser.add_argument("--command-timeout", type=_ranged_int(1, MAX_SECONDS, "--command-timeout"), default=None,
                        help="Timeout for individual commands/operations (default: 20)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Do not push, only show what would happen")
    parser.add_argument("--commit-confirmed", type=confirm_minutes_arg, nargs="?", const=10, default=None,
                        help="Use commit confirmed with auto-rollback timer in minutes, 1-65535 (default: 10, Junos only)")
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
                        help="Inline target as name:host:vendor:port, an IPv6 host in brackets "
                             "(repeatable, vendor defaults to --transport)")

    # Output
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON array (suppresses human-readable output)")
    parser.add_argument("--format", choices=["text", "json", "xml"], default="text",
                        help="Show output as the router's own JSON or XML reply, through its RPC "
                             "translation of the command (junos only; default: text)")
    parser.add_argument("--save-output", type=str,
                        help="Create dir (0700) and save each device's raw output in it (0600 files, not redacted)")
    parser.add_argument("--log", type=str,
                        help="Append per-device JSONL results to file (0600, secrets redacted as in the audit log)")
    parser.add_argument("--audit-log", type=str,
                        default=os.environ.get("HSSH_AUDIT_LOG"),
                        help="Edit audit log path for JSONL audit trail (or set HSSH_AUDIT_LOG env var)")
    parser.add_argument("--safety-file", type=str,
                        default=os.environ.get("HSSH_SAFETY_FILE"),
                        help="Safety gate JSON file for per-device rate limiting and cooldown")

    args = parser.parse_args()
    if not args.verbose:
        _quiet_transport_logs()
    args.batch_commands = None   # an inline batch, only a run file sets it
    args.jobs_data = None        # job entries from a run file

    # A run file sits between the command line and the config file: a flag
    # typed on the command line wins, the file wins over the environment and
    # ~/.h-ssh/config. It is read before anything else so the banner and the
    # checks below see what the run will use.
    if args.run:
        try:
            run_data = validate_run(load_run_file(args.run), args.run, TRANSPORT_CHOICES, CONFIG_FLOORS,
                                    CONFIG_CEILINGS)
            apply_run(args, run_data, parser)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2

    # Resolved before anything reads them, so --list-commands and the banner
    # see the same values the run will use. A --config named on the command
    # line that is not there is said so; the implicit default stays silent.
    if args.config and not Path(args.config).exists():
        print(f"ERROR: config file not found: {args.config}", file=sys.stderr)
        return 2
    try:
        file_config = load_config(args.config)
        apply_config_defaults(args, file_config)
    except ValueError as e:
        print(f"ERROR: {get_config_path() if args.config is None else args.config}: {e}", file=sys.stderr)
        return 2

    # A command made of whitespace is a typo, not a request.
    for flag, value in (("-sC", args.show_command), ("-eC", args.edit_command)):
        if value is not None and not value.strip():
            print(f"ERROR: {flag} is empty.", file=sys.stderr)
            return 2

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
            print(f"See h-app/hssh/dialects/junos.json for format example.\n")
        return 0

    # Two different paths: a binding's few fields, or the router's whole reply.
    if args.structured and args.format != "text":
        print("ERROR: --structured and --format are mutually exclusive.", file=sys.stderr)
        return 2

    # ------ JOB MODE ------
    job_entries = None
    if args.job or args.jobs_data:
        if any([args.show_command, args.edit_command, args.edit_dir, args.edit_broadcast, args.batch,
                args.batch_commands, args.rollback is not None, args.commit_status]):
            print("ERROR: --job cannot be combined with -sC, -eC, -eD, -eB, --batch, --rollback, or --commit-status.", file=sys.stderr)
            return 2
        if args.job and args.jobs_data:
            print("ERROR: --job and a run file's 'jobs' are two job lists; use one.", file=sys.stderr)
            return 2
        try:
            if args.job:
                job_entries = load_jobs(args.job, default_vendor=args.transport)
            else:
                job_entries = parse_jobs(args.jobs_data, default_vendor=args.transport)
        except (ValueError, json.JSONDecodeError) as e:
            print(f"ERROR: Invalid job file: {e}", file=sys.stderr)
            return 2

        targets = [entry.target for entry in job_entries]
        try:
            check_unique(targets, allow_repeats=True)
        except ValueError as e:
            print(f"ERROR: job file: {e}", file=sys.stderr)
            return 2
        has_edits = any(e.mode.startswith("edit") for e in job_entries)
        mode = "job"
        for je in job_entries:
            guard = edit_guard(je.target.vendor)
            if guard and je.mode.startswith("edit"):
                valid, err = guard.check_edit(je.command, allow_commit=True)
                if not valid:
                    print(f"ERROR: {guard.title} job command for '{je.target.name}' only accepts set-style commands: {err}", file=sys.stderr)
                    return 2
    else:
        # Determine mode
        modes = [
            bool(args.show_command),
            bool(args.edit_command),
            bool(args.edit_dir),
            bool(args.edit_broadcast),
            bool(args.batch) or bool(args.batch_commands),
            args.rollback is not None,
            bool(args.commit_status),
        ]
        if args.batch and args.batch_commands:
            print("ERROR: --batch and a run file's 'commands' are two command lists; use one.", file=sys.stderr)
            return 2
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

        # Load targets. A target that doesn't declare a vendor gets
        # --transport (or the config file's), the same for every form.
        if args.target:
            try:
                targets = [parse_inline_target(spec, default_vendor=args.transport) for spec in args.target]
            except ValueError as e:
                print(f"ERROR: {e}", file=sys.stderr)
                return 2
        else:
            try:
                targets = load_devices_csv(args.devices, default_vendor=args.transport)
            except Exception as e:
                print(f"ERROR loading devices: {e}", file=sys.stderr)
                return 2

        if not targets:
            print("ERROR: no devices found in inventory.", file=sys.stderr)
            return 2
        try:
            check_unique(targets)
        except ValueError as e:
            print(f"ERROR: {'inline targets' if args.target else args.devices}: {e}", file=sys.stderr)
            return 2

        # The edit guard keys off the targets' dialects, not a global flag —
        # a mixed inventory can have some devices that care and some that don't.
        broadcast_text = None
        edit_payloads = {}
        guards = {}
        for t in targets:
            guard = edit_guard(t.vendor)
            if guard:
                guards[guard.name] = guard
        if guards:
            if args.edit_command:
                for guard in guards.values():
                    valid, err = guard.check_edit(args.edit_command, allow_commit=True)
                    if not valid:
                        print(f"ERROR: {guard.title} -eC only accepts 'set ...' commands: {err}", file=sys.stderr)
                        return 2
            elif args.edit_broadcast:
                try:
                    b_content = Path(args.edit_broadcast).read_text(encoding="utf-8-sig")
                except Exception as e:
                    print(f"ERROR reading broadcast file '{args.edit_broadcast}': {e}", file=sys.stderr)
                    return 2
                for guard in guards.values():
                    valid, err = guard.check_edit(b_content, allow_commit=False)
                    if not valid:
                        print(f"ERROR: {guard.title} broadcast file '{args.edit_broadcast}' only accepts 'set ...' commands: {err}", file=sys.stderr)
                        return 2
            elif args.edit_dir:
                for t in targets:
                    guard = edit_guard(t.vendor)
                    if guard:
                        set_file = path_inside(args.edit_dir, f"{t.name}.set")
                        if set_file.is_file():
                            try:
                                d_content = set_file.read_text(encoding="utf-8-sig")
                            except Exception as e:
                                print(f"ERROR reading config file '{set_file}': {e}", file=sys.stderr)
                                return 2
                            valid, err = guard.check_edit(d_content, allow_commit=False)
                            if not valid:
                                print(f"ERROR: {guard.title} config file '{set_file}' only accepts 'set ...' commands: {err}", file=sys.stderr)
                                return 2

        # The payloads, read once here and handed to the runner and the audit
        # log as the same string: what the guard checked is what is sent.
        if args.edit_broadcast:
            try:
                broadcast_text = Path(args.edit_broadcast).read_text(encoding="utf-8-sig")
            except Exception as e:
                print(f"ERROR reading broadcast file '{args.edit_broadcast}': {e}", file=sys.stderr)
                return 2
        skipped_missing = 0
        if args.edit_dir:
            for t in targets:
                set_file = path_inside(args.edit_dir, f"{t.name}.set")
                if set_file.is_file():
                    try:
                        edit_payloads[t.name] = set_file.read_text(encoding="utf-8-sig")
                    except Exception as e:
                        print(f"ERROR reading config file '{set_file}': {e}", file=sys.stderr)
                        return 2
            # A device without a set file is known before the first lock. The
            # run is refused rather than deployed to everyone else, unless the
            # operator said those devices may be left out; then they are
            # reported as skipped, never silently.
            missing = [t.name for t in targets if t.name not in edit_payloads]
            if missing:
                shown = ", ".join(missing[:20]) + (" …" if len(missing) > 20 else "")
                if not args.allow_missing:
                    print(f"ERROR: -eD {args.edit_dir}: no <NAME>.set for {len(missing)} of {len(targets)} device(s): "
                          f"{shown}. Nothing was sent; --allow-missing skips them.", file=sys.stderr)
                    return 2
                print(f"Skipping {len(missing)} device(s) without a set file: {shown}", file=sys.stderr)
                targets = [t for t in targets if t.name in edit_payloads]
                skipped_missing = len(missing)
                if not targets:
                    print("ERROR: no device has a set file; nothing to do.", file=sys.stderr)
                    return 2

        # Mode label
        if args.show_command:
            mode = "show"
        elif args.edit_command:
            mode = "edit-cmd"
        elif args.edit_broadcast:
            mode = "edit-broadcast"
        elif args.batch or args.batch_commands:
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
    # Nobody watches a pipeline: a run file that commits must arm a timer, or
    # say it is a dry run. A flag on the command line may supply either.
    if args.run and has_edits and edit_needs_timer(args, is_confirm):
        print(f"ERROR: run file '{args.run}' makes changes without a rollback timer: set commit_confirmed "
              "(minutes) in the file or pass --commit-confirmed, or set dry_run.", file=sys.stderr)
        return 2
    # A confirm is a plain commit: it cannot arm a new timer, so a run that
    # asks for one would end with a banner promising a rollback that no
    # device is counting down.
    confirms = ([args.edit_command] if args.edit_command else
                [je.command for je in (job_entries or []) if je.mode.startswith("edit")])
    if args.commit_confirmed and confirms and all(is_confirm(c) for c in confirms):
        print('ERROR: --commit-confirmed does not go with -eC "commit": a confirm cannot arm a new timer.',
              file=sys.stderr)
        return 2
    if args.show_diff and (not has_edits or args.dry_run):
        print("ERROR: --show-diff goes with an edit that is not already a --dry-run.", file=sys.stderr)
        return 2
    # --format shapes a show's reply. An edit, --rollback or --commit-status
    # has none to shape, so it is refused rather than quietly ignored; a job
    # keeps it for its show entries.
    has_shows = any(e.mode == "show" for e in job_entries) if job_entries else mode in ("show", "show-batch")
    if args.format != "text" and not has_shows:
        print("ERROR: --format goes with a show (-sC, --batch, or a --job's show entries).", file=sys.stderr)
        return 2

    # Every target's vendor name resolves to a driver whose module is installed
    for v in set(t.vendor for t in targets):
        if v in drivers.RETIRED:
            print(f"ERROR: {drivers.RETIRED[v]}.", file=sys.stderr)
            return 2
        try:
            mod = VENDOR_MODULES.get(drivers.get(v).shim)
        except ValueError:
            mod = None
        if mod is None:
            print(f"ERROR: Unknown vendor '{v}'.", file=sys.stderr)
            return 2
        if not mod.AVAILABLE:
            install = VENDOR_INSTALL.get(v, v)
            print(f"ERROR: {install} not installed (required for vendor '{v}').", file=sys.stderr)
            return 2

    # Everything the run will write is proven writable before the first
    # device is touched: an audit log found unwritable after the commits
    # landed records nothing, and a safety gate that cannot keep its file
    # must refuse, not warn and run unguarded.
    for label, path in (("--audit-log", args.audit_log), ("--log", args.log)):
        if path:
            try:
                probe_append(path)
            except OSError as e:
                print(f"ERROR: {label} {e}; refusing to start.", file=sys.stderr)
                return 2
    safety_file = args.safety_file or os.environ.get("HSSH_SAFETY_FILE")
    try:
        safety_gate = SafetyGate(safety_file=safety_file) if safety_file else None
    except OSError as e:
        print(f"ERROR: --safety-file requested but unusable: {e}; refusing to start.", file=sys.stderr)
        return 2

    save_dir = None
    if args.save_output:
        save_dir = args.save_output
        # Raw device output (a config backup is the point), so the directory
        # and its files are the operator's alone: 0700 / 0600, never redacted.
        if Path(save_dir).exists() and not Path(save_dir).is_dir():
            print(f"ERROR: --save-output {save_dir} exists and is not a directory.", file=sys.stderr)
            return 2
        try:
            Path(save_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as e:
            print(f"ERROR: --save-output {save_dir}: {e.strerror or e}", file=sys.stderr)
            return 2

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
        if not _tty(sys.stdin):
            print("ERROR: No username provided and stdin is not a TTY. "
                  "Use --user, HSSH_USER, or set 'user' in %s." % get_config_path(),
                  file=sys.stderr)
            return 2
        default_user = getpass.getuser()
        user = input(f"Username [{default_user}]: ").strip() or default_user

    if not passwd:
        # No transport needs a password up front: a key or an agent may do.
        if _tty(sys.stdin):
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
        if args.batch_commands:
            batch_cmds = list(args.batch_commands)
        elif args.batch:
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

    args.workers, fd_note = fit_workers_to_open_files(resolve_workers(args.workers))
    if fd_note:
        print(f"WARNING: {fd_note}", file=sys.stderr)

    if show_progress:
        if job_entries:
            print(f"\nMode: job | Targets: {len(targets)} | Workers: {args.workers}")
        else:
            print(f"\nTransport: {args.transport} | Mode: {mode} | Workers: {args.workers}")
            if args.target:
                print(f"Targets: {len(targets)} (inline)")
            else:
                print(f"Inventory: {args.devices}")
        if args.run:
            timer = (f", commit confirmed {args.commit_confirmed} min" if has_edits and args.commit_confirmed
                     else ", dry run" if has_edits and args.dry_run else "")
            print(f"Run file: {args.run} ({'edit' if has_edits else 'read'} on {len(targets)} device(s){timer})")
        if save_dir:
            print(f"Save output dir: {save_dir}")
        if batch_cmds:
            print(f"Batch: {len(batch_cmds)} commands from {args.batch or 'the run file'}")
        print(f"Targets: {len(targets)}")

    # One unit of work per job entry, or per target. The entry (None outside
    # job mode) travels with its result, so a job that names one device in
    # two entries never has the second read as the first.
    units = [(je.target, je) for je in job_entries] if job_entries else [(t, None) for t in targets]

    def _audit_aborted(error):
        """One audit line per unit for a run the operator did not confirm."""
        if not args.audit_log:
            return
        for t, je in units:
            write_audit_entry(
                path=args.audit_log,
                device=t.name,
                host=t.host,
                vendor=t.vendor,
                mode=je.mode if je else mode,
                payload="",
                ok=False,
                error=error,
            )

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

    # Pre-flight check and confirmation for edit operations
    # --show-diff previews every target before asking, which proves
    # reachability the real way and spares the router a connection it counts
    # against its ssh rate limit.
    if has_edits and not args.dry_run and not args.show_diff:
        # Probed --workers at a time with --session-timeout, like the run
        # itself: 250 probes at once trip sshd's MaxStartups and a router's
        # ssh rate-limit, and called devices unreachable that the real
        # 32-worker edit then reached (H1). A probe that fails is tried once
        # more before the device is called unreachable, for the same reason.
        async def _probe(t):
            async with sem:
                result = await check_reachability(t, timeout=args.session_timeout)
                if not result[1]:
                    result = await check_reachability(t, timeout=args.session_timeout)
                return result

        if not json_mode:
            print(f"\nPre-flight check: Validating device reachability "
                  f"({min(workers, len(targets))} at a time, {args.session_timeout}s each)...")

        reachability_results = await asyncio.gather(*[_probe(t) for t in targets])

        unreachable = []
        for t, (name, reachable, msg) in zip(targets, reachability_results):
            if not json_mode:
                status = "[PASS]" if reachable else "[FAIL]"
                print(f"  {status} {name:16s} ({t.host}) - {msg}")
            if not reachable:
                unreachable.append(t)

        if unreachable:
            if args.audit_log:
                for ut in unreachable:
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
            names = [ut.name for ut in unreachable]
            if json_mode:
                err = {"error": f"{len(unreachable)} device(s) unreachable", "unreachable": names}
                print(json.dumps(err))
            else:
                print(f"\nERROR: {len(unreachable)} device(s) unreachable: {', '.join(names)}")
                print("Aborting to prevent partial deployment.")
            return 2

        if not json_mode:
            print(f"\nReady to execute on {len(targets)} device(s).")

        if args.show_diff:
            pass  # the diffs are shown first, the question comes after them
        elif not args.yes:
            if not _tty(sys.stdin):
                print("ERROR: Edit operation requires confirmation but stdin is not a TTY. Use -y to skip.", file=sys.stderr)
                return 2
            try:
                confirm = input("\nProceed with changes? [y/N]: ").strip().lower()
                if confirm not in ['y', 'yes']:
                    _audit_aborted("aborted by user confirmation")
                    print("Aborted by user.")
                    return 0
            except (KeyboardInterrupt, EOFError):
                _audit_aborted("aborted by user interrupt")
                print("\nAborted by user.")
                return 0
        elif not json_mode:
            print("(--yes flag provided, skipping confirmation)")

    if show_progress:
        print()

    failures = 0
    interrupted_connects = 0
    skipped = 0                                              # held back by the safety gate (in the results)
    not_run = skipped_missing if not job_entries else 0      # no set file (--allow-missing): not in the results
    json_results = []
    run_start = time.time()


    # A job may list one device in several entries. Those run one at a time
    # per host, in file order, so a show after an edit sees the edit and the
    # safety gate never meets the second entry as an "active connection".
    host_locks = {}

    def _host_lock(host):
        if not job_entries:
            return contextlib.nullcontext()
        return host_locks.setdefault(host, asyncio.Lock())

    async def _bounded_run(t, mode_override=None, cmd_override=None, dry_run=None, expected_diff=None,
                           started=None):
        async with _host_lock(t.host), sem:
            if started is not None:
                started()        # from here on the device may be touched
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
            # Edit payloads are sent as typed: the template library is for
            # show shortcuts, and a template could not pass the set-syntax
            # guard that already approved the typed text.
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
                payload_text=(broadcast_text if actual_mode == "edit-broadcast"
                              else edit_payloads.get(t.name) if actual_mode == "edit-dir" else None),
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
                expected_diff=expected_diff,
            )

    started = set()      # unit indices whose device may already be in play
    inflight = set()     # of those, the ones still running when Ctrl-C came

    async def _run_unit(i, dry_run=None, expected_diff=None):
        """units[i] on its device, in its own mode and command for a job
        entry; the index comes back with the result."""
        t, je = units[i]
        mark = lambda: started.add(i)
        if je is not None:
            result = await _bounded_run(t, je.mode, je.command, dry_run=dry_run, expected_diff=expected_diff,
                                        started=mark)
        else:
            result = await _bounded_run(t, dry_run=dry_run, expected_diff=expected_diff, started=mark)
        if not isinstance(result, RunResult):
            # A stand-in runner that still returns the bare tuple: the error is
            # read from its text, as it always was.
            name, ok, text, ms = result
            result = RunResult(name, ok, text, ms, error=None if ok else error_line(text))
        return i, result

    # --show-diff: every target's diff first, one question, then the real
    # run, which commits each diff only if the device produces it again.
    expected = {}
    if args.show_diff and has_edits and not args.dry_run:
        if not args.yes and not _tty(sys.stdin):
            print("ERROR: --show-diff needs a terminal to ask, or -y.", file=sys.stderr)
            return 2
        previews = [asyncio.create_task(_run_unit(i, dry_run=True)) for i in range(len(units))]
        preview_failed = []
        for coro in asyncio.as_completed(previews):
            i, res = await coro
            name, ok, out_text = res.name, res.ok, res.text
            if _tty(sys.stdout):
                out_text = terminal_safe(out_text)
            # stdout stays the JSON array in --json mode; the previews go to stderr
            print(f"\n--- {name}: {'diff' if ok else 'FAILED'} ---", file=sys.stderr if json_mode else sys.stdout)
            print(out_text.rstrip(), file=sys.stderr if json_mode else sys.stdout)
            if ok:
                # The diff the commit must find again; "" when the preview said
                # NO CHANGES. On a terminal it is the diff as shown, control
                # sequences stripped, as it always was.
                diff = res.result.diff if isinstance(res.result, R.EditResult) else ""
                expected[i] = terminal_safe(diff) if _tty(sys.stdout) else diff
            else:
                preview_failed.append(name)
            if args.audit_log:
                ut, uje = units[i]
                write_audit_entry(
                    path=args.audit_log, device=ut.name, host=ut.host, vendor=ut.vendor,
                    mode=uje.mode if uje else mode,
                    payload=(uje.command if uje else edit_cmd or broadcast_text or edit_payloads.get(ut.name) or ""),
                    ok=ok, diff=out_text if ok else None, error=None if ok else out_text.strip(),
                    dry_run=True, comment=args.comment)
        if preview_failed:
            print(f"\nERROR: dry-run failed on {', '.join(preview_failed)}; nothing committed.", file=sys.stderr)
            return 1
        if not args.yes:
            try:
                answer = input("\nCommit these changes on all devices? [y/N]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                _audit_aborted("aborted by user interrupt")
                print("\nAborted by user.")
                return 0
            if answer not in ("y", "yes"):
                _audit_aborted("aborted by user confirmation")
                print("Aborted by user.")
                return 0

    if job_entries:
        # A job lists one device in several entries. With the pool on they
        # share one session per device instead of logging in once per entry
        # (#57); the pool's per-router lock keeps a host's entries in order,
        # and an edit entry's session is clean again before the next one.
        pool.enable()

    tasks = [asyncio.create_task(_run_unit(i, expected_diff=expected.get(i))) for i in range(len(units))]
    screen = _tty(sys.stdout)     # control sequences are stripped for a terminal, kept for a pipe

    interrupted = False
    log_cmd = (batch_cmds or show_cmd or edit_cmd or args.edit_broadcast
               or (args.edit_dir and f"dir:{args.edit_dir}") or "job")
    log_ts = datetime.now().isoformat()
    log_warned = False

    async def _completed():
        """Results as they land. On Ctrl-C the units that have not started are
        cancelled; the ones in flight are still awaited, so a commit that is
        on its way to a device is reported, logged and audited, never dropped."""
        nonlocal interrupted
        pending = set(tasks)
        while pending:
            try:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            except (asyncio.CancelledError, KeyboardInterrupt):
                interrupted = True
                for i, task in enumerate(tasks):
                    if i not in started and task in pending:
                        task.cancel()
                        pending.discard(task)
                    elif task in pending and not task.done():
                        inflight.add(i)
                continue
            for task in done:
                if not task.cancelled():
                    yield task.result()

    async for i, res in _completed():
        name, ok, out_text, duration_ms = res
        if screen:
            out_text = terminal_safe(out_text)
        t, je = units[i]
        # A job entry runs in its own mode; everything else in the run's.
        dev_mode = je.mode if je else mode
        entry = {
            "device": name,
            "host": t.host,
            "vendor": t.vendor,
            "ok": ok,
            "duration_ms": duration_ms,
        }

        if mode == "commit-status":
            entry["commits"] = res.result.to_list() if ok and isinstance(res.result, R.CommitStatus) else []
            if ok and not json_mode:
                print(f"\n{name}:")
                for c in entry["commits"]:
                    pending = f"  [commit confirmed, rollback in {c['pending_rollback_minutes']} min]" if c.get("pending_rollback_minutes") is not None else ""
                    note = f"  {c['comment']}" if c.get("comment") else ""
                    print(f"  {c['seq']:>2}  {c['time']}  by {c['user']} via {c['client']}{pending}{note}")
            if not ok:
                entry["error"] = res.error if res.error is not None else (out_text.strip() or "unknown error")
        elif mode == "show-batch":
            cmd_results = res.result.to_list() if isinstance(res.result, R.BatchResult) else None

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
                entry["error"] = res.error if res.error is not None else (out_text.strip() or "unknown error")
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
            entry["error"] = res.error if res.error is not None else "unknown error"
        if i in inflight and not ok and is_connect_failure(entry.get("error", "")):
            # Ctrl-C came while this device was still being connected to; the
            # connect ran out on its own afterwards. Nothing reached the
            # device, and the operator stopped the run: that is interrupted,
            # not a device that failed.
            entry["interrupted"] = True
            entry["error"] = f"interrupted while connecting: {entry['error']}"
        json_results.append(entry)

        # Audit logging for operations
        if args.audit_log:
            audit_payload = ""
            if mode == "edit-cmd":
                audit_payload = edit_cmd or ""
            elif mode == "edit-dir":
                audit_payload = edit_payloads.get(name) or f"<no config file for {name}>"
            elif mode == "edit-broadcast":
                audit_payload = broadcast_text or ""
            elif mode == "rollback":
                audit_payload = f"rollback {args.rollback}"
            elif mode == "commit-status":
                audit_payload = "show system commit"
            elif mode == "job":
                audit_payload = ((resolve_command(je.command, t.vendor) if je.mode == "show" else je.command)
                                 if je.command else "")
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

        # The run log is written as the results land: a SIGTERM, an exception
        # later in the loop or an OOM loses nothing already reported.
        if args.log:
            try:
                secure_append(args.log, json.dumps(redact_values({
                    "timestamp": log_ts, "user": user, "mode": mode, "command": log_cmd,
                    "dry_run": args.dry_run, **entry})) + "\n")
            except Exception as e:
                if not log_warned:
                    print(f"WARNING: Could not write to log file: {e}", file=sys.stderr)
                    log_warned = True

        if raw_mode:
            if mode == "show-batch":
                cmd_results = res.result.to_list() if isinstance(res.result, R.BatchResult) else None

                if isinstance(cmd_results, list):
                    print(f"{name}:")
                    for cr in cmd_results:
                        if cr.get("ok"):
                            print(strip_result_header(document_text(cr["output"]), cr["command"]))
                        else:
                            print(f"{name}: {cr.get('command')}: {cr.get('error')}", file=sys.stderr)
                    print()
                else:
                    print(f"{name}: ERROR: {res.error}" if res.error is not None else f"{name}: failed", file=sys.stderr)
            elif ok:
                resolved_cmd = resolve_command(show_cmd, t.vendor) if show_cmd else None
                print(f"{name}:")
                print(strip_result_header(out_text, resolved_cmd))
                print()
            else:
                # stdout stays device output only, so failures go to stderr.
                print(f"{name}: ERROR: {res.error}" if res.error is not None else f"{name}: failed", file=sys.stderr)

        if not json_mode and not raw_mode:
            timestamp = datetime.now().strftime("%H:%M:%S")
            if mode == "show-batch":
                cmd_results = res.result.to_list() if isinstance(res.result, R.BatchResult) else None

                if isinstance(cmd_results, list):
                    ok_count = sum(1 for r in cmd_results if r.get("ok"))
                    total = len(cmd_results)
                    if ok:
                        status = f"OK ({ok_count}/{total} commands)"
                    elif ok_count > 0:
                        status = f"PARTIAL ({ok_count}/{total} commands)"
                    else:
                        status = "INTERRUPTED" if entry.get("interrupted") else "FAIL"
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
                    status = "INTERRUPTED" if entry.get("interrupted") else "FAIL"
                    print(f"[{timestamp}] {name:16s} {status}")
                    if args.verbose:
                        print(f"\n--- Output from {name} ---")
                        print(out_text)
                        print(f"--- End of {name} ---\n")
                    elif not ok and res.error is not None:
                        print(f"  ERROR: {res.error}")
            else:
                status = "OK" if ok else ("INTERRUPTED" if entry.get("interrupted") else "FAIL")
                print(f"[{timestamp}] {name:16s} {status}")

                if args.verbose:
                    print(f"\n--- Output from {name} ---")
                    print(out_text)
                    print(f"--- End of {name} ---\n")
                elif ok and (dev_mode.startswith("edit") or dev_mode == "rollback"):
                    print(format_edit_result(out_text))
                elif not ok and res.error is not None:
                    print(f"  ERROR: {res.error}")

        if not ok:
            if entry.get("error", "").startswith("safety gate blocked"):
                skipped += 1
            elif entry.get("interrupted"):
                interrupted_connects += 1
            else:
                failures += 1

    if job_entries:
        pool.close_all(shutdown=False)   # the run is over: every session closed cleanly, in parallel
        pool.disable()

    # Write structured JSONL log. It holds the same payloads, replies and
    # diffs as the audit log, so it gets the same redaction and file mode.
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
            note = (f"; {interrupted_connects} interrupted while connecting"
                    if interrupted_connects else "")
            print(f"Interrupted. Completed {len(json_results) - interrupted_connects} of "
                  f"{len(targets)} device(s){note}.", file=sys.stderr)

        # The verdict counts what did not run as well as what failed: a run the
        # safety gate kept away from every device must not read as a success.
        notes = ([f"skipped by the safety gate: {skipped}"] if skipped else []) + \
                ([f"skipped for want of a set file: {not_run}"] if not_run else [])
        if failures:
            verdict = f"Done. Failures: {failures}" + (", " + ", ".join(notes) if notes else "")
        elif notes:
            applied = len(json_results) - skipped
            verdict = f"Done. OK: {applied}, " + ", ".join(notes)
            if has_edits and not applied:
                verdict += ", nothing applied"
        else:
            verdict = "Done. All devices OK."
        if not raw_mode:
            print("")
            if failures or skipped or not_run or not interrupted:
                print(verdict)
        elif failures or skipped or not_run:
            # stdout is device output only; the verdict belongs on stderr.
            print(verdict, file=sys.stderr)

        # The reminder is for timers that are actually running: a device
        # that was refused, failed, or had no changes armed nothing.
        armed = [e for e in json_results
                 if e.get("ok") and re.search(r"COMMIT (OK|CONFIRMED \()", str(e.get("output") or ""))]
        if args.commit_confirmed and not args.dry_run and has_edits and armed:
            # A job's timers are armed on its edit entries' targets, not on
            # the inventory file or any --target given alongside it.
            specs = args.target
            if job_entries:
                specs = list(dict.fromkeys(target_spec(je.target) for je in job_entries
                                           if je.mode.startswith("edit")))
            print("")
            print("=" * 70)
            print(" " * 15 + "DON'T FORGET TO CONFIRM THE COMMIT!")
            print("=" * 70)
            print(f"Run this command to confirm within {args.commit_confirmed} minutes:")
            print("  " + build_confirm_command(user, specs, args.devices, args.transport))
            print("\nOr the changes will automatically rollback!")
            print("=" * 70)
            print("")

    # Structured stderr summary
    elapsed_ms = int((time.time() - run_start) * 1000)
    ok_count = len(json_results) - failures - skipped - interrupted_connects
    stderr_mode = "batch" if mode == "show-batch" else ("job" if mode == "job" else mode.split("-")[0])
    summary = json.dumps({
        "targets": len(json_results) + not_run,
        "ok": ok_count,
        "fail": failures,
        "skipped": skipped + not_run,
        **({"interrupted": interrupted_connects} if interrupted else {}),
        "elapsed_ms": elapsed_ms,
        "mode": stderr_mode,
    })
    print(f"[h-ssh] {summary}", file=sys.stderr)

    if safety_gate is not None:
        safety_gate.close()

    if interrupted:
        return 130  # 128 + SIGINT, the shell convention
    if failures:
        return 1
    return 3 if skipped or not_run else 0   # 3: nothing failed, but not everything ran


def _quiet_transport_logs() -> None:
    """paramiko logs a full traceback at ERROR from its transport thread when
    a device closes the connection mid-handshake; with no logging configured
    Python's last-resort handler prints it to stderr next to the one FAIL
    line that already says so. Silenced unless -v; a library caller
    configures logging as it likes and is not touched here."""
    for name in ("paramiko", "ncclient"):
        lg = logging.getLogger(name)
        lg.setLevel(logging.CRITICAL)
        if not lg.handlers:
            lg.addHandler(logging.NullHandler())


def _stdout_gone() -> None:
    """The reader of our output closed it (`| head`, also `2>&1 | head`).
    Point both fds at /dev/null so the interpreter's final flush does not
    fail a second time."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        for stream in (sys.stdout, sys.stderr):
            os.dup2(devnull, stream.fileno())
    except (OSError, ValueError, AttributeError):
        pass


def main_sync() -> None:
    """Synchronous entry point for console_scripts and h-ssh.py."""
    rc = 0
    try:
        rc = asyncio.run(main())
        sys.stdout.flush()          # a reader that left shows up here, not at interpreter exit
    except KeyboardInterrupt:
        # Ctrl-C is a normal way to stop a fleet run; a stack trace is not a
        # useful thing to print at someone who already knows what they did.
        print("\nInterrupted.", file=sys.stderr)
        rc = 130
    except BrokenPipeError:
        # `h-ssh ... | head`: the reader has what it wanted. Not an error of
        # ours, and not a traceback; the run's own verdict, if it got that
        # far, stands.
        _stdout_gone()
    finally:
        try:
            pool.close_all()        # a job run that ended early (Ctrl-C, a crash) leaves no session open
        except Exception:
            pass
    sys.exit(rc)
