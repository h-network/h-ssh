"""The h-ssh command line: parse, resolve precedence, build one RunSpec, render the RunReport.

Precedence (section 3.1): flags, then run file, then profile, then ~/.h-ssh/config, then defaults.
The password is HSSH_PASSWORD or the prompt; there is no --password flag and no file carries one.
"""

from __future__ import annotations

import argparse
import difflib
import getpass
import json
import logging
import os
import re
import shlex
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Sequence

from hssh.dialects.base import Dialect
from hssh.drivers import Registry
from hssh.frontends import profiles, settings
from hssh.frontends.settings import CREDENTIAL_KEYS, load_config  # noqa: F401
from hssh.frontends.fleet import (
    LIBRARY_LOGGERS, Runner, check_unique, load_devices_csv, package_version, parse_target, quiet_library_logs,
    run_spec,
)
from hssh.frontends.runfile import apply_run, load_run_file, validate_run
from hssh.model import (
    Credentials, EditSettings, Fault, Mode, PolicySettings, RecordSettings, RunReport, RunSpec,
    SafetySettings, Target, Timeouts,
)
from hssh.orchestrator import (
    DEFAULT_CONFIRMED_MINUTES, DEFAULT_HOST_KEY_POLICY, DEFAULT_POLICY, DEFAULT_PROBE, DEFAULT_SAFETY,
    DEFAULT_SKIP_UNREACHABLE,
    DEFAULT_STORE, DEFAULT_TIMEOUTS, DEFAULT_TRANSPORT, DEFAULT_VENDOR, DEFAULT_WORKERS, check_comment,
    check_confirmed_minutes, default_username,
)
from hssh.paths import path_inside, validate_device_name
from hssh.screen import is_terminal, terminal_safe
from hssh.store import Store, operation_dict

TRANSPORT_CHOICES = ("ssh", "openssh", "netconf", "telnet")
HOST_KEY_CHOICES = ("accept-new", "strict", "off")

# Config-file keys with the orchestrator's default; None means "no value".
CONFIG_DEFAULTS: dict[str, Any] = {
    "transport": DEFAULT_TRANSPORT, "vendor": DEFAULT_VENDOR, "user": None, "workers": DEFAULT_WORKERS,
    "connect_timeout": DEFAULT_TIMEOUTS.connect, "session_timeout": DEFAULT_TIMEOUTS.setup,
    "command_timeout": DEFAULT_TIMEOUTS.command, "commit_timeout": DEFAULT_TIMEOUTS.commit, "retries": DEFAULT_POLICY.retries,
    "retry_pause": DEFAULT_POLICY.retry_pause, "host_key_policy": DEFAULT_HOST_KEY_POLICY, "probe": DEFAULT_PROBE,
    "skip_unreachable": DEFAULT_SKIP_UNREACHABLE,
    "cooldown": DEFAULT_SAFETY.cooldown_seconds, "rate_limit": DEFAULT_SAFETY.rate_limit,
}
EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_SKIPPED, EXIT_INCOMPLETE, EXIT_INTERRUPTED = 0, 1, 2, 3, 4, 130
# Worst first, for the exit code of a --every watch.
EXIT_ORDER = (EXIT_INTERRUPTED, EXIT_INCOMPLETE, EXIT_USAGE, EXIT_FAILED, EXIT_SKIPPED, EXIT_OK)
MAX_EVERY_SECONDS = 86400


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise SystemExit(f"ERROR: {message}")


def default_devices_path() -> str:
    home = Path.home() / ".h-ssh" / "devices.csv"
    return str(home) if home.exists() else "devices.csv"


def seconds_arg(text: str) -> float:
    """--every: one second to a day."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"takes seconds, not {text!r}") from None
    if not 1 <= value <= MAX_EVERY_SECONDS:
        raise argparse.ArgumentTypeError(f"takes 1 to {MAX_EVERY_SECONDS} seconds (a day), not {text}")
    return value


def count_arg(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"takes a whole number, not {text!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"takes 1 or more, not {text}")
    return value


def build_parser() -> _Parser:
    p = _Parser(prog="h-ssh", description="Operational commands and configuration changes across fleets of network devices.")
    p.add_argument("hosts", nargs="*", metavar="HOST", help="bare host or name:host[:vendor][:port]; with any target given the inventory is not read")
    p.add_argument("--target", action="append", metavar="SPEC", help="inline target name:host[:vendor][:port] (repeatable)")
    p.add_argument("--devices", metavar="CSV", help=f"inventory (default: {default_devices_path()})")
    p.add_argument("--transport", choices=TRANSPORT_CHOICES, help=f"transport for targets that name none (default: {DEFAULT_TRANSPORT})")
    p.add_argument("--vendor", metavar="NAME", help=f"vendor for targets that name none (default: {DEFAULT_VENDOR})")
    p.add_argument("--user", metavar="NAME", help="username (default: config, then the login name)")
    p.add_argument("--config", metavar="FILE", help="defaults file (default: ~/.h-ssh/config)")
    p.add_argument("--run", metavar="FILE", help="YAML or JSON run file; a typed flag wins over it")

    mode = p.add_argument_group("mode")
    mode.add_argument("-sC", "--show-command", metavar="CMD", help="one show command on every target")
    mode.add_argument("--batch", metavar="FILE", help="show commands, one per line")
    mode.add_argument("--profile", metavar="NAME", help="a named command set, run like --batch")
    mode.add_argument("-eC", "--edit-command", metavar="TEXT", help="configuration lines for every target")
    mode.add_argument("-eB", "--edit-file", metavar="FILE", help="configuration file for every target")
    mode.add_argument("-eD", "--edit-dir", metavar="DIR", help="one <NAME>.set configuration file per target")
    mode.add_argument("--confirm", action="store_true", help="confirm the pending commit on every target")
    mode.add_argument("--commit-status", action="store_true", help="show the commit history")

    edit = p.add_argument_group("edit")
    edit.add_argument("-y", "--yes", action="store_true", help="apply; without it an edit is a dry run")
    edit.add_argument("--commit-confirmed", type=int, nargs="?", const=DEFAULT_CONFIRMED_MINUTES, metavar="MIN",
                      help=f"commit confirmed, minutes (default {DEFAULT_CONFIRMED_MINUTES})")
    edit.add_argument("--comment", metavar="TEXT", help="commit comment")
    edit.add_argument("--allow-missing", action="store_true", help="-eD: skip the targets that have no <NAME>.set")
    edit.add_argument("--synchronize", action="store_true",
                      help="commit synchronize on the edit or the confirm (dual routing engines; NETCONF only)")

    behaviour = p.add_argument_group("behaviour")
    behaviour.add_argument("--workers", type=int)
    behaviour.add_argument("--retries", type=int)
    behaviour.add_argument("--retry-pause", type=int, metavar="SECONDS")
    behaviour.add_argument("--connect-timeout", type=int, metavar="SECONDS")
    behaviour.add_argument("--session-timeout", type=int, metavar="SECONDS",
                           help="seconds for the session setup after the SSH banner: key exchange, login, NETCONF hello")
    behaviour.add_argument("--command-timeout", type=int, metavar="SECONDS")
    behaviour.add_argument("--commit-timeout", type=int, metavar="SECONDS")
    behaviour.add_argument("--host-key-policy", choices=HOST_KEY_CHOICES)
    behaviour.add_argument("--probe", dest="probe", action="store_const", const=True, default=None, help="reachability check before the run")
    behaviour.add_argument("--no-probe", dest="probe", action="store_const", const=False)
    behaviour.add_argument("--skip-unreachable", action="store_const", const=True, default=None,
                           help="edits: go on without the devices the probe found dead; they are skipped")
    behaviour.add_argument("--cooldown", type=int, metavar="SECONDS")
    behaviour.add_argument("--rate-limit", type=int, metavar="PER_MINUTE")
    behaviour.add_argument("--safety-file", metavar="FILE", help="safety gate state (or HSSH_SAFETY_FILE); off without one")
    behaviour.add_argument("--every", type=seconds_arg, metavar="SECONDS",
                           help="watch: run the reads again every SECONDS and print, per tick, what changed since the last kept run")
    behaviour.add_argument("--times", type=count_arg, metavar="N", help="with --every: stop after N ticks")

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="the report as JSON")
    out.add_argument("--raw", action="store_true", help="device output only")
    out.add_argument("-v", "--verbose", action="store_true")
    out.add_argument("--store", metavar="FILE", help=f"SQLite result store (or HSSH_STORE; default: ./{DEFAULT_STORE})")
    out.add_argument("--no-store", action="store_true")
    out.add_argument("--audit-log", metavar="FILE", help="JSONL audit trail of changes (or HSSH_AUDIT_LOG)")
    out.add_argument("--log", metavar="FILE")
    out.add_argument("--save-output", metavar="DIR")
    out.add_argument("--list-profiles", action="store_true")
    return p


def typed_dests(parser: argparse.ArgumentParser, argv: list[str]) -> set[str]:
    """Destinations the command line gave, whatever their value, so a typed flag wins over a run file: argv parsed again with every default suppressed."""
    saved = [(action, action.default) for action in parser._actions]
    try:
        for action, _ in saved:
            action.default = argparse.SUPPRESS
        return set(vars(parser.parse_intermixed_args(argv)))
    finally:
        for action, default in saved:
            action.default = default


def apply_config_defaults(args: argparse.Namespace, config: dict[str, str]) -> None:
    """Fill options the command line and run file left unset: config file, then the built-in default."""
    if args.user is None:
        args.user = os.environ.get("HSSH_USER") or None
    args.store = settings.store_path(args.store, config)
    args.audit_log = settings.audit_log_path(args.audit_log, config)
    args.safety_file = settings.safety_file_path(args.safety_file, config)
    for key, fallback in CONFIG_DEFAULTS.items():
        if getattr(args, key, None) is not None:
            continue
        if key not in config:
            setattr(args, key, fallback)
            continue
        value: Any = config[key]
        if isinstance(fallback, bool):
            value = value.lower() in ("yes", "true", "1", "on")
        elif isinstance(fallback, int):
            value = int(value)
        setattr(args, key, value)


def resolve_targets(args: argparse.Namespace) -> tuple[Target, ...]:
    if args.target:
        targets = [parse_target(s, args.transport, args.vendor) for s in args.target]
    else:
        targets = load_devices_csv(args.devices or default_devices_path(), args.transport, args.vendor)
    for target in targets:
        validate_device_name(target.name)
    check_unique(targets)
    return tuple(targets)


def resolve_mode(args: argparse.Namespace) -> Mode:
    chosen = [m for m, given in (("show", args.show_command), ("batch", args.batch or args.batch_commands),
                                 ("edit", args.edit_command or args.edit_file or args.edit_dir),
                                 ("confirm", args.confirm), ("commit_status", args.commit_status)) if given]
    if len(chosen) != 1:
        raise ValueError("give exactly one of -sC, --batch/--profile, -eC/-eB/-eD, --confirm, --commit-status")
    if args.edit_dir and (args.edit_command or args.edit_file):
        raise ValueError("-eD goes alone: -eC or -eB beside it is refused")
    if args.allow_missing and not args.edit_dir:
        raise ValueError("--allow-missing goes with -eD: it skips the targets that have no <NAME>.set")
    if args.skip_unreachable and chosen[0] != "edit":
        raise ValueError("--skip-unreachable goes with an edit (-eC, -eB, -eD)")
    if chosen[0] != "edit":
        for flag, given in (("-y", args.yes), ("--comment", args.comment is not None),
                            ("--commit-confirmed", args.commit_confirmed is not None)):
            if given:
                raise ValueError(f"{flag} goes with an edit (-eC, -eB, -eD); it would do nothing here")
    if args.synchronize and chosen[0] not in ("edit", "confirm"):
        raise ValueError("--synchronize goes with an edit (-eC, -eB, -eD) or --confirm; it would do nothing here")
    if args.every is not None and chosen[0] not in ("show", "batch"):
        raise ValueError("--every repeats reads (-sC, --batch, --profile), not edits, confirms or the commit status")
    return chosen[0]


def check_flags(args: argparse.Namespace) -> None:
    """Pairings that would make a flag do nothing, or the output unreadable, refused before anything runs."""
    if args.times is not None and args.every is None:
        raise ValueError("--times goes with --every")
    if args.every is not None and args.no_store:
        raise ValueError("--every compares every tick with the last kept run through the store; drop --no-store")
    if args.every is not None and (args.json or args.raw):
        raise ValueError("--every prints one line per tick and what changed, not --json or --raw output; "
                         "every tick is in the store for h-ssh-store")
    if args.no_store and "store" in args.typed:
        raise ValueError("--no-store and --store contradict each other")
    if args.raw and args.json:
        raise ValueError("--raw and --json are mutually exclusive")
    if args.raw and args.verbose:
        raise ValueError("--raw and -v are mutually exclusive")
    if args.save_output and Path(args.save_output).exists() and not Path(args.save_output).is_dir():
        raise ValueError(f"--save-output {args.save_output} exists and is not a directory")
    if args.user and (why := plain_line(args.user)):
        raise ValueError(f"the username has {why}; a username is plain text")


def check_commands(commands: Sequence[str], source: str) -> None:
    """Each command is one line of plain text: a line break would run two commands, a NUL or an ESC is not text."""
    for command in commands:
        if why := plain_line(command):
            raise ValueError(f"{source}: {command!r} has {why}; a command is one line of plain text")


def plain_line(text: str) -> str | None:
    """What keeps `text` from being one line of plain text, named, or None."""
    if "\n" in text or "\r" in text:
        return "a line break"
    found = control_line(text)
    return found[2] if found else None


def resolve_credentials(args: argparse.Namespace) -> Credentials:
    """The user as resolved (flag, run file, HSSH_USER, config), else the login name; the password from HSSH_PASSWORD or a prompt."""
    user = args.user or default_username()
    password = os.environ.get("HSSH_PASSWORD")
    if password is None and sys.stdin.isatty():
        password = getpass.getpass(f"Password for {user}: ") or None
    return Credentials(username=user, password=password)


def target_dialects(targets: Sequence[Target]) -> dict[str, Dialect]:
    """Each target's dialect by target name; a target without a driver is refused here, before the password."""
    registry = Registry()
    registry.load_entry_points()
    try:
        return {target.name: registry.resolve(target).dialect for target in targets}
    except Fault as f:
        raise ValueError(f.detail) from f


def payload_lines(text: str, prefixes: Sequence[str]) -> tuple[str, ...]:
    """The configuration lines to send: blank lines and full-line comments dropped, an inline "#" kept."""
    lines = (line.rstrip() for line in text.splitlines())
    return tuple(line for line in lines if line.strip() and not line.lstrip().startswith(tuple(prefixes)))


# C0 controls but Tab, DEL, C1 controls and lone surrogates; a payload keeps its line breaks, nothing else of these.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff]")
_CONTROL_NAMES = {"\r": "a carriage return", "\x00": "a NUL", "\x1b": "an ESC", "\x7f": "a DEL"}

def control_line(text: str) -> tuple[int, str, str] | None:
    """(line number, the line, what) for the first control character in a payload, or None; a lone surrogate is a byte that was not UTF-8."""
    for number, line in enumerate(text.split("\n"), 1):
        if m := _CONTROL.search(line.rstrip("\r")):
            ch = m.group()
            if "\ud800" <= ch <= "\udfff":
                return number, line, f"a byte that is not UTF-8 {ch!r}"
            return number, line, _CONTROL_NAMES.get(ch, f"a control character {ch!r}")
    return None


def set_files(args: argparse.Namespace, targets: Sequence[Target]) -> dict[str, Path]:
    """-eD: the <NAME>.set of each target; the targets without one end the run, or are skipped with --allow-missing."""
    base = Path(args.edit_dir)
    if not base.is_dir():
        raise ValueError(f"-eD {base}: not a directory")
    files = {t.name: path_inside(base, f"{validate_device_name(t.name)}.set") for t in targets}
    missing = [name for name, path in files.items() if not path.is_file()]
    if missing and not args.allow_missing:
        raise ValueError(f"-eD {base}: no <NAME>.set for {len(missing)} of {len(targets)} device(s): "
                         f"{listed(missing)}. Nothing was sent; --allow-missing skips them.")
    if missing:
        print(f"Skipping {len(missing)} device(s) without a set file: {listed(missing)}", file=sys.stderr)
    found = {name: path for name, path in files.items() if name not in missing}
    if not found:
        raise ValueError(f"-eD {base}: no device has a set file; nothing to do")
    return found


def listed(names: Sequence[str]) -> str:
    return ", ".join(names[:20]) + (" …" if len(names) > 20 else "")


def edit_payloads(args: argparse.Namespace, targets: Sequence[Target]) -> dict[str, tuple[str, ...]]:
    """Each target's configuration lines, stripped and checked by its own dialect, read before the password."""
    dialects = target_dialects(targets)
    if args.edit_dir:
        sources = {name: (str(path), path.read_text(encoding="utf-8-sig")) for name, path in set_files(args, targets).items()}
    else:
        text = args.edit_command or Path(args.edit_file).read_text(encoding="utf-8-sig")
        source = "-eC" if args.edit_command else f"-eB {args.edit_file}"
        sources = {t.name: (source, text) for t in targets}
    payloads, empty = {}, []
    for name, (source, text) in sources.items():
        if found := control_line(text):
            number, line, what = found
            raise ValueError(f"{source}: line {number} has {what} ({line!r}); a payload is plain text")
        lines = payload_lines(text, dialects[name].comment_prefixes)
        if not lines:
            empty.append(source)
            continue
        if why := dialects[name].check_edit(list(lines)):
            raise ValueError(f"{source}: {why}")
        payloads[name] = lines
    if empty:
        raise ValueError(f"nothing but blank lines and comments in {listed(sorted(set(empty)))}. Nothing was sent")
    return payloads


def check_edit_args(args: argparse.Namespace, edit: EditSettings) -> None:
    """The edit settings a run cannot go on with, said before the password is asked."""
    if edit.confirmed_minutes is not None and (why := check_confirmed_minutes(edit.confirmed_minutes)):
        raise ValueError(why)
    if edit.comment is not None and (why := check_comment(edit.comment)):
        raise ValueError(why)
    if args.run and edit.apply and edit.confirmed_minutes is None:
        raise ValueError(f"run file '{args.run}' applies changes without a rollback timer: set commit_confirmed "
                         "(minutes) in the file or pass --commit-confirmed, or drop yes for a dry run")


def build_spec(args: argparse.Namespace, argv: list[str]) -> RunSpec:
    mode = resolve_mode(args)
    check_flags(args)
    targets = resolve_targets(args)
    commands: tuple[str, ...] = ()
    payloads: dict[str, tuple[str, ...]] = {}
    if mode == "show":
        commands = (args.show_command,)
        check_commands(commands, "-sC")
    elif mode == "batch":
        commands = tuple(args.batch_commands or profiles.read_commands(Path(args.batch)))
        check_commands(commands, f"--batch {args.batch}" if args.batch else "commands")
    elif mode == "edit":
        payloads = edit_payloads(args, targets)
    edit = None
    if mode == "edit":
        edit = EditSettings(apply=args.yes, confirmed_minutes=args.commit_confirmed, comment=args.comment,
                            synchronize=args.synchronize)
        check_edit_args(args, edit)
    elif mode == "confirm" and args.synchronize:
        edit = EditSettings(apply=True, synchronize=True)
    safety = None
    if args.safety_file:
        safety = SafetySettings(cooldown_seconds=args.cooldown, rate_limit=args.rate_limit, safety_file=args.safety_file)
    return RunSpec(
        targets=targets, mode=mode, commands=commands, payloads=payloads,
        credentials=resolve_credentials(args),
        timeouts=Timeouts(connect=args.connect_timeout, setup=args.session_timeout, command=args.command_timeout,
                          commit=args.commit_timeout),
        workers=args.workers, host_key_policy=args.host_key_policy, probe=args.probe,
        skip_unreachable=args.skip_unreachable, edit=edit,
        policy=PolicySettings(retries=args.retries, retry_pause=args.retry_pause),
        safety=safety,
        recording=RecordSettings(store_path=None if args.no_store else args.store,
                                 audit_log_path=args.audit_log, log_path=args.log,
                                 save_output_path=args.save_output, argv=tuple(argv),
                                 origin="h-ssh", version=package_version()),
    )


def render(report: RunReport, args: argparse.Namespace, out=sys.stdout) -> None:
    if args.json:
        print(json.dumps(report_dict(report), indent=2), file=out)
        return
    safe = terminal_safe if is_terminal(out) else (lambda text: text)
    for tr in report.results:
        if tr.status == "skipped":
            faults = [op.outcome.detail for op in tr.operations if isinstance(op.outcome, Fault)]
            print(f"{tr.target.name}: SKIPPED" + (f": {safe(faults[0])}" if faults else ""), file=out)
            continue
        for op in tr.operations:
            if isinstance(op.outcome, Fault) and op.command == "close":
                print(f"WARNING: {tr.target.name}: close failed: {op.outcome.detail}", file=sys.stderr)
                continue
            if isinstance(op.outcome, Fault):
                print(f"{tr.target.name}: FAIL {op.command}: {op.outcome.kind.name} {safe(op.outcome.detail)}", file=out)
                continue
            if not args.raw:
                print(f"=== {tr.target.name} ({tr.target.host}) {op.command} [{op.elapsed_ms} ms]", file=out)
            print(safe(op.outcome.output), file=out)
    if report.interrupted:
        print(f"Interrupted. Completed {report.ok + report.failed} of {len(report.results)} device(s).", file=sys.stderr)
    if not args.raw:
        print(verdict(report), file=out)
        for name, minutes in report.pending.items():
            print(f"pending commit on {name}: rolls back in {minutes} minutes", file=out)
        if report.pending:
            print(f"confirm with: {confirm_command(args)}", file=out)
    elif report.failed or report.skipped or report.not_kept:
        print(verdict(report), file=sys.stderr)


def verdict(report: RunReport) -> str:
    """The run's counts; what was skipped is named by reason, and a record not kept is said, so a run that did not reach every device never reads as all OK."""
    line = f"run {report.run_id}: {report.ok} ok, {report.failed} failed, {report.skipped} skipped"
    reasons: dict[str, int] = {}
    for tr in report.results:
        if tr.status == "skipped":
            faults = [op.outcome.detail for op in tr.operations if isinstance(op.outcome, Fault)]
            reason = faults[0] if faults else "not started"
            reasons[reason] = reasons.get(reason, 0) + 1
    if reasons:
        line += " (" + ", ".join(f"{n} {reason}" for reason, n in reasons.items()) + ")"
    if report.not_kept:
        line += f"; {report.not_kept} record(s) not kept"
    return line


def confirm_command(args: argparse.Namespace) -> str:
    """The command that confirms this run's pending commits: the same program, user and targets as typed."""
    prog = sys.argv[0] if sys.argv and sys.argv[0].endswith(".py") else "h-ssh"
    words = [prog, "--confirm"]
    if args.user:
        words += ["--user", args.user]
    if args.target:
        words += args.hosts + [w for spec in args.target if spec not in args.hosts for w in ("--target", spec)]
    else:
        words += ["--devices", args.devices or default_devices_path()]
    for flag in ("transport", "vendor"):
        if flag in args.typed:
            words += [f"--{flag}", getattr(args, flag)]
    return " ".join(shlex.quote(w) for w in words)


def summary_line(report: RunReport) -> str:
    """One JSON line for stderr: the counts a pipeline reads."""
    elapsed_ms = int((datetime.fromisoformat(report.finished) - datetime.fromisoformat(report.started)).total_seconds() * 1000)
    counts = {"targets": len(report.results), "ok": report.ok, "fail": report.failed, "skipped": report.skipped}
    if report.interrupted:
        counts["interrupted"] = True
    if report.not_kept:
        counts["not_kept"] = report.not_kept
    return "[h-ssh] " + json.dumps({**counts, "elapsed_ms": elapsed_ms, "mode": report.mode})


def report_dict(report: RunReport) -> dict[str, Any]:
    """The report as JSON data; each operation is the store's operation_dict, so --json, saved batches and the store rows agree."""
    return {
        "run_id": report.run_id, "mode": report.mode, "started": report.started, "finished": report.finished,
        "ok": report.ok, "failed": report.failed, "skipped": report.skipped, "interrupted": report.interrupted,
        "not_kept": report.not_kept, "pending": dict(report.pending),
        "results": [{"target": tr.target.name, "host": tr.target.host, "status": tr.status,
                     "operations": [operation_dict(op) for op in tr.operations]} for tr in report.results],
    }


def exit_code(report: RunReport) -> int:
    if report.interrupted:
        return EXIT_INTERRUPTED
    if report.not_kept:
        return EXIT_INCOMPLETE
    if report.failed:
        return EXIT_FAILED
    if report.skipped:
        return EXIT_SKIPPED
    return EXIT_OK


def worst(a: int, b: int) -> int:
    return min(a, b, key=EXIT_ORDER.index)


Rows = dict[tuple[str, int], dict[str, Any]]


def read_rows(store_path: str, run_id: int) -> Rows:
    """A kept run's operation rows by (target, seq), through the store's reader."""
    store = Store(store_path, readonly=True)
    try:
        return {(row["target"], row["seq"]): dict(row) for row in store.results(run_id=run_id)}
    finally:
        store.close()


def watch_tick(tick: int, report: RunReport, rows: Rows, previous: Rows | None, out=sys.stdout) -> None:
    """One line per tick and, for every device whose reply changed since the last kept run, a unified diff."""
    safe = terminal_safe if is_terminal(out) else (lambda text: text)
    stamp = time.strftime("%H:%M:%S")
    counts = f"{report.ok} OK, {report.failed} failed" + (f", {report.skipped} skipped" if report.skipped else "")
    kept = f"run {report.run_id}" + (f", {report.not_kept} record(s) not kept" if report.not_kept else "")
    if previous is None:
        print(f"tick {tick} {stamp}: {counts}; baseline {kept}", file=out, flush=True)
        return
    changed = [(rows[key], previous.get(key)) for key in sorted(rows)
               if key not in previous or any(previous[key][c] != rows[key][c] for c in ("ok", "output", "fault", "detail"))]
    print(f"tick {tick} {stamp}: {counts}, {len(changed)} changed; {kept}", file=out, flush=True)
    for row, before in changed:
        head = f"--- {row['target']}: {(row['command'] or '').splitlines()[0][:60] if row['command'] else ''}"
        if before is None:
            print(safe(head + ": new"), file=out)
            continue
        if row["ok"] != before["ok"]:
            detail = (row["detail"] or "").splitlines()[0] if row["detail"] else ""
            head += f": {'OK' if before['ok'] else 'FAIL'} -> {'OK' if row['ok'] else 'FAIL'}" + (f" ({detail})" if detail else "")
        print(safe(head), file=out)
        diff = difflib.unified_diff((before["output"] or "").splitlines(), (row["output"] or "").splitlines(),
                                    fromfile=before["started"][:19], tofile=row["started"][:19], lineterm="", n=1)
        for line in diff:
            print("  " + safe(line), file=out)


def watch(args: argparse.Namespace, spec: RunSpec, runner: Runner, reader: Callable[[str, int], Rows] | None = None) -> int:
    """--every: a run per tick, each compared with the last kept run through the store; the exit code is the worst tick's."""
    reader = reader or read_rows
    code, previous, kept = EXIT_OK, None, 0
    try:
        for tick in range(1, (args.times or sys.maxsize) + 1):
            if tick > 1:
                time.sleep(args.every)
            report = runner(spec)
            try:
                rows = reader(args.store, report.run_id)
            except OSError as e:
                print(f"ERROR: --every: store {args.store}: {e}; a watch keeps all its ticks in one store, so it stops here",
                      file=sys.stderr)
                return worst(code, EXIT_USAGE)
            watch_tick(tick, report, rows, previous)
            print(summary_line(report), file=sys.stderr)
            code, previous = worst(code, exit_code(report)), rows
            kept += not report.not_kept
            if report.interrupted:
                break
        return code
    except KeyboardInterrupt:
        print(f"\nInterrupted. {kept} tick(s) kept in the store.", file=sys.stderr)
        return EXIT_INTERRUPTED


def main(argv: list[str] | None = None, runner: Runner = run_spec) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    args = parser.parse_intermixed_args(argv)
    typed = typed_dests(parser, argv)
    args.target = (list(args.hosts) + list(args.target or [])) or None
    args.batch_commands = None
    args.typed = typed
    if not args.verbose:
        quiet_library_logs()
        for name in LIBRARY_LOGGERS:
            logging.getLogger(name).setLevel(logging.CRITICAL)
    try:
        if args.list_profiles:
            print("\n".join(profiles.listing_lines()))
            return EXIT_OK
        if args.run:
            apply_run(args, validate_run(load_run_file(args.run), args.run), typed)
        if args.profile:
            args.batch = str(profiles.profile_path(args.profile))
        apply_config_defaults(args, load_config(args.config))
        spec = build_spec(args, argv)
    except (ValueError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return EXIT_USAGE
    try:
        if args.every is not None:
            return watch(args, spec, runner)
        report = runner(spec)
        render(report, args)
        print(summary_line(report), file=sys.stderr)
        return exit_code(report)
    except Fault as e:
        print(f"ERROR: {e.kind.name}: {e.detail}", file=sys.stderr)
        return EXIT_USAGE


def stdout_gone() -> None:
    """The reader of our output left (`| head`): park both streams on /dev/null so the interpreter's last flush has nothing to say."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        for stream in (sys.stdout, sys.stderr):
            os.dup2(devnull, stream.fileno())
    except (OSError, ValueError, AttributeError):
        pass


def main_sync() -> None:
    try:
        code = main()
        sys.stdout.flush()
    except KeyboardInterrupt:
        code = EXIT_INTERRUPTED
    except BrokenPipeError:
        stdout_gone()
        code = EXIT_OK
    raise SystemExit(code)
