"""The h-ssh command line: parse, resolve precedence, build one RunSpec, render the RunReport.

Precedence (section 3.1): flags, then run file, then profile, then ~/.h-ssh/config, then defaults.
The password is HSSH_PASSWORD or the prompt; there is no --password flag and no file carries one.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import shlex
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from hssh.drivers import Registry
from hssh.frontends import profiles
from hssh.frontends.fleet import (
    LIBRARY_LOGGERS, Runner, check_unique, load_devices_csv, parse_target, quiet_library_logs, run_spec,
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

TRANSPORT_CHOICES = ("ssh", "openssh", "netconf", "telnet")
HOST_KEY_CHOICES = ("accept-new", "strict", "off")
FORMAT_CHOICES = ("text", "json", "xml")

# Config-file keys with the orchestrator's default; None means "no value".
CONFIG_DEFAULTS: dict[str, Any] = {
    "transport": DEFAULT_TRANSPORT, "vendor": DEFAULT_VENDOR, "user": None, "workers": DEFAULT_WORKERS,
    "connect_timeout": DEFAULT_TIMEOUTS.connect, "session_timeout": DEFAULT_TIMEOUTS.setup,
    "command_timeout": DEFAULT_TIMEOUTS.command, "commit_timeout": DEFAULT_TIMEOUTS.commit, "retries": DEFAULT_POLICY.retries,
    "retry_pause": DEFAULT_POLICY.retry_pause, "host_key_policy": DEFAULT_HOST_KEY_POLICY, "probe": DEFAULT_PROBE,
    "skip_unreachable": DEFAULT_SKIP_UNREACHABLE,
    "cooldown": DEFAULT_SAFETY.cooldown_seconds, "rate_limit": DEFAULT_SAFETY.rate_limit,
    "store": None, "audit_log": None, "safety_file": None,
}
CREDENTIAL_KEYS = ("password", "passwd", "secret", "token", "pass")

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_SKIPPED, EXIT_INCOMPLETE, EXIT_INTERRUPTED = 0, 1, 2, 3, 4, 130
# Worst first, for the exit code of a --every watch.
EXIT_ORDER = (EXIT_INTERRUPTED, EXIT_INCOMPLETE, EXIT_USAGE, EXIT_FAILED, EXIT_SKIPPED, EXIT_OK)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        raise SystemExit(f"ERROR: {message}")


def config_path() -> Path:
    return Path.home() / ".h-ssh" / "config"


def default_devices_path() -> str:
    home = Path.home() / ".h-ssh" / "devices.csv"
    return str(home) if home.exists() else "devices.csv"


def load_config(path: str | None = None) -> dict[str, str]:
    """`key = value` lines with `#` comments; a missing file is empty, a credential key is refused."""
    p = Path(path) if path else config_path()
    if not p.is_file():
        return {}
    config: dict[str, str] = {}
    for n, line in enumerate(p.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            raise ValueError(f"{p}: line {n}: expected 'key = value', got {line!r}")
        key, value = line.split("=", 1)
        key = key.strip().lower().replace("-", "_")
        if key in CREDENTIAL_KEYS:
            raise ValueError(f"{p}: line {n}: '{key}' is not allowed, a config file never carries a credential")
        config[key] = value.strip().strip('"').strip("'")
    return config


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
    mode.add_argument("--format", choices=FORMAT_CHOICES, default=None, help="json or xml asks for structured data (NETCONF)")
    mode.add_argument("-eC", "--edit-command", metavar="TEXT", help="configuration lines for every target")
    mode.add_argument("-eB", "--edit-file", metavar="FILE", help="configuration file for every target")
    mode.add_argument("--confirm", action="store_true", help="confirm the pending commit on every target")
    mode.add_argument("--commit-status", action="store_true", help="show the commit history")

    edit = p.add_argument_group("edit")
    edit.add_argument("-y", "--yes", action="store_true", help="apply; without it an edit is a dry run")
    edit.add_argument("--commit-confirmed", type=int, nargs="?", const=DEFAULT_CONFIRMED_MINUTES, metavar="MIN",
                      help=f"commit confirmed, minutes (default {DEFAULT_CONFIRMED_MINUTES})")
    edit.add_argument("--comment", metavar="TEXT", help="commit comment")

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
    behaviour.add_argument("--safety-file", metavar="FILE")
    behaviour.add_argument("--every", type=float, metavar="SECONDS", help="repeat the run and print what changed")
    behaviour.add_argument("--times", type=int, help="with --every: stop after this many runs")

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="the report as JSON")
    out.add_argument("--raw", action="store_true", help="device output only")
    out.add_argument("-v", "--verbose", action="store_true")
    out.add_argument("--store", metavar="FILE", help=f"SQLite result store (default: ./{DEFAULT_STORE})")
    out.add_argument("--no-store", action="store_true")
    out.add_argument("--audit-log", metavar="FILE", default=os.environ.get("HSSH_AUDIT_LOG") or None)
    out.add_argument("--log", metavar="FILE")
    out.add_argument("--save-output", metavar="DIR")
    out.add_argument("--list-profiles", action="store_true")
    return p


def typed_dests(parser: argparse.ArgumentParser, argv: list[str]) -> set[str]:
    """Destinations the command line gave, whatever their value, so a typed flag wins over a run file."""
    typed = set()
    for action in parser._actions:
        if any(opt in argv or any(a.startswith(opt + "=") for a in argv) for opt in action.option_strings):
            typed.add(action.dest)
    if any(not a.startswith("-") for a in argv):
        typed.add("hosts")
    return typed


def apply_config_defaults(args: argparse.Namespace, config: dict[str, str]) -> None:
    """Fill options the command line and run file left unset: config file, then the built-in default."""
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
    check_unique(targets)
    return tuple(targets)


def resolve_mode(args: argparse.Namespace) -> Mode:
    chosen = [m for m, given in (("show", args.show_command), ("batch", args.batch or args.batch_commands),
                                 ("edit", args.edit_command or args.edit_file), ("confirm", args.confirm),
                                 ("commit_status", args.commit_status)) if given]
    if len(chosen) != 1:
        raise ValueError("give exactly one of -sC, --batch/--profile, -eC/-eB, --confirm, --commit-status")
    if args.skip_unreachable and chosen[0] != "edit":
        raise ValueError("--skip-unreachable goes with an edit (-eC, -eB)")
    if chosen[0] == "show" and args.format not in (None, "text"):
        return "structured"
    return chosen[0]


def resolve_credentials(args: argparse.Namespace) -> Credentials:
    """The user from flags or config, else the login name; the password from HSSH_PASSWORD or a terminal prompt."""
    user = args.user or os.environ.get("HSSH_USER") or default_username()
    password = os.environ.get("HSSH_PASSWORD")
    if password is None and sys.stdin.isatty():
        password = getpass.getpass(f"Password for {user}: ") or None
    return Credentials(username=user, password=password)


def comment_prefixes(targets: Sequence[Target]) -> tuple[str, ...]:
    """What starts a full-line comment for every target's dialect; "#" where a dialect says nothing."""
    registry = Registry()
    registry.load_entry_points()
    common: set[str] | None = None
    for target in targets:
        try:
            prefixes = set(getattr(registry.resolve(target).dialect, "comment_prefixes", ("#",)))
        except Fault:
            prefixes = {"#"}
        common = prefixes if common is None else common & prefixes
    return tuple(sorted(common or ()))


def payload_lines(text: str, prefixes: Sequence[str]) -> tuple[str, ...]:
    """The configuration lines to send: blank lines and full-line comments dropped, an inline "#" kept."""
    lines = (line.rstrip() for line in text.splitlines())
    return tuple(line for line in lines if line.strip() and not line.lstrip().startswith(tuple(prefixes)))


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
    targets = resolve_targets(args)
    commands: tuple[str, ...] = ()
    config_lines: tuple[str, ...] = ()
    if mode in ("show", "structured"):
        commands = (args.show_command,)
    elif mode == "batch":
        commands = tuple(args.batch_commands or profiles.read_commands(Path(args.batch)))
    elif mode == "edit":
        text = args.edit_command or Path(args.edit_file).read_text(encoding="utf-8-sig")
        config_lines = payload_lines(text, comment_prefixes(targets))
    edit = None
    if mode == "edit":
        edit = EditSettings(apply=args.yes, confirmed_minutes=args.commit_confirmed, comment=args.comment)
        check_edit_args(args, edit)
    safety = None
    if args.safety_file:
        safety = SafetySettings(cooldown_seconds=args.cooldown, rate_limit=args.rate_limit, safety_file=args.safety_file)
    return RunSpec(
        targets=targets, mode=mode, commands=commands, config_lines=config_lines,
        format=args.format if mode == "structured" else None,
        credentials=resolve_credentials(args),
        timeouts=Timeouts(connect=args.connect_timeout, setup=args.session_timeout, command=args.command_timeout,
                          commit=args.commit_timeout),
        workers=args.workers, host_key_policy=args.host_key_policy, probe=args.probe,
        skip_unreachable=args.skip_unreachable, edit=edit,
        policy=PolicySettings(retries=args.retries, retry_pause=args.retry_pause),
        safety=safety,
        recording=RecordSettings(store_path=None if args.no_store else (args.store or DEFAULT_STORE),
                                 audit_log_path=args.audit_log, log_path=args.log,
                                 save_output_path=args.save_output, argv=tuple(argv)),
    )


def render(report: RunReport, args: argparse.Namespace, out=sys.stdout) -> None:
    if args.json:
        print(json.dumps(report_dict(report), indent=2), file=out)
        return
    for tr in report.results:
        if tr.status == "skipped":
            faults = [op.outcome.detail for op in tr.operations if isinstance(op.outcome, Fault)]
            print(f"{tr.target.name}: SKIPPED" + (f": {faults[0]}" if faults else ""), file=out)
            continue
        for op in tr.operations:
            if isinstance(op.outcome, Fault) and op.command == "close":
                print(f"WARNING: {tr.target.name}: close failed: {op.outcome.detail}", file=sys.stderr)
                continue
            if isinstance(op.outcome, Fault):
                print(f"{tr.target.name}: FAIL {op.command}: {op.outcome.kind.name} {op.outcome.detail}", file=out)
                continue
            if not args.raw:
                print(f"=== {tr.target.name} ({tr.target.host}) {op.command} [{op.elapsed_ms} ms]", file=out)
            print(op.outcome.output, file=out)
    if not args.raw:
        print(f"run {report.run_id}: {report.ok} ok, {report.failed} failed, {report.skipped} skipped", file=out)
        for name, minutes in report.pending.items():
            print(f"pending commit on {name}: rolls back in {minutes} minutes", file=out)
        if report.pending:
            print(f"confirm with: {confirm_command(args)}", file=out)


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
    def outcome(op) -> dict[str, Any]:
        if isinstance(op.outcome, Fault):
            return {"ok": False, "fault": op.outcome.kind.name, "detail": op.outcome.detail}
        return {"ok": True, "output": op.outcome.output, "data": op.outcome.data}

    return {
        "run_id": report.run_id, "mode": report.mode, "started": report.started, "finished": report.finished,
        "ok": report.ok, "failed": report.failed, "skipped": report.skipped, "interrupted": report.interrupted,
        "not_kept": report.not_kept, "pending": dict(report.pending),
        "results": [{"target": tr.target.name, "host": tr.target.host, "status": tr.status,
                     "operations": [{"command": op.command, "started": op.started, "elapsed_ms": op.elapsed_ms,
                                     **outcome(op)} for op in tr.operations]} for tr in report.results],
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


def changed_lines(previous: RunReport | None, current: RunReport) -> list[str]:
    """What differs per target and command since the previous report, for --every."""
    if previous is None:
        return []
    before = {(tr.target.name, op.command): op.outcome for tr in previous.results for op in tr.operations}
    lines = []
    for tr in current.results:
        for op in tr.operations:
            old = before.get((tr.target.name, op.command))
            if old != op.outcome:
                lines.append(f"{tr.target.name} {op.command}: changed")
    return lines


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
        if args.every is None:
            report = runner(spec)
            render(report, args)
            print(summary_line(report), file=sys.stderr)
            return exit_code(report)
        previous = None
        code = EXIT_OK
        for tick in range(args.times or sys.maxsize):
            if tick:
                time.sleep(args.every)
            report = runner(spec)
            print("\n".join(changed_lines(previous, report)) if previous else "", end="")
            render(report, args)
            print(summary_line(report), file=sys.stderr)
            code = worst(code, exit_code(report))
            previous = report
            if report.interrupted:
                break
        return code
    except Fault as e:
        print(f"ERROR: {e.kind.name}: {e.detail}", file=sys.stderr)
        return EXIT_USAGE


def main_sync() -> None:
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
