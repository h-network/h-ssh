"""Command-line interface for h-ssh."""

import argparse
import asyncio
import concurrent.futures
import contextlib
import difflib
import getpass
import signal
import json
import logging
import os
import re
import shlex
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from .core import (
    Target, load_devices_csv, load_config, get_config_path, parse_bare_target,
    resolve_command, resolve_structured,
    get_available_commands, read_command_file_lines, parse_inline_target,
    load_jobs, parse_jobs, resolve_target_port, check_unique,
    check_confirm_minutes, control_character, control_line, read_failure, is_file,
    comment_fault, COMMENT_RULE,

    path_inside, set_file_payload, comments_named,
)
from .runner import (run_for_target_async, is_connect_failure, RunResult, error_line, is_read, reads_only, save_name,
                     opens_session, DEFAULT_CONNECT_TIMEOUT)
from . import probe as probes
from .transports.connect import budget as connect_budget, where as host_port
from .drivers import results as R
from .runfile import load_run_file, validate_run, apply_run, edit_needs_timer
from . import profiles
from .safety import SafetyGate
from . import pool
from .audit import write_audit_entry, redact_values, secure_append, secure_write, probe_append
from .store import Store, StoreError, ENV_VAR as STORE_ENV, DEFAULT as STORE_DEFAULT, where as store_where
from .store import _identity as store_identity
from .screen import terminal_safe, is_terminal as _tty
from . import __version__
from . import drivers
# The worker ceiling and the open-file fitting are hssh.limits', shared with
# the library engine (hssh.fleet); the CLI's names for them stay.
from .limits import MAX_WORKERS, FDS_PER_WORKER, FDS_BASE, fit_workers_to_open_files  # noqa: F401
from .limits import MAX_PROBES, fit_probes_to_open_files



def list_vendors_lines():
    """`--list-vendors`: one line per driver, in the registry's order (the
    built-ins first), then the entry points that failed to load."""
    rows = []
    for name, d in drivers.DRIVERS.items():
        transport = d.transport.name + (" (frozen)" if d.transport.frozen else "")
        rows.append((name, ", ".join(d.aliases) or "-", transport, d.dialect.name,
                     ",".join(d.transport.formats), " ".join(sorted(d.supports)), drivers.SOURCES[name]))
    head = ("name", "aliases", "transport", "dialect", "formats", "supports", "source")
    widths = [max(len(r[i]) for r in rows + [head]) for i in range(len(head) - 1)]
    fmt = "  ".join("{:<%d}" % w for w in widths) + "  {}"
    lines = [fmt.format(*head)] + [fmt.format(*r) for r in rows]
    for ep, why in drivers.BROKEN.items():
        lines.append(f"broken entry point '{ep}': {why}")
    return lines



_RESULT_HEADER_KEYS = ("DEVICE:", "HOST:", "MODE:", "VENDOR:")


def strip_result_header(out_text: str, command: str = None) -> str:
    """Return just what the device said.

    The runner prefixes each result with DEVICE/HOST/MODE/VENDOR and a blank
    line, and text transports echo the command as '$ cmd'. Both are framing for
    the human-readable view; --raw wants neither.
    """
    # On "\n" alone: splitlines() also breaks on NEL, VT, FF and the Unicode
    # separators, and the join would turn each into LF, so the record would
    # no longer be the reply as it came.
    lines = out_text.split("\n")
    i = 0
    while i < len(lines) and lines[i].startswith(_RESULT_HEADER_KEYS):
        i += 1
    if i and i < len(lines) and not lines[i].strip():
        i += 1
    return strip_echo("\n".join(lines[i:]), command)


def strip_echo(text: str, command: str = None) -> str:
    """One command's reply without the '$ cmd' echo a text transport opens
    it with. A batch's replies have no runner header to lose, so a reply
    that opens like one ('MODE: active-standby') keeps that line."""
    lines = text.split("\n")
    # Only drop the echo when it is exactly the command we sent, so device
    # output that happens to start with '$ ' survives intact.
    if command and lines[0] == "$ %s" % command:
        lines = lines[1:]
    return "\n".join(lines).strip("\n")


def document_text(output) -> str:
    """One command's output as it is printed and diffed: a JSON reply (a dict,
    from --format json) pretty-printed, XML and text as they are."""
    if isinstance(output, str):
        return output
    return json.dumps(output, indent=2)



def resolve_workers(requested: int) -> int:
    """Clamp --workers to something a thread pool can honour."""
    try:
        n = int(requested)
    except (TypeError, ValueError):
        return 8
    return max(1, min(n, MAX_WORKERS))


MAX_SECONDS = 86400


def _seconds_arg(text: str) -> float:
    """--every SECONDS: one second to a day (MAX_SECONDS, the timeouts'
    ceiling too); fractions are allowed."""
    try:
        value = float(text)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"--every takes seconds, not {text!r}")
    if not value >= 1:
        raise argparse.ArgumentTypeError(f"--every takes 1 second or more, not {text}")
    if value > MAX_SECONDS:
        raise argparse.ArgumentTypeError(f"--every takes at most {MAX_SECONDS} seconds (a day), not {text}")
    return value


def _ms_arg(text: str) -> float:
    """--slow MS: milliseconds above 0, fractions allowed, up to a day's
    worth (the config file's `slow` is held to the same)."""
    try:
        value = float(text)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"--slow takes milliseconds, not {text!r}")
    if not 0 < value <= MAX_SECONDS * 1000:          # NaN is neither
        raise argparse.ArgumentTypeError(f"--slow takes milliseconds above 0, up to {MAX_SECONDS * 1000}, not {text}")
    return value


def _not_empty(text: str) -> str:
    """An argparse type for a flag that names a file, a directory, a user or
    a profile (and --comment): an empty value is refused, not taken for the
    flag left out (#140). `--audit-log "$AUDIT"` with the variable unset
    turned the HSSH_AUDIT_LOG audit trail off, `--config ''` read the
    default config, `--user ''` logged in as HSSH_USER."""
    if text == "":
        raise argparse.ArgumentTypeError("empty (an unset variable?); give it a value or leave the flag out")
    return text


def _comment_arg(text: str) -> str:
    """--comment TEXT, stripped: an empty one is refused as every flag's is
    (#140), and so is one Junos would not log as given (#146), here before
    the probe touches a box: only blanks, a line break (Junos keeps the last
    line alone), another control character, or more than 512 bytes (failed
    at every router's commit check, after its lock, load and diff)."""
    _not_empty(text)
    fault = comment_fault(text.strip())
    if fault:
        raise argparse.ArgumentTypeError(f"{text!r} {fault}; {COMMENT_RULE}")
    return text.strip()


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


class PromptClosed(Exception):
    """The operator ended the input at a credential prompt (Ctrl-D)."""


def _ask(prompt: str, secret: bool = False) -> str:
    """One credential prompt. The question goes to the terminal, never into
    redirected stdout; Ctrl-D is PromptClosed (one line, exit 2) instead of a
    traceback; and the first Ctrl-C ends the run: asyncio's own SIGINT
    handler would only cancel the task while the read goes on blocking, so
    Python's default handler is restored for the duration of the prompt."""
    previous = signal.getsignal(signal.SIGINT)
    try:
        signal.signal(signal.SIGINT, signal.default_int_handler)
    except (ValueError, OSError):            # not the main thread: keep what there is
        previous = None
    try:
        if secret:
            return getpass.getpass(prompt)
        print(prompt, end="", file=sys.stderr, flush=True)
        line = sys.stdin.readline()
        if not line:
            raise EOFError
        return line.strip()
    except EOFError:
        print(file=sys.stderr)
        raise PromptClosed(prompt.split(" ")[0].rstrip(":").lower())
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)


class _Parser(argparse.ArgumentParser):
    """argparse's error() prints the whole usage block before the one line
    that matters; on a 30-flag tool that buries it. One line, exit 2."""
    def error(self, message):
        self.exit(2, f"{self.prog}: error: {message} (see --help)\n")


def typed_dests(parser: argparse.ArgumentParser, argv) -> set:
    """The options argv gives, whatever their value: argv parsed again with
    every default suppressed, so only what was typed lands in the namespace.
    `--format text` or `--devices devices.csv` is typed though it is the
    default, and a run file must not take its place (#140). A bare host is
    `hosts`. The parser's defaults are put back as they were."""
    saved = [(action, action.default) for action in parser._actions]
    try:
        for action, _ in saved:
            action.default = argparse.SUPPRESS
        return set(vars(parser.parse_intermixed_args(argv)))
    finally:
        for action, default in saved:
            action.default = default



# Everything here may be set in ~/.h-ssh/config. The password may not: a config
# file on a shared host is the wrong home for a secret.
CONFIG_DEFAULTS = {
    "workers": 8,
    "session_timeout": 30,
    "connect_timeout": DEFAULT_CONNECT_TIMEOUT,
    "command_timeout": 20,
    "retries": 2,
    "transport": "ssh",
    "slow": float(probes.SLOW_MS),
}


TRANSPORT_CHOICES = ["junos", "ssh", "openssh", "telnet"]
# The floor a config-file value must reach; a flag has argparse for this.
CONFIG_FLOORS = {"workers": 1, "retries": 0, "session_timeout": 1, "connect_timeout": 1, "command_timeout": 1}
CONFIG_CEILINGS = {"workers": MAX_WORKERS, "session_timeout": MAX_SECONDS, "connect_timeout": MAX_SECONDS,
                   "command_timeout": MAX_SECONDS, "slow": MAX_SECONDS * 1000}
# `probe = no` skips the probe before every run, as --no-probe does for one (#127).
PROBE_WORDS = {"yes": True, "true": True, "on": True, "1": True, "no": False, "false": False, "off": False, "0": False}


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
        if isinstance(fallback, float):
            try:
                value = float(value)
            except (TypeError, ValueError):
                raise ValueError(f"{key} = {value!r} is not a number")
            if not value > 0:                    # NaN is not either
                raise ValueError(f"{key} = {value:g} is not above 0")
            if value > CONFIG_CEILINGS[key]:
                raise ValueError(f"{key} = {value:g} is above {CONFIG_CEILINGS[key]}")
        elif isinstance(fallback, int):
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
    word = str(config.get("probe", "yes")).strip().lower()
    if word not in PROBE_WORDS:
        raise ValueError(f"probe = {word!r} is not yes or no")
    args.probe_by_config = PROBE_WORDS[word]


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


def build_confirm_command(user, target_specs, devices: str, transport: str, bare=()) -> str:
    """The command that confirms this run's commit-confirmed.

    Rebuilt from the run's own arguments, so it reaches the same devices as
    the same user, started the same way: the targets as typed (bare ones
    stay bare, --target ones keep the flag; a job's edit targets, rebuilt),
    or else the inventory file. --transport is kept only when it names a
    transport that can confirm a commit.
    """
    cmd = [shlex.quote(confirm_program()) + ' -eC "commit"']
    if user:
        cmd.append("--user " + shlex.quote(user))
    if target_specs:
        cmd.extend(shlex.quote(spec) if spec in bare else "--target " + shlex.quote(spec)
                   for spec in target_specs)
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


def comment_prefixes(vendor: str) -> tuple:
    """What starts a full-line comment in an edit payload for this vendor's
    dialect: `#`, and `!` for an IOS-shaped one. `#` alone for a vendor name
    the check further down reports as unknown."""
    try:
        return drivers.get(vendor).dialect.comment_prefixes
    except ValueError:
        return ("#",)


def nothing_to_apply(text: str, targets) -> str:
    """Where `text`, an edit payload, has nothing but blank lines and
    comments for some target's dialect: the comments named, and the targets
    when not all of them (` for SW1, SW2`); '' when every target gets a
    line. A `! x` is nothing to an IOS-shaped dialect and a line to the
    plain drivers, so it depends on the target."""
    empty = [t for t in targets if not set_file_payload(text, comment_prefixes(t.vendor))]
    if not empty:
        return ""
    kinds = comments_named(tuple(dict.fromkeys(c for t in empty for c in comment_prefixes(t.vendor))))
    names = [t.name for t in empty]
    whom = "" if len(empty) == len(targets) else " for " + ", ".join(names[:20]) + (" …" if len(names) > 20 else "")
    return f"nothing but blank lines and {kinds} comments in it{whom}"


def probe_lines(results) -> list:
    """--probe's report, one line per box: the name, the result, the TCP
    handshake's round trip and the banner time, the banner or the reason,
    and the slow tag."""
    name_width = max(len(r.device) for r in results)
    result_width = max(len(r.result) for r in results)
    lines = []
    for r in results:
        parts = [r.device.ljust(name_width), r.result.ljust(result_width)]
        if r.connect_ms is not None:
            parts.append(f"connect {probes.ms_text(r.connect_ms)} ms")
        if r.banner_ms is not None:
            parts.append(f"banner {probes.ms_text(r.banner_ms)} ms")
        if r.ok:
            parts.append(r.banner if r.banner is not None else "TCP only, no banner to check")
        elif r.reason:
            parts.append(r.reason)
        if r.slow:
            parts.append(r.slow)
        lines.append("  ".join(parts).rstrip())
    return lines


def probe_summary(results, seconds: float, slow_ms: float, name_slow: bool = True) -> str:
    """`Probe: N box(es) in Ts: L live, D dead (refused 1, ...), S slow`,
    the slow ones named with their round trip when their lines are not
    printed."""
    text = f"Probe: {len(results)} box(es) in {seconds:.1f}s: {probes.tally(results)}"
    slow = [r for r in results if r.slow]
    if slow:
        named = ""
        if name_slow:
            named = ": " + ", ".join(f"{r.device} {probes.ms_text(r.connect_ms)} ms" for r in slow[:10]) + \
                    (" …" if len(slow) > 10 else "")
        text += f" (above {slow_ms:g} ms{named})"
    return text


def held_by(gate, targets) -> dict:
    """{(host, port): why} for the boxes the safety gate holds now (a
    cooldown, a corrupt safety file), each its host and the port its
    transport uses, as the gate keys them: the probe does not contact them
    either, and the run's gate turns them away as before."""
    if gate is None:
        return {}
    boxes = {(t.host, resolve_target_port(t)) for t in targets}
    return {box: f"safety gate: {why}" for box, why in gate.holds(boxes).items()}


def plan_logins(units, mode: str, dry_run: bool, previews: bool):
    """The logins a run will make, for the safety gate's rate limit, which
    counts logins (#145): ({(host, port): the sessions the run opens to
    that device}, {the units that ride a session already open}). `units`
    are the run's (target, job entry or None) in file order; `previews`:
    --show-diff previews the edits first. A unit logs in once, and its
    preview once more (the previews run before the session pool is on); a
    dry run of a read logs in nowhere; a job's entries for one device on a
    pooled transport (NETCONF) share one session (#57), so only the first
    of them to open one logs in."""
    logins, rides, opened = {}, set(), set()
    for i, (t, je) in enumerate(units):
        device = (t.host, resolve_target_port(t))
        unit_mode = je.mode if je is not None else mode
        n = 1 if previews and (je is None or unit_mode.startswith("edit")) else 0
        if opens_session(unit_mode, dry_run):
            pooled = je is not None and drivers.get(t.vendor).transport.pooled
            if pooled and device in opened:
                rides.add(i)
            else:
                n += 1
                if pooled:
                    opened.add(device)
        logins[device] = logins.get(device, 0) + n
    return logins, rides


async def probe_alone(args, targets, store, user, json_mode: bool, safety_gate=None) -> int:
    """--probe with no command: every box probed (hssh.probe), no login
    and no credential; one line per box and a summary, or the records with
    --json; kept in the store as a run of mode `probe`, a row per box (one
    that is not live is a failed row with its verdict, so `h-ssh-store
    failed` lists it). 0 when every box is live, 1 when one is dead, 3
    when none is but one was not probed (reached through a proxy, held by
    the safety gate), 4 when the store could not keep it. The record (the
    rows, the audit log, --log) is written before the report is printed,
    so a reader that leaves early (`| head`) or a Ctrl-C while it prints
    costs at most the report, never the record; the run row is closed
    whatever ends the run, as interrupted where the report was cut short
    (on 3.11+ a Ctrl-C there takes effect only at the next await, so the
    report usually finishes and the run is whole)."""
    limit, note = fit_probes_to_open_files(min(MAX_PROBES, len(targets)))
    if note:
        print(f"WARNING: {note}", file=sys.stderr)
    seconds = connect_budget(args.connect_timeout, args.session_timeout)
    if not json_mode:
        print(f"\nProbe: {len(targets)} box(es), {limit} at a time, {seconds:g}s for the TCP connect and "
              f"{seconds:g}s for the banner")
    run_id = None
    if store is not None:
        try:
            run_id = store.begin_run("probe", sys.argv[1:], user, len(targets), __version__,
                                     origin=socket.gethostname(), command="probe")
        except Exception as e:                    # the file went away since it was opened
            print(f"ERROR: store {store.path}: {e}; refusing to start.", file=sys.stderr)
            return 2
    recorded = {"live": 0, "dead": 0}     # the boxes whose record is written; every other one is skipped
    tried = lost = 0                      # rows handed to the store, and those it could not keep
    reason = None
    whole = False                         # the run got to the end of its report
    try:
        started = time.time()
        results = await probes.probe(targets, seconds, args.slow, limit, user=user,
                                     held=held_by(safety_gate, targets))
        elapsed_ms = int((time.time() - started) * 1000)
        stamp = datetime.now().isoformat()
        for r in results:
            record = r.to_dict()
            entry = {"device": r.device, "host": r.host, "vendor": r.vendor, "ok": r.ok,
                     "duration_ms": r.duration_ms, "error": None if r.ok else r.verdict, "output": record}
            if run_id is not None:
                tried += 1
                try:
                    store.add_entry(run_id, entry, "probe", fmt="json")
                except Exception as e:
                    lost += 1
                    reason = reason or str(e)
            if args.audit_log:
                write_audit_entry(path=args.audit_log, device=r.device, host=r.host, vendor=r.vendor, mode="probe",
                                  payload="", ok=r.ok, error=entry["error"])
            if args.log:
                try:
                    secure_append(args.log, json.dumps(redact_values({
                        "timestamp": stamp, "user": user, "mode": "probe", "command": "probe",
                        "dry_run": args.dry_run, **record, "error": entry["error"]})) + "\n")
                except Exception as e:
                    print(f"WARNING: Could not write to log file: {e}", file=sys.stderr)
                    args.log = None
            if r.ok or r.dead:
                recorded["live" if r.ok else "dead"] += 1
        if run_id is not None:
            gone = store.still_there()
            if gone is not None:          # SQLite kept writing into the void; nothing of this run is on disk
                lost, reason = tried, gone
        live, dead = recorded["live"], recorded["dead"]
        passed = len(results) - live - dead              # not probed
        if json_mode:
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            shown = terminal_safe if _tty(sys.stdout) else (lambda text: text)    # a banner is the device's text
            for line in probe_lines(results):
                print(shown(line))
            print()
            print(probe_summary(results, elapsed_ms / 1000, args.slow, name_slow=False))
        whole = True
    finally:
        # Whatever ends it (Ctrl-C during the probe or the report, a reader
        # that left, anything else), the run row is closed with how far it
        # got, as interrupted where it was cut short; one whose rows the
        # store kept none of stays open, as a run's does (`?/?`).
        if run_id is not None and (lost < tried or tried == 0):
            try:
                store.finish_run(run_id, recorded["live"], recorded["dead"],
                                 len(targets) - recorded["live"] - recorded["dead"],
                                 interrupted=not whole)
            except Exception as e:
                if whole:
                    print(f"WARNING: store {store.path}: {e}", file=sys.stderr)
    if lost:
        print(f"WARNING: store {store.path}: {lost} of {tried} results were not kept: {reason}", file=sys.stderr)
    summary = {"targets": len(results), "ok": live, "fail": dead, "skipped": passed,
               "slow": sum(1 for r in results if r.slow), **({"not_kept": lost} if lost else {}),
               "elapsed_ms": elapsed_ms, "mode": "probe"}
    print(f"[h-ssh] {json.dumps(summary)}", file=sys.stderr)
    if lost:
        return 4
    return 1 if dead else 3 if passed else 0


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
    parser = _Parser(
        description="Multi-vendor network automation tool.",
        epilog="The password is typed at the prompt when stdin is a terminal, or read from HSSH_PASSWORD "
               "when a pipeline runs h-ssh; there is no --password flag, and the config file never "
               "carries one.")

    parser.add_argument("--devices", type=_not_empty, default=get_default_devices_path(),
                        help="Devices CSV (default: ~/.h-ssh/devices.csv or ./devices.csv)")
    parser.add_argument("--transport", choices=TRANSPORT_CHOICES, default=None,
                        help="Transport for targets that don't declare one (default: ssh)")
    parser.add_argument("--structured", action="store_true",
                        help="Return structured data where the vendor supports it "
                             "(junos NETCONF); falls back to text elsewhere")
    parser.add_argument("--user", type=_not_empty,
                        help="Username (or HSSH_USER, or 'user' in ~/.h-ssh/config; default: the name you are logged in as)")
    parser.add_argument("--config", type=_not_empty,
                        help="Config file with defaults (default: ~/.h-ssh/config)")

    # Modes
    parser.add_argument("-sC", "--show-command", type=str,
                        help="Show command to run on all targets")
    parser.add_argument("-eC", "--edit-command", type=str,
                        help="Single config command (Junos expects 'set ...')")
    parser.add_argument("-eD", "--edit-dir", type=_not_empty,
                        help="Directory containing <NAME>.set files")
    parser.add_argument("-eB", "--edit-broadcast", type=_not_empty,
                        help="Multi-line config file for all devices (e.g., configs/all.set)")
    parser.add_argument("--allow-missing", action="store_true",
                        help="-eD: skip devices that have no <NAME>.set instead of refusing the run "
                             "(they count as skipped: exit 3)")
    parser.add_argument("--batch", type=_not_empty,
                        help="File containing show commands to run in batch (one per line, # comments)")
    parser.add_argument("--profile", type=_not_empty, metavar="NAME",
                        help="A named command set, run like --batch: ~/.h-ssh/profiles/NAME.txt, else one that "
                             "ships with h-ssh (--list-profiles shows both)")
    parser.add_argument("--job", type=_not_empty,
                        help="JSON job file with per-device commands (use - for stdin)")
    parser.add_argument("--run", type=_not_empty, metavar="FILE",
                        help="YAML or JSON run file: every key is a flag name (devices, show, commands, "
                             "edit, jobs, workers, ...); a flag on the command line wins over the file")
    parser.add_argument("--rollback", type=_ranged_int(0, 49, "--rollback"), metavar="N",
                        help="Return every target to rollback N (0-49), with the same gates as an edit (Junos only)")
    parser.add_argument("--commit-status", action="store_true",
                        help="Show the commit history as data: sequence, time, user, comment, pending commit-confirmed timer (Junos only)")
    parser.add_argument("--comment", type=_comment_arg, metavar="TEXT",
                        help="Log this comment with the commit; it shows in 'show system commit' (Junos only): "
                             "one line of text, at most 512 bytes")
    parser.add_argument("--show-diff", action="store_true",
                        help="Edits: run a dry-run on every target, print the diffs, then ask once before "
                             "committing; a diff that changed by then is not committed")
    parser.add_argument("--probe", action="store_true",
                        help="Alone, with no command: check every box without logging in (a TCP connect and the "
                             "SSH banner): one line per box with its result, the handshake's round trip and the "
                             "banner time, then a summary; kept in the store; exit 0 when every box is live, 1 "
                             "when one is dead, 3 when none is but one was not probed (behind a ProxyJump or "
                             "ProxyCommand, held by the safety gate). With a command: probe first even where the "
                             "config file or a run file says not to")

    # Behavior
    parser.add_argument("--retries", type=_ranged_int(0, None, "--retries"), default=None,
                        help="Retries per device after the first attempt (default: 2). "
                             "Permanent failures never retry.")
    parser.add_argument("--workers", type=_ranged_int(1, MAX_WORKERS, "--workers"), default=None,
                        help="Parallel workers (default: 8)")
    parser.add_argument("--session-timeout", type=_ranged_int(1, MAX_SECONDS, "--session-timeout"), default=None,
                        help="Timeout for setting up the session: key exchange, authentication, the NETCONF "
                             "hello; the whole login on telnet (default: 30)")
    parser.add_argument("--connect-timeout", type=_ranged_int(1, MAX_SECONDS, "--connect-timeout"), default=None,
                        metavar="SECONDS",
                        help="junos, ssh, openssh: how long the TCP connect and the SSH banner may take, per "
                             "attempt and never more than --session-timeout; a device that has not answered by "
                             "then is tried again after a short pause, --retries times (default: 3)")
    parser.add_argument("--command-timeout", type=_ranged_int(1, MAX_SECONDS, "--command-timeout"), default=None,
                        help="Timeout for individual commands/operations (default: 20)")
    parser.add_argument("--no-probe", action="store_true",
                        help="Skip the probe that runs before every run (a TCP connect and the SSH banner per box, "
                             "100 at a time: the run goes to the live boxes, a dead one is FAIL within seconds, "
                             "and an edit asks before it goes on without one); you say every box is up and "
                             "accept the risk")
    parser.add_argument("--slow", type=_ms_arg, metavar="MS", default=None,
                        help="The probe tags a live box whose TCP handshake took longer than MS milliseconds as "
                             "slow; information only, never a failure (default: 10)")
    parser.add_argument("--skip-unreachable", action="store_true",
                        help="Edits: go on with the boxes that answered the probe, without asking; the others are "
                             "skipped (exit 3). Without it a dead box stops an edit that has no terminal to ask at "
                             "(exit 2); -y does not stand in for it")
    parser.add_argument("--dry-run", action="store_true",
                        help="Do not push, only show what would happen")
    parser.add_argument("--commit-confirmed", type=confirm_minutes_arg, nargs="?", const=10, default=None,
                        help="Use commit confirmed with auto-rollback timer in minutes, 1-65535 (default: 10, Junos only)")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip confirmation prompt for edit operations (not the probe's question about "
                             "unreachable boxes; see --skip-unreachable)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output for all operations")
    parser.add_argument("--every", type=_seconds_arg, metavar="SECONDS", default=None,
                        help="Watch: run the same reads again every SECONDS after the previous tick and print, per "
                             "tick, what changed since the one before (reads only, the store on, not with --json or "
                             "--raw; 1 to 86400 s); until Ctrl-C or --times")
    parser.add_argument("--times", type=_ranged_int(1, None, "--times"), default=None,
                        help="With --every: stop after this many ticks")
    parser.add_argument("--diff", action="store_true",
                        help="Compare output across devices (show modes only); the baseline is the first device "
                             "in target order that answered (bare hosts, then --target; or the inventory's rows)")
    parser.add_argument("--raw", action="store_true",
                        help="Print only each device's output, no progress lines or headers")
    parser.add_argument("--list-commands", action="store_true",
                        help="List available command shortcuts for the selected transport")
    parser.add_argument("--list-vendors", action="store_true",
                        help="List every driver a target may name: aliases, transport, dialect, "
                             "formats, what it supports, and where it came from")
    parser.add_argument("--list-profiles", action="store_true",
                        help="List the command sets --profile can name: yours (~/.h-ssh/profiles) and the shipped ones")

    # Inline targets
    parser.add_argument("--target", type=str, action="append",
                        help="Inline target as name:host:vendor:port, an IPv6 host in brackets "
                             "(repeatable, vendor defaults to --transport)")
    parser.add_argument("hosts", nargs="*", metavar="HOST",
                        help="Targets typed bare, before or between the flags: a host alone (a device named "
                             "after itself, on --transport) or name:host[:vendor][:port] as for --target; an IPv6 "
                             "host in brackets. With any target given, the inventory file is not read")

    # Output
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON array (suppresses human-readable output)")
    parser.add_argument("--format", choices=["text", "json", "xml"], default="text",
                        help="Show output as the router's own JSON or XML reply, through its RPC "
                             "translation of the command (junos only; default: text)")
    parser.add_argument("--save-output", type=_not_empty,
                        help="Create dir (0700) and save each device's raw output in it (0600 files, not redacted): "
                             "NAME.output, or NAME.json for a batch; a job's later entries for one device go to "
                             "NAME.2.output, NAME.3.output, ... in file order")
    parser.add_argument("--log", type=_not_empty,
                        help="Append per-device JSONL results to file (0600, secrets redacted as in the audit log)")
    parser.add_argument("--store", type=_not_empty,
                        help=f"The SQLite file every run is kept in: one row per command per device, the reply as "
                             f"the device gave it, 0600 (default ${STORE_ENV}, else `store` in the config file, "
                             f"else ./{STORE_DEFAULT}; read it with h-ssh-store)")
    parser.add_argument("--no-store", action="store_true",
                        help="Keep nothing of this run")
    # An empty value is refused (_not_empty); an empty variable is no audit
    # log or safety file, as it always was, and argparse never sees it.
    parser.add_argument("--audit-log", type=_not_empty,
                        default=os.environ.get("HSSH_AUDIT_LOG") or None,
                        help="Edit audit log path for JSONL audit trail (or set HSSH_AUDIT_LOG env var)")
    parser.add_argument("--safety-file", type=_not_empty,
                        default=os.environ.get("HSSH_SAFETY_FILE") or None,
                        help="Safety gate JSON file for per-device rate limiting and cooldown")

    args = parser.parse_intermixed_args()
    typed = typed_dests(parser, sys.argv[1:])     # what the command line gave, for the run file (#140)
    if not args.verbose:
        _quiet_transport_logs()
    # A host typed bare is an inline target like any --target; from here on
    # only args.target is looked at, bare_hosts remembers which were bare.
    bare_hosts = list(args.hosts)
    args.target = (bare_hosts + list(args.target or [])) or None
    if args.list_profiles:
        try:
            lines = profiles.listing_lines()
        except OSError as e:                 # a profiles directory that may not be read
            print(f"ERROR reading {e.filename}: {read_failure(e)}", file=sys.stderr)
            return 2
        for line in lines:
            print(line)
        return 0
    if args.profile:
        # A profile is a batch file by name; from here on it is --batch, and
        # as a command-line value it wins over a run file's `batch`.
        if args.batch:
            print("ERROR: --profile and --batch both name the commands; give one of them", file=sys.stderr)
            return 2
        try:
            args.batch = str(profiles.profile_path(args.profile))
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        except OSError as e:                 # a directory on the way that may not be searched
            print(f"ERROR reading profile '{args.profile}' ({e.filename}): {read_failure(e)}", file=sys.stderr)
            return 2
        typed.add("batch")
    args.batch_commands = None   # the batch: a run file's commands, or the --batch/--profile file's lines read below
    args.jobs_data = None        # job entries from a run file

    # A run file sits between the command line and the config file: a flag
    # typed on the command line wins, whatever its value, the file wins over
    # the environment and ~/.h-ssh/config. It is read before anything else so
    # the banner and the checks below see what the run will use.
    from_run_file = []           # the options the run file set
    devices_unused = False       # the file's `devices`, replaced by a typed --devices or target
    if args.run:
        try:
            run_data = validate_run(load_run_file(args.run), args.run, TRANSPORT_CHOICES, CONFIG_FLOORS,
                                    CONFIG_CEILINGS)
            from_run_file = apply_run(args, run_data, typed)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        devices_unused = "devices" in run_data and "devices" not in from_run_file

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
    if args.probe and args.no_probe:
        if "no_probe" not in from_run_file:
            print("ERROR: --probe and --no-probe contradict each other.", file=sys.stderr)
            return 2
        args.no_probe = False       # typed on the command line, --probe wins over a run file's no_probe
    # The probe before the run (#127): on unless --no-probe (or a run file's
    # no_probe) or `probe = no` in the config file says otherwise; --probe
    # with a command turns it on over both files.
    probe_first = not args.no_probe and (args.probe or args.probe_by_config)

    # A command made of whitespace is a typo, not a request; one with a
    # control character in it is not a command: a line break in -sC would
    # run two lines (and a retry both again), a NUL or an ESC is not text.
    # An edit payload is lines, so -eC keeps its line breaks.
    for flag, value in (("-sC", args.show_command), ("-eC", args.edit_command)):
        if value is None:
            continue
        if not value.strip():
            print(f"ERROR: {flag} is empty.", file=sys.stderr)
            return 2
        what = control_character(value, line_breaks=flag == "-eC")
        if what:
            print(f"ERROR: {flag} has {what} ({value!r}); "
                  f"{'a command is one line of text' if flag == '-sC' else 'a payload is plain text'}.",
                  file=sys.stderr)
            return 2

    if args.list_vendors:
        for line in list_vendors_lines():
            print(line)
        return 0

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
        # A job's targets are its entries. A target typed beside it, or an
        # inventory named with --devices, was ignored without a word: the
        # job ran on every device it names, and with edit entries and -y it
        # committed on routers the operator meant to leave out (#140).
        beside = [what for what, given in (("a bare host", bare_hosts), ("--target", "target" in typed),
                                            ("--devices", "devices" in typed)) if given]
        if beside:
            jobs = "--job" if args.job else "a run file's 'jobs'"
            print(f"ERROR: {', '.join(beside)} beside {jobs}: a job's targets are its entries.", file=sys.stderr)
            return 2
        # So are a run file's `devices` beside a --job typed next to the
        # file: the job ran and committed on its own entries, the file's
        # devices dropped without a word (#140). Beside the file's own
        # `jobs` they are not used, as the README says.
        if args.job and "devices" in from_run_file:
            print(f"ERROR: run file '{args.run}': 'devices' beside --job: a job's targets are its entries.",
                  file=sys.stderr)
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
        # A device may be named in several entries: seq_of counts them per
        # device in file order, 0 for the first. The one count is both the
        # entry's store seq (its own row, so a device a job names twice does
        # not have its first row replaced by its second; a batch's commands
        # count up the same way) and, with --save-output, its own file
        # (R1.output, R1.2.output, R1.3.output, ...). It moves on by one an
        # entry because a job entry is one row (a show or an edit); an entry
        # that wrote several rows would have to move it on by as many.
        seq_of, counted = [], {}
        for je in job_entries:
            assert je.mode in ("show", "edit-cmd"), f"job entry mode {je.mode!r}: seq counts one row an entry"
            seq_of.append(counted.get(je.target.name, 0))
            counted[je.target.name] = seq_of[-1] + 1
        if args.save_output:
            # R1's second entry is R1.2.output, which is also the file of a
            # device named R1.2: one result would replace the other. Refused
            # with the job file's other mistakes, before the password prompt.
            saved_as = {}
            for t, seq in zip(targets, seq_of):
                whose = f"{t.name}'s entry {seq + 1}" if seq else t.name
                fname = save_name(t.name, seq)
                if fname in saved_as:
                    print(f"ERROR: --save-output: {saved_as[fname]} and {whose} would both be saved as {fname}; "
                          "rename one of the devices. Nothing was sent.", file=sys.stderr)
                    return 2
                saved_as[fname] = whose
        has_edits = any(e.mode.startswith("edit") for e in job_entries)
        mode = "job"
        for je in job_entries:
            guard = edit_guard(je.target.vendor)
            if guard and je.mode.startswith("edit"):
                valid, err = guard.check_edit(je.command, allow_commit=True)
                if not valid:
                    print(f"ERROR: {guard.title} job command for '{je.target.name}' only accepts set-style commands: {err}", file=sys.stderr)
                    return 2
        # As for -eC: an edit of nothing but blank lines and the comments of
        # its target's dialect has nothing to apply (#142).
        for n, je in enumerate(job_entries):
            empty = nothing_to_apply(je.command, [je.target]) if je.mode.startswith("edit") else ""
            if empty:
                print(f"ERROR: Invalid job file: Job entry {n} ({je.target.name}): 'edit' has {empty}. "
                      "Nothing was sent.", file=sys.stderr)
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
        alone = args.probe and not any(modes)     # --probe with no command: the health check, no run
        if sum(modes) != 1 and not alone:
            print("ERROR: choose exactly one of -sC, -eC, -eD, -eB, --batch, --rollback, --commit-status, or --job "
                  "(or --probe alone, to check the boxes).", file=sys.stderr)
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
        # The batch is read here, with the run's other files and before the
        # password prompt: a file that cannot be read is said so, not a
        # traceback; a line with a control character is not a command.
        if args.batch:
            source = f"profile '{args.profile}' ({args.batch})" if args.profile else f"batch file '{args.batch}'"
            try:
                if not is_file(Path(args.batch)):
                    print(f"ERROR: batch file not found: {args.batch}", file=sys.stderr)
                    return 2
                args.batch_commands = read_command_file_lines(Path(args.batch))
            except (OSError, UnicodeDecodeError) as e:
                print(f"ERROR reading {source}: {read_failure(e)}", file=sys.stderr)
                return 2
            if not args.batch_commands:
                print("ERROR: batch file is empty after filtering.", file=sys.stderr)
                return 2
        else:
            source = f"run file '{args.run}' commands"
        for cmd in args.batch_commands or ():
            what = control_character(cmd)
            if what:
                print(f"ERROR: {source}: {what} in {cmd!r}; a command is one line of text.", file=sys.stderr)
                return 2

        # A target typed on the command line, or a typed --devices, replaced
        # the run file's `devices` (a list or a path); said once, not per tick.
        if devices_unused and (args.every is None or not _WATCH["tick"]):
            by = "the targets on the command line win" if args.target else "--devices on the command line wins"
            print(f"Run file '{args.run}': 'devices' is ignored; {by}.", file=sys.stderr)

        # Load targets. A target that doesn't declare a vendor gets
        # --transport (or the config file's), the same for every form.
        if args.target:
            try:
                targets = [parse_bare_target(spec, default_vendor=args.transport) if spec in bare_hosts
                           else parse_inline_target(spec, default_vendor=args.transport) for spec in args.target]
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

        # The payloads, read once here and handed to the checks below, the
        # runner and the audit log as the same string: what is checked is what
        # is sent, but for the blank lines and full-line comments ('#', and '!'
        # for an IOS-shaped dialect), which the runner keeps from every driver
        # (core.set_file_payload).
        broadcast_text = None
        edit_payloads = {}
        if args.edit_broadcast:
            try:
                broadcast_text = Path(args.edit_broadcast).read_text(encoding="utf-8-sig")
            except Exception as e:
                print(f"ERROR reading broadcast file '{args.edit_broadcast}': {e}", file=sys.stderr)
                return 2
        if args.edit_dir:
            for t in targets:
                set_file = path_inside(args.edit_dir, f"{t.name}.set")
                if set_file.is_file():
                    try:
                        edit_payloads[t.name] = set_file.read_text(encoding="utf-8-sig")
                    except Exception as e:
                        print(f"ERROR reading config file '{set_file}': {e}", file=sys.stderr)
                        return 2
        # -eC's rule, on every driver: a payload is plain text but for its
        # line breaks. A CLI acts on a control character as it is typed (^C,
        # ^U and DEL leave the rest of the line to run as a line of its own,
        # a `commit` too, --dry-run or not), so a file with one is refused
        # before the password is asked. A Tab passes here, as NETCONF reads
        # it as a space; the drivers that type at a CLI refuse it themselves,
        # before they connect.
        files = [("-eB", args.edit_broadcast, broadcast_text)] if broadcast_text is not None else []
        files += [("-eD", path_inside(args.edit_dir, f"{name}.set"), text) for name, text in edit_payloads.items()]
        for flag, path, text in files:
            found = control_line(text)
            if found:
                n, line, what = found
                print(f"ERROR: {flag} {path}: line {n} has {what} ({line!r}); a payload is plain text.",
                      file=sys.stderr)
                return 2

        # The edit guard keys off the targets' dialects, not a global flag —
        # a mixed inventory can have some devices that care and some that don't.
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
                for guard in guards.values():
                    valid, err = guard.check_edit(broadcast_text, allow_commit=False)
                    if not valid:
                        print(f"ERROR: {guard.title} broadcast file '{args.edit_broadcast}' only accepts 'set ...' commands: {err}", file=sys.stderr)
                        return 2
            elif args.edit_dir:
                for t in targets:
                    guard = edit_guard(t.vendor)
                    if guard and t.name in edit_payloads:
                        valid, err = guard.check_edit(edit_payloads[t.name], allow_commit=False)
                        if not valid:
                            set_file = path_inside(args.edit_dir, f"{t.name}.set")
                            print(f"ERROR: {guard.title} config file '{set_file}' only accepts 'set ...' commands: {err}", file=sys.stderr)
                            return 2

        # A payload with nothing but blank lines and comments is refused
        # here, on every driver, before anything is written or sent: the
        # plain ssh and openssh drivers logged in, sent nothing and said OK,
        # where the Junos guard refuses it. What is a comment is the target
        # dialect's: '#', and '!' for an IOS-shaped one, whose edit typed
        # `configure terminal` and `end` for a file of '!' lines, or an -eC
        # '! x', and said OK (#142).
        empty = nothing_to_apply(args.edit_command, targets) if args.edit_command is not None else ""
        if empty:
            # Said as the run file's key when it is the file's, as its other refusals are.
            what = f"run file '{args.run}': 'edit'" if "edit" in from_run_file else f"-eC {args.edit_command!r}"
            print(f"ERROR: {what} has {empty}. Nothing was sent.", file=sys.stderr)
            return 2
        empty = nothing_to_apply(broadcast_text, targets) if broadcast_text is not None else ""
        if empty:
            print(f"ERROR: -eB {args.edit_broadcast}: {empty}. Nothing was sent.", file=sys.stderr)
            return 2
        skipped_missing = 0
        if args.edit_dir:
            empty = [t for t in targets if t.name in edit_payloads and nothing_to_apply(edit_payloads[t.name], [t])]
            if empty:
                shown = ", ".join(f"{t.name}.set" for t in empty[:20]) + (" …" if len(empty) > 20 else "")
                kinds = comments_named(tuple(dict.fromkeys(c for t in empty for c in comment_prefixes(t.vendor))))
                print(f"ERROR: -eD {args.edit_dir}: nothing but blank lines and {kinds} comments in {shown}. "
                      "Nothing was sent.", file=sys.stderr)
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
        if alone:
            mode = "probe"
        elif args.show_command:
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

    # --diff compares a show's replies across the devices; with an edit, a
    # job or any other mode it was accepted and did nothing (#140).
    if args.diff and mode not in ("show", "show-batch"):
        print("ERROR: --diff goes with a show (-sC, --batch, --profile): it compares the replies across devices.",
              file=sys.stderr)
        return 2
    if args.comment is not None and not has_edits:
        print("ERROR: --comment goes with an edit (-eC, -eD, -eB, --rollback, or a job with edits).", file=sys.stderr)
        return 2
    # So do the timer, the probe's go-ahead and --allow-missing: on a run
    # with no edit they were accepted and did nothing (#140), typed or from
    # a run file alike. --allow-missing is for -eD; beside another edit it
    # changes nothing and is let be, so a run file that sets it for every
    # edit still runs.
    for flag, given in (("--commit-confirmed", args.commit_confirmed is not None),
                        ("--skip-unreachable", args.skip_unreachable)):
        if given and not has_edits:
            print(f"ERROR: {flag} goes with an edit (-eC, -eD, -eB, --rollback, or a job with edits).",
                  file=sys.stderr)
            return 2
    if args.allow_missing and not has_edits:
        print("ERROR: --allow-missing goes with -eD: it skips the devices that have no <NAME>.set.", file=sys.stderr)
        return 2
    # Nobody watches a pipeline: a run file that commits must arm a timer, or
    # say it is a dry run. A flag on the command line may supply either, and
    # an edit given there (-eC, -eD, -eB, --rollback, a --job file) is held to
    # it as the file's own are.
    job_edits = [je.command for je in (job_entries or []) if je.mode.startswith("edit")]
    if args.run and has_edits and edit_needs_timer(args, is_confirm, job_edits):
        print(f"ERROR: run file '{args.run}' makes changes without a rollback timer: set commit_confirmed "
              "(minutes) in the file or pass --commit-confirmed, or set dry_run.", file=sys.stderr)
        return 2
    # A confirm is a plain commit: it cannot arm a new timer, so a run that
    # asks for one would end with a banner promising a rollback that no
    # device is counting down.
    confirms = [args.edit_command] if args.edit_command else job_edits
    if args.commit_confirmed and confirms and all(is_confirm(c) for c in confirms):
        print('ERROR: --commit-confirmed does not go with -eC "commit": a confirm cannot arm a new timer.',
              file=sys.stderr)
        return 2
    if args.show_diff and (not has_edits or args.dry_run):
        print("ERROR: --show-diff goes with an edit that is not already a --dry-run.", file=sys.stderr)
        return 2
    # A preview is a dry run of one entry on the device as it is now, and a
    # job runs a device's entries one after another, each on the device as
    # the one before left it. A device's second edit was previewed without
    # its first (a delete of what the first sets: NO CHANGES), and after the
    # y the first committed and the second failed `diff changed since
    # preview`: the job half applied (#144). Refused, before anything is
    # written or sent, until a device's edits are previewed as one candidate.
    if args.show_diff and job_entries:
        edits = {}
        for je in job_entries:
            if je.mode.startswith("edit"):
                edits[je.target.name] = edits.get(je.target.name, 0) + 1
        several = [name for name, n in edits.items() if n > 1]
        if several:
            shown = ", ".join(several[:20]) + (" …" if len(several) > 20 else "")
            print(f"ERROR: --show-diff: the job has more than one edit entry for {shown}; its edits would be "
                  "previewed one by one, each on the device as it is now, so a later one's preview would not "
                  "see the ones before it. Put a device's edits in one entry, or drop --show-diff. "
                  "Nothing was sent.", file=sys.stderr)
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
            driver = drivers.get(v)
            mod = drivers.module_of(driver) if mode != "probe" else None     # a probe logs in nowhere
        except (ValueError, ImportError):
            print(f"ERROR: Unknown vendor '{v}'.", file=sys.stderr)
            return 2
        if mod is not None and not getattr(mod, "AVAILABLE", True):
            print(f"ERROR: {driver.transport.install} not installed (required for vendor '{v}').",
                  file=sys.stderr)
            return 2

    # --every's refusals come before anything is written: a watch refused
    # here leaves no store file and no audit log behind.
    if args.times is not None and args.every is None:
        print("ERROR: --times goes with --every.", file=sys.stderr)
        return 2
    if args.every is not None:
        if mode not in ("show", "show-batch"):
            print("ERROR: --every watches reads (-sC, --batch, --profile), not edits, rollbacks, commit status, jobs "
                  "or --probe.", file=sys.stderr)
            return 2
        if args.no_store:
            print("ERROR: --every compares every tick with the one before through the store; drop --no-store "
                  "or name a --store.", file=sys.stderr)
            return 2
        if args.json or args.raw:
            # The tick lines and the diffs are the watch's output, and they
            # are neither a JSON array nor device output: `--json --every | jq`
            # broke at the first tick. The ticks are in the store for a pipeline.
            print("ERROR: --every prints one line per tick and what changed, not --json or --raw output; "
                  "drop one of them (every tick is in the store for h-ssh-store).", file=sys.stderr)
            return 2

    # A shortcut is sent as its file says, resolved per vendor, so the command
    # it stands for is held to the rule of one typed: one line of text (a
    # job's shows too). --format turns a command into an RPC and sends it
    # with no gate at all, so under it a show, and every line of a batch (a
    # file, a profile, a run file's commands), must also be a read, in a dry
    # run as well. Both refused here, before any I/O, by the runner's rules;
    # a job's show entries are held to reads by the runner.
    if job_entries:
        sends = [(je.command, je.target.vendor) for je in job_entries if je.mode == "show"]
    else:
        sends = [(raw, vendor) for vendor in sorted({t.vendor for t in targets})
                 for raw in ([args.show_command] if args.show_command else args.batch_commands or [])]
    for raw, vendor in dict.fromkeys(sends):
        resolved = str(resolve_command(raw, vendor))
        what = control_character(resolved) if resolved != raw else None
        if what:
            print(f"ERROR: shortcut {raw!r} ({vendor}) has {what} ({resolved!r}); a command is one line of text.",
                  file=sys.stderr)
            return 2
        if args.format != "text" and not job_entries and not is_read(drivers.get(vendor).dialect, resolved):
            print(f"ERROR: {reads_only(args.format, resolved)}", file=sys.stderr)
            return 2

    # The refusals that need nothing written come before anything is: a run
    # refused here leaves no store file, no audit log and no --save-output
    # directory behind.
    if args.no_store and args.store:
        print("ERROR: --no-store and --store contradict each other.", file=sys.stderr)
        return 2
    if args.raw and args.verbose:
        print("ERROR: --raw and -v are mutually exclusive.", file=sys.stderr)
        return 2
    if args.raw and args.json:
        print("ERROR: --raw and --json are mutually exclusive.", file=sys.stderr)
        return 2
    if mode != "probe" and os.environ.get("HSSH_PASSWORD") == "" and not _tty(sys.stdin):
        # A pipeline whose secret lookup came back empty: refused, since the
        # run would otherwise go on to key authentication without a word. A
        # probe logs in nowhere and asks for no password.
        print("ERROR: HSSH_PASSWORD is set but empty; refusing to start.", file=sys.stderr)
        return 2
    if mode != "probe":
        # The username the run logs in with is plain text: telnet types it at
        # the login: prompt as it is, and what followed a line break in it ran
        # as commands once the login succeeded, a commit too, in a run that
        # only reads. No device takes such a name, so it is refused for every
        # driver, before anything is written. Not quoted: what follows a line
        # break in it may well be the password.
        if args.user:
            named, source = args.user, (f"run file '{args.run}': 'user'" if "user" in from_run_file
                                        else "--user")
        elif os.environ.get("HSSH_USER"):
            named, source = os.environ["HSSH_USER"], "HSSH_USER"
        else:
            named = file_config.get("user")
            source = f"{get_config_path() if args.config is None else args.config}: 'user'"
        what = control_character(named or "", tabs=False)
        if what:
            print(f"ERROR: {source} has {what}; a username is plain text. Nothing was sent.", file=sys.stderr)
            return 2
    # An edit that changes the network needs its question answered: without
    # a terminal or -y it is refused here, before the probe touches a box.
    commits = has_edits and not args.dry_run
    if commits and not args.yes and not _tty(sys.stdin):
        if args.show_diff:
            print("ERROR: --show-diff needs a terminal to ask, or -y.", file=sys.stderr)
        else:
            print("ERROR: Edit operation requires confirmation but stdin is not a TTY. Use -y to skip.", file=sys.stderr)
        return 2
    save_dir = args.save_output or None
    if save_dir and Path(save_dir).exists() and not Path(save_dir).is_dir():
        print(f"ERROR: --save-output {save_dir} exists and is not a directory.", file=sys.stderr)
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
    store = None
    if not args.no_store:
        # Every run is kept. The store is opened, and its tables made, before
        # the first device is touched: one that cannot be written is no run,
        # found out now and not after the commits landed. It comes before the
        # safety file and the --save-output directory, so a store refused
        # leaves neither; a run refused after it takes it away (_discard_store).
        store_path = store_where(args.store, file_config)
        if args.every is not None and _WATCH["tick"]:
            # A later tick of a watch. Opening a store deleted since would make
            # a new, empty one and go on there, the ticks so far left behind.
            found = store_identity(store_path)
            if found != _WATCH["store"]:
                print(f"ERROR: store {store_path}: the store file was {'deleted' if found is None else 'replaced'} "
                      f"after tick {_WATCH['tick']}; a watch keeps all its ticks in one store, so it stops here.",
                      file=sys.stderr)
                return 2
        try:
            store = Store(store_path)
        except StoreError as e:
            print(f"ERROR: store {e}; every run is kept, so a store that cannot be written is no run: "
                  f"use --store PATH for another file, or --no-store; refusing to start.", file=sys.stderr)
            return 2
        if args.every is not None and not _WATCH["tick"]:
            _WATCH["store"] = store.identity       # the file every later tick must find at the path

    def _discard_store() -> None:
        """A run stopped before it starts, once its store is open: the store
        goes again when this run made it and nothing is kept in it
        (Store.discard), so such a run leaves no h-ssh.db behind; one that
        was there is left as it was."""
        if store is not None:
            store.discard()

    safety_file = args.safety_file       # the flag, the run file's, or HSSH_SAFETY_FILE
    try:
        safety_gate = SafetyGate(safety_file=safety_file) if safety_file else None
    except OSError as e:
        _discard_store()
        print(f"ERROR: --safety-file requested but unusable: {e}; refusing to start.", file=sys.stderr)
        return 2

    # One unit of work per job entry, or per target. The entry (None outside
    # job mode) travels with its result, so a job that names one device in
    # two entries never has the second read as the first.
    units = [(je.target, je) for je in job_entries] if job_entries else [(t, None) for t in targets]

    # The gate's rate limit counts logins (#145). A job's entries, and the
    # previews of --show-diff, were each counted as an attempt: past ten for
    # one device the gate turned the rest away, and a change set confirmed
    # whole was applied in part. What the run logs in to each device is known
    # now; a run that would pass the limit is refused before anything is
    # sent, and the run itself counts the same logins.
    rides = set()        # the units that ride a session the run has open: no login of their own
    if safety_gate is not None and mode != "probe":
        logins, rides = plan_logins(units, mode, args.dry_run, bool(args.show_diff and commits))
        crowded = {device: n for device, n in logins.items() if n > safety_gate.rate_limit}
        if crowded:
            _discard_store()
            names = {}
            for t, _ in units:
                names.setdefault((t.host, resolve_target_port(t)), t.name)
            shown = ", ".join(f"{names[d]} ({host_port(*d)}) {n} times" for d, n in list(crowded.items())[:20])
            print(f"ERROR: --safety-file: the safety gate lets a device have {safety_gate.rate_limit} logins in "
                  f"{safety_gate.rate_window:g} s, and this run would log in more often: {shown}"
                  f"{' …' if len(crowded) > 20 else ''}. The gate would turn the rest away part way through; "
                  "split the run. Nothing was sent.", file=sys.stderr)
            return 2

    if save_dir:
        # Raw device output (a config backup is the point), so the directory
        # and its files are the operator's alone: 0700 / 0600, never redacted.
        try:
            Path(save_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as e:
            _discard_store()
            print(f"ERROR: --save-output {save_dir}: {e.strerror or e}", file=sys.stderr)
            return 2

    # Credentials. The user: flag, environment, config file. The password has
    # two sources and no flag: typed at the prompt when someone runs h-ssh by
    # hand, or HSSH_PASSWORD when a pipeline runs it (handed over by whatever
    # keeps the secret). A flag would put it in `ps`, the shell history and
    # every stored command line; the config file is never read for it, so a
    # shell alias cannot leak it to disk.
    config = file_config
    user = args.user or os.environ.get("HSSH_USER") or config.get("user")
    passwd = os.environ.get("HSSH_PASSWORD")

    json_mode = args.json
    raw_mode = args.raw
    # Progress chatter only. An edit's probe line and confirmation stay visible.
    show_progress = not (json_mode or raw_mode)

    if args.every is not None:
        show_progress = False      # a watch prints one line per tick and what changed, not every device every time

    if not user:
        # Like ssh: no --user, no HSSH_USER, no `user` in the config file
        # means the name you are logged in as, with no question asked.
        user = getpass.getuser()

    if mode == "probe":
        # A probe logs in nowhere: no password is read or asked for.
        try:
            return await probe_alone(args, targets, store, user, json_mode, safety_gate)
        finally:
            if store is not None:
                store.close()
            if safety_gate is not None:
                safety_gate.close()
    if args.every is not None and _WATCH["tick"]:
        # A later tick of a watch: the password typed (or skipped) before
        # tick 1 is the watch's, not asked for again after every sleep.
        passwd = _WATCH["passwd"]
    elif not passwd:
        # No transport needs a password up front: a key or an agent may do.
        if _tty(sys.stdin):
            try:
                passwd = _ask("Password (press Enter to skip): ", secret=True) or None
            except PromptClosed:
                _discard_store()
                print("ERROR: no password given at the prompt (Enter skips it); nothing was sent.",
                      file=sys.stderr)
                return 2
            except KeyboardInterrupt:
                _discard_store()            # Ctrl-C there stops the run before it starts, as Ctrl-D does
                raise
        else:
            passwd = None
    if args.every is not None:
        _WATCH["passwd"] = passwd

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
            batch_cmds = list(args.batch_commands)      # the file's lines, or the run file's list

        if not json_mode and (args.every is None or not _WATCH["tick"]):
            # Report resolution once per vendor actually present, not per device,
            # and once per watch, not between its tick lines.
            for vendor in sorted({t.vendor for t in targets}):
                for raw in [c for c in ([show_cmd, edit_cmd] + (batch_cmds or [])) if c]:
                    resolved = resolve_command(raw, vendor)
                    if resolved != raw:
                        print(f"Resolved '{raw}' -> '{resolved}' ({vendor})")

    # A job runs on the session pool: a device on a pooled transport keeps its
    # session from one entry to the next, and those sessions count against
    # the open-file limit beside the workers (#147).
    pooled = 0
    if job_entries:
        per_box = {}
        for t, _ in units:
            if drivers.get(t.vendor).transport.pooled:
                box = (t.host, resolve_target_port(t))
                per_box[box] = per_box.get(box, 0) + 1
        pooled = sum(1 for n in per_box.values() if n > 1)
    args.workers, fd_note = fit_workers_to_open_files(resolve_workers(args.workers), pooled)
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
        devices = len({(t.host, resolve_target_port(t)) for t in targets})   # a job may list a device more than once
        waves = -(-devices // args.workers)
        if waves > 4 and args.workers < 64 and not fd_note:
            # Workers stay at 8 by default; a fleet run is told what it costs
            # (not when the open-file limit just lowered them: that WARNING said why).
            print(f"Hint: {devices} devices at {args.workers} workers is {waves} waves; --workers 64 would be "
                  f"{-(-devices // 64)} (one session per router either way)")

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
    # devices queue behind threads, and blocked ones (a device that does not
    # answer) hold a thread the whole time, stalling everything behind them.
    workers = resolve_workers(args.workers)
    loop = asyncio.get_running_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="hssh"))

    sem = asyncio.Semaphore(workers)

    # The run's row in the store. A read's is opened before its probe, so a
    # read stopped there is kept as an interrupted run; an edit's once the
    # edit is past its questions (the probe's, the confirmation, --show-diff's),
    # so an edit stopped before them committed nothing and leaves no row.
    store_run = None

    def _begin_run() -> bool:
        """Open the run's row; False (said why) when the store went away
        since it was opened."""
        nonlocal store_run
        if store is None:
            return True
        try:
            about = ("\n".join(batch_cmds) if batch_cmds else
                     show_cmd or edit_cmd or args.edit_broadcast or (args.edit_dir and f"dir:{args.edit_dir}") or mode)
            store_run = store.begin_run(mode, sys.argv[1:], user, len(units), __version__,
                                        origin=socket.gethostname(), command=about)
        except Exception as e:
            print(f"ERROR: store {store.path}: {e}; refusing to start.", file=sys.stderr)
            return False
        return True

    if not has_edits and not _begin_run():
        return 2

    # The probe (#127), before every run unless --no-probe or `probe = no`
    # says otherwise: a TCP connect and the SSH banner per box, no login, at
    # most MAX_PROBES at once, to where the box's transport will connect.
    # The run goes to the boxes that answered; a dead one is that run's
    # FAIL, with the probe's reason; one it did not probe (reached through a
    # proxy, or held by the safety gate) is run as without the probe. It
    # replaces the edit's pre-flight, which waited --session-timeout and
    # tried twice: an edit goes on without a dead box only when the operator
    # says so, asked at a terminal (-y confirms the edit, never a partial
    # deployment) or by --skip-unreachable without one, and those left out
    # are skipped (exit 3). That is for a box the edit goes to: a dead box a
    # job only reads is a FAIL of the run, as in a show. A dry run is asked
    # and stopped the same way: it rehearses the edit.
    dead = {}               # unit index -> the probe's result, for a unit whose box did not answer
    leave_out = set()       # of those, the units an edit goes on without: skipped, not failed
    probe_ms = None         # how long the probe took, for the summary
    interrupted = False     # Ctrl-C, during a read's probe or during the run
    not_started = 0         # the units a Ctrl-C during a read's probe kept from starting: all, skipped
    if probe_first:
        boxes = {}
        for t, _ in units:
            boxes.setdefault((t.host, resolve_target_port(t)), t)     # a job may name a device in several entries
        limit, probe_note = fit_probes_to_open_files(min(MAX_PROBES, len(boxes)))
        if probe_note:
            print(f"WARNING: {probe_note}", file=sys.stderr)
        probe_started = time.monotonic()
        try:
            answers = await probes.probe(list(boxes.values()),
                                         connect_budget(args.connect_timeout, args.session_timeout),
                                         args.slow, limit, user=user, held=held_by(safety_gate, boxes.values()))
        except (asyncio.CancelledError, KeyboardInterrupt):
            if has_edits:
                raise           # an edit stopped before its questions is no run (see above)
            # A read stopped during its probe: no device was started. The run
            # ends here as an interrupted one, its row kept, every device skipped.
            interrupted, not_started, answers = True, len(units), []
        probe_ms = int((time.monotonic() - probe_started) * 1000)
        found = dict(zip(boxes, answers))
        for i, (t, _) in enumerate(units):
            r = found.get((t.host, resolve_target_port(t)))
            if r is not None and r.dead:
                dead[i] = r
        if not interrupted and (show_progress or (has_edits and not json_mode)):
            print(f"\n{probe_summary(list(found.values()), probe_ms / 1000, args.slow)}")
        # The boxes an edit goes to: every box of -eC, -eD, -eB and --rollback,
        # the boxes of a job's edit entries. Only their being dead stops the edit.
        edited = {(t.host, resolve_target_port(t)) for t, je in units if je is None or je.mode.startswith("edit")}
        down = [r for box, r in found.items() if r.dead and box in edited] if has_edits else []
        if down:
            reachable = sum(1 for r in found.values() if not r.dead)
            listing = "\n".join(f"  {r.device:16s} ({r.host}) {r.verdict}" for r in down)
            if not json_mode:
                print(listing)
            go_on = False
            if reachable and args.skip_unreachable:
                go_on = True
                print(f"Skipping {len(down)} unreachable device(s) (--skip-unreachable): "
                      f"{', '.join(r.device for r in down)}", file=sys.stderr)
            elif reachable and _tty(sys.stdin):
                if json_mode:       # stdout stays the JSON: the boxes and the question go to the terminal
                    print(listing, file=sys.stderr)
                try:
                    go_on = _ask(f"Continue with the {reachable} reachable? [y/N]: ").strip().lower() in ("y", "yes")
                except PromptClosed:
                    pass
                except KeyboardInterrupt:
                    print(file=sys.stderr)
            if not go_on:
                if args.audit_log:
                    for i, r in dead.items():
                        t, je = units[i]
                        write_audit_entry(path=args.audit_log, device=t.name, host=t.host, vendor=t.vendor,
                                          mode=je.mode if je else mode, payload="", ok=False,
                                          error=f"preflight probe failed: {r.verdict} (aborted)")
                names = [r.device for r in down]
                if json_mode:
                    print(json.dumps({"error": f"{len(down)} device(s) unreachable", "unreachable": names,
                                      "reasons": {r.device: r.verdict for r in down}}))
                else:
                    print(f"\nERROR: {len(down)} device(s) unreachable: {', '.join(names)}")
                    print("Aborting to prevent partial deployment" +
                          (f"; --skip-unreachable goes on with the {reachable} reachable." if reachable
                           else ": no device answered the probe."))
                return 2
            leave_out = {i for i in dead if (units[i][0].host, resolve_target_port(units[i][0])) in edited}

    if commits and not args.show_diff:
        if not json_mode:
            print(f"\nReady to execute on {len(units) - len(dead)} device(s).")     # a dead box is not run
        if not args.yes:
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
    unreachable = 0                                          # left out by an edit after the probe (in the results)
    not_run = skipped_missing if not job_entries else 0      # no set file (--allow-missing): not in the results
    json_results = []
    given_at = []        # each result's place in target order, for --diff
    run_start = time.time()
    store_tried = store_lost = 0      # device results handed to the store, and those it could not keep
    store_reason = None
    unkept = []                       # --every: those results' rows, compared as the tick got them
    if has_edits and not (args.show_diff and commits) and not _begin_run():
        return 2


    # A job may list one device in several entries. Those run one at a time
    # per device, in file order, so a show after an edit sees the edit and the
    # safety gate never meets the second entry as an "active connection". A
    # device is its host and the port its transport uses: two routers behind
    # one address run side by side (#145).
    device_locks = {}

    def _device_lock(t):
        if not job_entries:
            return contextlib.nullcontext()
        return device_locks.setdefault((t.host, resolve_target_port(t)), asyncio.Lock())

    # A job's device keeps its pooled session from one entry to the next,
    # and no longer: after its last entry the session is closed, so a job
    # through many routers holds none for the ones it is done with (#147).
    last_entry = {}
    if job_entries:
        for i, (t, _) in enumerate(units):
            if drivers.get(t.vendor).transport.pooled:
                last_entry[(t.host, resolve_target_port(t))] = i
    release_after = set(last_entry.values())

    def _release_session(t) -> None:
        release = getattr(drivers.module_of(drivers.get(t.vendor)), "release", None)
        if callable(release):
            try:
                release(t.host, user, passwd, port=t.port)
            except Exception:
                pass        # the end of the run closes it all the same

    async def _bounded_run(t, mode_override=None, cmd_override=None, dry_run=None, expected_diff=None,
                           started=None, seq=0, save=True, logs_in=True):
        async with _device_lock(t), sem:
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
                connect_timeout=args.connect_timeout,
                command_timeout=args.command_timeout,
                dry_run=dry_run,
                payload_text=(broadcast_text if actual_mode == "edit-broadcast"
                              else edit_payloads.get(t.name) if actual_mode == "edit-dir" else None),
                commit_confirmed=args.commit_confirmed,
                save_dir=save_dir if save else None,
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
                seq=seq,
                stop=stopped,
                logs_in=logs_in,
            )

    started = set()      # unit indices whose device may already be in play
    inflight = set()     # of those, the ones still running when Ctrl-C came
    stopped = threading.Event()      # set on Ctrl-C: an attempt in flight is that device's last

    def _dead_result(i):
        """The result of a unit whose box the probe found dead: the probe's
        words, as the runner words a failure; the device is not touched."""
        t, je = units[i]
        error = f"probe: {dead[i].verdict}" + ("; skipped" if i in leave_out else "")
        text = (f"DEVICE: {t.name}\nHOST:   {t.host}\nMODE:   {je.mode if je else mode}\nVENDOR: {t.vendor}\n\n"
                f"ERROR: {error}\n")
        if save_dir:
            secure_write(str(path_inside(save_dir, save_name(t.name, seq_of[i] if je else 0))), text)
        return RunResult(t.name, False, text, dead[i].duration_ms, error=error)

    async def _run_unit(i, dry_run=None, expected_diff=None, save=True, logs_in=True):
        """units[i] on its device, in its own mode and command for a job
        entry; the index comes back with the result. save=False keeps its
        result out of --save-output (a --show-diff preview); logs_in=False
        for a unit that rides the session the run has open to its device."""
        t, je = units[i]
        if i in dead:
            return i, _dead_result(i)
        mark = lambda: started.add(i)
        if je is not None:
            result = await _bounded_run(t, je.mode, je.command, dry_run=dry_run, expected_diff=expected_diff,
                                        started=mark, seq=seq_of[i], save=save, logs_in=logs_in)
        else:
            result = await _bounded_run(t, dry_run=dry_run, expected_diff=expected_diff, started=mark, save=save,
                                        logs_in=logs_in)
        if i in release_after and pool.POOL.enabled:
            await asyncio.to_thread(_release_session, t)
        if not isinstance(result, RunResult):
            # A stand-in runner that still returns the bare tuple: the error is
            # read from its text, as it always was.
            name, ok, text, ms = result
            result = RunResult(name, ok, text, ms, error=None if ok else error_line(text))
        return i, result

    # --show-diff: every edit's diff first, one question, then the real
    # run, which commits each diff only if the device produces it again.
    # Only the units that commit are previewed: a job's show is a read, run
    # after the question. A preview is saved nowhere: --save-output keeps
    # what the run did, so an answer other than y leaves its files as they
    # were, where the preview was written over them (#144).
    expected = {}
    if args.show_diff and commits:
        previews = [asyncio.create_task(_run_unit(i, dry_run=True, save=False)) for i, (_, je) in enumerate(units)
                    if i not in dead and (je is None or je.mode.startswith("edit"))]
        preview_failed = []
        for coro in asyncio.as_completed(previews):
            try:
                i, res = await coro
            except (asyncio.CancelledError, KeyboardInterrupt):
                # As in the run itself (_completed): a preview whose connect
                # runs out after Ctrl-C is not tried again.
                stopped.set()
                raise
            name, ok, out_text = res.name, res.ok, res.text
            # stdout stays the JSON array in --json mode; the previews go to
            # stderr, sanitised when that stream is a terminal. What is kept
            # (the diff the commit must find again, the audit entry) is the reply.
            stream = sys.stderr if json_mode else sys.stdout
            print(f"\n--- {name}: {'diff' if ok else 'FAILED'} ---", file=stream)
            print((terminal_safe(out_text) if _tty(stream) else out_text).rstrip(), file=stream)
            if ok:
                # The diff the commit must find again, as the device gave it;
                # "" when the preview said NO CHANGES.
                expected[i] = res.result.diff if isinstance(res.result, R.EditResult) else ""
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
        if not _begin_run():
            return 2

    if job_entries:
        # A job lists one device in several entries. With the pool on they
        # share one session per device instead of logging in once per entry
        # (#57); the pool's per-router lock keeps a host's entries in order,
        # and an edit entry's session is clean again before the next one.
        pool.enable()

    tasks = [] if interrupted else [asyncio.create_task(_run_unit(i, expected_diff=expected.get(i),
                                                                 logs_in=i not in rides))
                                    for i in range(len(units))]
    screen = _tty(sys.stdout)     # control sequences are stripped for a terminal, kept for a pipe

    def _screen(text: str) -> str:
        """Device text as it goes to stdout: a terminal gets it with what it
        would act on taken out, a pipe gets it as it came. The record (the
        store, --log, --json) is the reply as it came either way."""
        return terminal_safe(text) if screen else text

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
                # A device whose attempt fails from here on is not tried
                # again: a connect that ran out is a NotAppliedError, and an
                # edit retried after the operator stopped the run could commit.
                stopped.set()
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
        shown = _screen(out_text)
        t, je = units[i]
        # A job entry runs in its own mode; everything else in the run's.
        dev_mode = je.mode if je else mode
        # The show this device ran, resolved for its vendor (a shortcut can
        # differ device to device), a job's show entry its own: the command
        # field, and the '$ cmd' echo a text transport opens its reply with.
        dev_show = je.command if je and je.mode == "show" else show_cmd
        resolved_cmd = resolve_command(dev_show, t.vendor) if dev_show else None
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
                        cr["output"] = strip_echo(cr["output"], cr["command"])
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
        given_at.append(i)

        # What was sent to this device, for the audit log and the store: the
        # resolved show, the edit payload, the rollback, the commit history ask.
        sent = ""
        if mode == "edit-cmd":
            sent = edit_cmd or ""
        elif mode == "edit-dir":
            sent = edit_payloads.get(name) or f"<no config file for {name}>"
        elif mode == "edit-broadcast":
            sent = broadcast_text or ""
        elif mode == "rollback":
            sent = f"rollback {args.rollback}"
        elif mode == "commit-status":
            sent = "show system commit"
        elif mode == "job":
            sent = ((resolve_command(je.command, t.vendor) if je.mode == "show" else je.command)
                    if je.command else "")
        elif mode == "show":
            sent = resolve_command(show_cmd, t.vendor) if show_cmd else ""
        elif mode == "show-batch":
            sent = json.dumps([resolve_command(c, t.vendor) for c in batch_cmds]) if batch_cmds else ""

        if store_run is not None:
            store_tried += 1
            try:
                # A job entry's row is at its place among its device's entries:
                # seq_of, the count its --save-output file is named by as well.
                store.add_entry(store_run, entry, sent,
                                fmt=args.format if dev_mode in ("show", "show-batch") else "text",
                                seq=seq_of[i] if je else 0)
                # SQLite writes into a deleted or replaced file without a
                # word; one stat per result says so as it happens, not at the end.
                gone = store.still_there() if store_reason is None else None
            except Exception as e:
                store_lost += 1
                gone = str(e)
                if args.every is not None:
                    unkept += _watch_rows(entry, sent)
            if gone is not None and store_reason is None:
                # The run goes on, the results are still shown; the loss is
                # counted and said once more, with the exit code, at the end.
                store_reason = gone
                print(f"WARNING: store {store.path}: {gone}; the run goes on, its results are shown but not kept",
                      file=sys.stderr)

        # Audit logging for operations
        if args.audit_log:
            audit_payload = sent
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
        # later in the loop or an OOM loses nothing already reported. It holds
        # the replies and the edit diffs (and an -eC payload, as its command),
        # so it gets the audit log's redaction and file mode.
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
                            print(_screen(strip_echo(document_text(cr["output"]), cr["command"])))
                        else:
                            print(f"{name}: {cr.get('command')}: {cr.get('error')}", file=sys.stderr)
                    print()
                else:
                    print(f"{name}: ERROR: {res.error}" if res.error is not None else f"{name}: failed", file=sys.stderr)
            elif ok:
                print(f"{name}:")
                print(strip_result_header(shown, resolved_cmd))
                print()
            else:
                # stdout stays device output only, so failures go to stderr.
                print(f"{name}: ERROR: {res.error}" if res.error is not None else f"{name}: failed", file=sys.stderr)

        if show_progress:                 # the per-device verdict line; a --every tick prints its changes instead
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
                                print(_screen(document_text(cr.get("output", ""))))
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
                        print(shown)
                        print(f"--- End of {name} ---\n")
                    elif not ok and res.error is not None:
                        print(f"  ERROR: {res.error}")
            else:
                status = ("OK" if ok else "SKIPPED" if i in leave_out
                          else "INTERRUPTED" if entry.get("interrupted") else "FAIL")
                print(f"[{timestamp}] {name:16s} {status}")

                if args.verbose:
                    print(f"\n--- Output from {name} ---")
                    print(shown)
                    print(f"--- End of {name} ---\n")
                elif ok and (dev_mode.startswith("edit") or dev_mode == "rollback"):
                    print(format_edit_result(shown))
                elif not ok and res.error is not None:
                    print(f"  ERROR: {res.error}")

        if not ok:
            if i in leave_out:
                unreachable += 1
            elif entry.get("error", "").startswith("safety gate blocked"):
                skipped += 1
            elif entry.get("interrupted"):
                interrupted_connects += 1
            else:
                failures += 1

    closing = time.monotonic()
    if job_entries:
        pool.close_all(shutdown=False)   # the run is over: every session closed cleanly, in parallel
        pool.disable()
    # One second in all for the closes: close_all() has already waited on its own (#113).
    _drain_closes(max(0.0, 1.0 - (time.monotonic() - closing)))

    # Cross-device diff (show modes only). The results go back into target
    # order: the baseline is the first device in it that answered, not the
    # first to answer, and --json lists the devices in it, so one command
    # line diffs the same way, and lists the same way, every run. A reply
    # is trimmed, so its last line has no newline: lines are compared
    # without theirs and joined with one. With the newlines kept, a last
    # line would not match itself once a line follows it, and a changed
    # one would run into the line put in after it.
    ok_results = []
    if args.diff and mode in ["show", "show-batch"]:
        # Every result has its place: one without is an error, not a device left out.
        json_results[:] = [r for _, r in sorted(zip(given_at, json_results, strict=True), key=lambda p: p[0])]
        ok_results = [r for r in json_results if r["ok"]]
        if len(ok_results) >= 2:
            baseline = ok_results[0]
            baseline_name = baseline["device"]

            if mode == "show":
                baseline_lines = document_text(baseline["output"]).splitlines()
                for other in ok_results[1:]:
                    other_lines = document_text(other["output"]).splitlines()
                    diff_lines = list(difflib.unified_diff(
                        baseline_lines, other_lines,
                        fromfile=baseline_name, tofile=other["device"], lineterm="",
                    ))
                    diff_text = "\n".join(diff_lines)
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
                            bl.splitlines(),
                            document_text(cr["output"]).splitlines(),
                            fromfile=baseline_name, tofile=other["device"], lineterm="",
                        ))
                        diff_text = "\n".join(diff_lines)
                        cmd_diffs.append({
                            "command": cr["command"],
                            "diff": diff_text if diff_text else "(identical)",
                        })
                    other["diff"] = cmd_diffs
                baseline["diff"] = "(baseline)"

    if json_mode:
        print(json.dumps(json_results, indent=2))
    else:
        # Print diff output, sanitised a line at a time: the diff is of the
        # replies as they came, where VT, FF and NEL end a line, and taken out
        # of the whole text they would run a removed line into the one before.
        if args.diff and mode in ["show", "show-batch"]:
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
                                print(f"    {_screen(ln)}")
                            print()
                    elif mode == "show-batch":
                        print(f"  {baseline_name} vs {other['device']}:")
                        for cd in other.get("diff", []):
                            print(f"    [{cd['command']}]")
                            if cd["diff"] == "(identical)":
                                print(f"      (identical)")
                            else:
                                for ln in cd["diff"].splitlines():
                                    print(f"      {_screen(ln)}")
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
                ([f"skipped for want of a set file: {not_run}"] if not_run else []) + \
                ([f"skipped as unreachable: {unreachable}"] if unreachable else [])
        if failures:
            verdict = f"Done. Failures: {failures}" + (", " + ", ".join(notes) if notes else "")
        elif notes:
            applied = len(json_results) - skipped - unreachable
            verdict = f"Done. OK: {applied}, " + ", ".join(notes)
            if has_edits and not applied:
                verdict += ", nothing applied"
        else:
            verdict = "Done. All devices OK."
        if not raw_mode and args.every is None:
            print("")
            if failures or skipped or not_run or unreachable or not interrupted:
                print(verdict)
        elif failures or skipped or not_run or unreachable:
            # stdout is device output only; the verdict belongs on stderr.
            print(verdict, file=sys.stderr)

        # The reminder is for timers that are actually running: a device
        # that was refused, failed, or had no changes armed nothing.
        armed = [e for e in json_results
                 if e.get("ok") and re.search(r"COMMIT (OK|CONFIRMED \()", str(e.get("output") or ""))]
        if args.commit_confirmed and not args.dry_run and has_edits and armed:
            # A job's timers are armed on its edit entries' targets, not on
            # the inventory file or a run file's `devices` beside its jobs (a
            # target typed beside a job is refused, and so are a run file's
            # `devices` beside a typed --job).
            specs = args.target
            if job_entries:
                specs = list(dict.fromkeys(target_spec(je.target) for je in job_entries
                                           if je.mode.startswith("edit")))
            print("")
            print("=" * 70)
            print(" " * 15 + "DON'T FORGET TO CONFIRM THE COMMIT!")
            print("=" * 70)
            print(f"Run this command to confirm within {args.commit_confirmed} minutes:")
            print("  " + build_confirm_command(user, specs, args.devices, args.transport, bare=bare_hosts))
            print("\nOr the changes will automatically rollback!")
            print("=" * 70)
            print("")

    # Structured stderr summary
    elapsed_ms = int((time.time() - run_start) * 1000)
    ok_count = len(json_results) - failures - skipped - unreachable - interrupted_connects
    stderr_mode = "batch" if mode == "show-batch" else ("job" if mode == "job" else mode.split("-")[0])
    not_kept = 0
    if store_run is not None:
        gone = store.still_there()
        if gone is not None:              # SQLite kept writing into the void; nothing of this run is on disk
            not_kept, store_reason = store_tried, gone
        else:
            not_kept = store_lost
    summary = json.dumps({
        "targets": len(json_results) + not_run,
        "ok": ok_count,
        "fail": failures,
        "skipped": skipped + not_run + unreachable + not_started,
        **({"interrupted": interrupted_connects} if interrupted else {}),
        **({"not_kept": not_kept} if not_kept else {}),
        **({"probe_ms": probe_ms} if probe_ms is not None else {}),
        "elapsed_ms": elapsed_ms,
        "mode": stderr_mode,
    })
    print(f"[h-ssh] {summary}", file=sys.stderr)

    if store_run is not None:
        # The run row is closed when any result was kept; with nothing kept
        # it stays open (`?/?` in `h-ssh-store runs`), a true record of a run
        # that could not keep its results.
        if not_kept < store_tried or store_tried == 0:
            try:
                store.finish_run(store_run, ok_count, failures, skipped + not_run + unreachable + not_started,
                                 interrupted)
            except Exception as e:
                print(f"WARNING: store {store.path}: {e}", file=sys.stderr)
        lost = f"{not_kept} of {store_tried} results were not kept: {store_reason}" if not_kept else None
        if lost:
            print(f"WARNING: store {store.path}: {lost}", file=sys.stderr)
        if args.every is not None:
            _WATCH["tick"] += 1
            if not lost:
                _WATCH["kept"] += 1        # the store has all of this tick: what Ctrl-C calls kept
            _WATCH["previous"] = _watch_report(store, store_run, _WATCH["previous"], _WATCH["tick"], ok_count,
                                               failures, lost, unkept)
            _WATCH["every"] = args.every
            _WATCH["again"] = not interrupted and (args.times is None or _WATCH["tick"] < args.times)
    if store is not None:
        store.close()

    if safety_gate is not None:
        safety_gate.close()

    if interrupted:
        return 130  # 128 + SIGINT, the shell convention
    if not_kept:
        return 4    # the run's record is incomplete: results were not kept (before 1 and 3; `fail` is in the summary)
    if failures:
        return 1
    return 3 if skipped or not_run or unreachable else 0   # 3: nothing failed, but not everything ran


# --every: the watch's state between ticks. main() runs one tick and leaves
# `again` for main_sync(), which sleeps and runs the next; `passwd` is what
# the prompt got before tick 1, asked once for the whole watch; `previous`
# the tick before's rows; `store` the identity of the file tick 1 was kept
# in; `kept` how many ticks the store kept in full.
_WATCH = {"tick": 0, "previous": None, "again": False, "every": None, "passwd": None, "store": None, "kept": 0}

# A watch exits with the worst of its ticks, in this order: interrupted,
# results not kept, refused (a tick that cannot start ends the watch), a
# device failed, not everything ran, fine.
_WATCH_CODES = (130, 4, 2, 1, 3, 0)


def _worst(a: int, b: int) -> int:
    return min(a, b, key=lambda code: _WATCH_CODES.index(code) if code in _WATCH_CODES else len(_WATCH_CODES))


def _watch_sleep(seconds: float) -> None:
    time.sleep(seconds)


def _watch_rows(entry: dict, command: str) -> list:
    """A device's result as the store's rows hold it (a batch is a row per
    command), for a result the store could not keep: the watch compares it
    all the same."""
    def text(out):
        return out if out is None or isinstance(out, str) else json.dumps(out)

    ts = datetime.now().astimezone().isoformat(timespec="seconds")
    row = {"device": entry["device"], "ts": ts}
    if isinstance(entry.get("commands"), list) and entry["commands"]:
        return [{**row, "seq": seq, "command": cr.get("command", ""), "ok": 1 if cr.get("ok") else 0,
                 "error": cr.get("error"), "output": text(cr.get("output"))}
                for seq, cr in enumerate(entry["commands"])]
    return [{**row, "seq": 0, "command": command, "ok": 1 if entry.get("ok") else 0,
             "error": entry.get("error"), "output": text(entry.get("output"))}]


def _watch_report(store, run_id: str, previous: Optional[dict], tick: int, ok: int, failed: int,
                  lost: Optional[str] = None, unkept=()) -> dict:
    """One line per tick and, for every device whose reply changed since the
    tick before, the difference: the thing a watch is for. Every tick is a
    run in the store, so `h-ssh-store diff` can go back to any two of them.
    `lost` is what the store could not keep of this tick, in the warning's
    words, and the tick's line says it: a baseline that is not all there is
    not called kept. `unkept` is those results' rows: compared as the tick
    got them, so a reply the store lost hides no change and is not new on
    the tick after. Returns this tick's rows, the next tick's `previous`."""
    stamp = time.strftime("%H:%M:%S")
    rows = {(r["device"], r["seq"]): r for r in store.results(run_id=run_id)}
    for r in unkept:
        rows.setdefault((r["device"], r["seq"]), r)
    if previous is None:
        kept = f"baseline not kept ({lost})" if lost else f"baseline kept as run {run_id}"
        print(f"tick {tick} {stamp}: {ok} OK, {failed} failed; {kept}", flush=True)
        return rows
    changed = []
    for key in sorted(rows):
        r, p = rows[key], previous.get(key)
        if p is None or (p["ok"], p["output"], p["error"]) != (r["ok"], r["output"], r["error"]):
            changed.append((r, p))
    print(f"tick {tick} {stamp}: {ok} OK, {failed} failed, {len(changed)} changed" + (f"; {lost}" if lost else ""),
          flush=True)
    safe = terminal_safe if _tty(sys.stdout) else (lambda text: text)      # the rows are the replies as they came
    for r, p in changed:
        command = (r["command"] or "").strip().splitlines()[0] if (r["command"] or "").strip() else ""
        head = f"--- {r['device']}: {command[:60]}"
        if p is None:
            print(f"{head}: new")
            continue
        if r["ok"] != p["ok"]:
            error = (r["error"] or "").strip().splitlines()[0] if r["error"] else ""
            head += f": {'OK' if p['ok'] else 'FAIL'} -> {'OK' if r['ok'] else 'FAIL'}" + (f" ({error})" if error else "")
        print(safe(head))
        a, b = (p["output"] or "").splitlines(), (r["output"] or "").splitlines()
        for line in difflib.unified_diff(a, b, fromfile=p["ts"][:19], tofile=r["ts"][:19], lineterm="", n=1):
            print("  " + safe(line))
    sys.stdout.flush()
    return rows

def _drain_closes(timeout: float = 1.0) -> None:
    """Sessions are closed beside the work; before the run reports, wait
    for the closes still in flight (the junos transport has them, if it
    was loaded at all)."""
    mod = sys.modules.get("hssh.transports.netconf")
    if mod is not None:
        try:
            mod.wait_for_closes(timeout)
        except Exception:
            pass


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
    _WATCH.update(tick=0, previous=None, again=False, every=None, passwd=None, store=None, kept=0)
    try:
        rc = asyncio.run(main())
        while _WATCH["again"]:      # --every: the tick left word that another follows
            _WATCH["again"] = False
            _watch_sleep(_WATCH["every"])
            rc = _worst(rc, asyncio.run(main()))    # a tick that failed is not forgotten by a clean one after it
        sys.stdout.flush()          # a reader that left shows up here, not at interpreter exit
    except KeyboardInterrupt:
        # Ctrl-C is a normal way to stop a fleet run; a stack trace is not a
        # useful thing to print at someone who already knows what they did.
        ticks, kept = _WATCH["tick"], _WATCH["kept"]
        said = f" {kept} tick(s) kept in the store" + (f", {ticks - kept} not kept in full" if kept < ticks else "")
        print("\nInterrupted." + (said + "." if ticks else ""), file=sys.stderr)
        rc = 130
    except BrokenPipeError:
        # `h-ssh ... | head`: the reader has what it wanted. Not an error of
        # ours, and not a traceback; the run's own verdict, if it got that
        # far, stands.
        _stdout_gone()
    finally:
        _WATCH["passwd"] = None     # the watch is over; its credential is not kept around
        # Half a second in all for the closes, close_all()'s own wait included (#113).
        closing = time.monotonic()
        try:
            pool.close_all(wait=0.5)    # a job run that ended early (Ctrl-C, a crash) leaves no session open
        except Exception:
            pass
        _drain_closes(max(0.0, 0.5 - (time.monotonic() - closing)))
    sys.exit(rc)
