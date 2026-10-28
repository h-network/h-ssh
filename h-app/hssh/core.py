"""Core utilities for h-ssh package."""

import csv
import json
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from . import drivers


# A device name becomes a file name (<name>.set, <name>.output): hostname
# characters only, nothing that pathlib would read as a directory, a parent
# or an option.
_DEVICE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]*")


def validate_device_name(name: str) -> str:
    """The name of a target, as it may appear in a file path. Anything with a
    separator, a leading '-' or '.', or empty, is a ValueError: a '../' in an
    inventory row once chose which local file became the pushed config and
    where the device's output was written."""
    if not isinstance(name, str) or not _DEVICE_NAME.fullmatch(name):
        raise ValueError(f"invalid device name {name!r}: letters, digits, '_', '.', ':' and '-' only, "
                         "not starting with '-' or '.'")
    return name


def path_inside(base: str, filename: str) -> Path:
    """`<base>/<filename>`, refused unless it stays inside `base` once resolved."""
    root = Path(base).resolve()
    target = (root / filename).resolve()
    if target.parent != root:
        raise ValueError(f"{filename!r} does not stay inside {base}")
    return Path(base) / filename


@dataclass
class Target:
    name: str
    host: str  # IP or resolvable hostname
    vendor: str = "ssh"  # Default: plain SSH, the transport that assumes least
    port: Optional[int] = None  # None = vendor default (22/23/830)

    def __post_init__(self):
        validate_device_name(self.name)


def _is_comment_or_empty(line: str, comments: Tuple[str, ...] = ("#",)) -> bool:
    s = line.strip()
    return not s or s.startswith(tuple(comments))


def check_port(value, where: str) -> int:
    """A TCP port as a number in 1..65535; anything else names where it came from."""
    if isinstance(value, bool):
        raise ValueError(f"{where}: 'port' must be a number, not a boolean")
    if isinstance(value, str):
        if not value.strip().isdigit():
            raise ValueError(f"{where}: 'port' must be a number, not {value!r}")
        value = int(value.strip())
    if not isinstance(value, int):
        raise ValueError(f"{where}: 'port' must be a number, not {type(value).__name__}")
    if not 1 <= value <= 65535:
        raise ValueError(f"{where}: port {value} is outside 1..65535")
    return value


def check_unique(targets: List["Target"], allow_repeats: bool = False) -> None:
    """One name is one device and one device is one name. A name under two
    hosts, or one host under two names, is a mistake that would commit to
    the wrong box or twice; the same row twice (allow_repeats=False) runs a
    device twice and writes both results to one file. A job may repeat a
    device on purpose (its entries run in order), so it allows repeats but
    not contradictions. A device is its host and the port the transport
    will use, so `R1:10.0.0.1:junos` and `R2:10.0.0.1:830:junos` are one
    box under two names; the message keeps the port as typed. Raises
    ValueError naming the duplicate."""
    by_name: dict = {}     # name -> ((host, port in use), host[:port] as typed)
    by_host: dict = {}     # (host, port in use) -> name
    for t in targets:
        where = (t.host, resolve_target_port(t))
        typed = f"{t.host}:{t.port}" if t.port else t.host
        if t.name in by_name and by_name[t.name][0] != where:
            other, other_typed = by_name[t.name]
            if other_typed == typed:      # the same host, the ports differ only by default: say which
                other_typed, typed = f"{other[0]}:{other[1]}", f"{where[0]}:{where[1]}"
            raise ValueError(f"device name {t.name!r} is used for two hosts: {other_typed} and {typed}")
        if where in by_host and by_host[where] != t.name:
            raise ValueError(f"host {typed} is listed under two names: {by_host[where]!r} and {t.name!r}")
        if not allow_repeats and t.name in by_name:
            raise ValueError(f"device {t.name!r} ({t.host}) is listed twice")
        by_name[t.name] = (where, typed)
        by_host[where] = t.name


def load_devices_csv(path: str, default_vendor: str = "ssh") -> List[Target]:
    """
    Accepts:
      - CSV with header name,ip or name,ip,vendor
      - CSV without header
      - Lines with just a name
      - Inline or full-line comments '#'

    A row that doesn't declare a vendor gets default_vendor (the CLI passes
    --transport); a declared one always wins.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Devices file not found: {path}")

    targets: List[Target] = []
    # utf-8-sig: an inventory saved by Excel or Notepad starts with a BOM,
    # which is not part of the first device's name.
    raw_lines = p.read_text(encoding="utf-8-sig").splitlines()

    filtered = [ln for ln in raw_lines if not _is_comment_or_empty(ln)]

    # If no comma anywhere, treat as "one name per line"
    if not any("," in ln for ln in filtered):
        for ln in filtered:
            name = ln.split("#", 1)[0].strip()
            if name:
                targets.append(Target(name=name, host=name, vendor=default_vendor))
        return targets

    # Otherwise parse as CSV
    cleaned_rows = []
    for ln in filtered:
        ln = ln.split("#", 1)[0].strip()
        if ln:
            cleaned_rows.append(ln)

    reader = csv.reader(cleaned_rows)
    rows = list(reader)
    if not rows:
        return targets

    first = [c.strip().lower() for c in rows[0]]
    has_header = len(first) >= 1 and first[0] == "name"
    start_idx = 1 if has_header else 0

    for i, r in enumerate(rows[start_idx:], start=start_idx + 1):
        if not r:
            continue
        if len(r) > 4:
            raise ValueError(f"{path} row {i}: {len(r)} columns; expected name,ip[,vendor[,port]]")
        name = r[0].strip()
        ip = r[1].strip() if len(r) > 1 else ""
        vendor = r[2].strip().lower() if len(r) > 2 else default_vendor
        port_str = r[3].strip() if len(r) > 3 else ""
        port = check_port(port_str, f"{path} row {i} ({name or '?'})") if port_str else None
        if not name:
            continue
        host = ip if ip else name
        targets.append(Target(name=name, host=host, vendor=vendor, port=port))

    return targets



def get_config_path() -> Path:
    """Where per-user defaults live, alongside devices.csv."""
    return Path.home() / ".h-ssh" / "config"


CONFIG_CREDENTIAL_KEYS = ("password", "passwd", "secret", "token", "pass")


def load_config(path: str = None) -> Dict[str, str]:
    """Read 'key = value' defaults. Missing file is not an error.

    Deliberately not INI or YAML: no sections to get wrong, no dependency, and
    the same '#' comment handling the devices file already has.
    """
    p = Path(path) if path else get_config_path()
    if p.is_dir():
        raise ValueError("is a directory, not a config file")
    if not p.is_file():
        return {}

    config = {}
    try:
        text = p.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("is not UTF-8 text")
    for n, line in enumerate(text.splitlines(), start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            raise ValueError(f"line {n}: expected 'key = value', got {line!r}")
        key, value = line.split("=", 1)
        key = key.strip().lower().replace("-", "_")
        value = value.strip().strip('"').strip("'")
        if key in CONFIG_CREDENTIAL_KEYS:
            # Refused, not ignored: a password left in a world-readable file
            # is the harm, and a run that quietly went on to key auth would
            # hide it. The run file says the same (hssh.runfile).
            raise ValueError(f"line {n}: '{key}' is not allowed, a config file never carries a "
                             "credential: use HSSH_PASSWORD or the prompt")
        if key and value:
            config[key] = value
    return config


# NAME:[v6]... — an IPv6 literal has colons of its own, so it goes in brackets.
_BRACKETED_HOST = re.compile(r"^([^:]+):\[([^\]]+)\](?::(.*))?$")


def parse_bare_target(spec: str, default_vendor: str = "ssh") -> Target:
    """A target typed bare on the command line. A host alone (`10.0.0.1`,
    `cr1.example.net`, `[2001:db8::1]`) is a device named after itself on
    default_vendor; a word with a separator is the --target form,
    NAME:HOST[:VENDOR][:PORT], and parses as one."""
    spec = spec.strip()
    if not spec:
        raise ValueError("Invalid target: an empty word")
    if spec.startswith("[") and spec.endswith("]") and ":" in spec:
        host = spec[1:-1]
        return Target(name=host, host=host, vendor=default_vendor)
    if ":" not in spec:
        return Target(name=spec, host=spec, vendor=default_vendor)
    return parse_inline_target(spec, default_vendor=default_vendor)


def parse_inline_target(spec: str, default_vendor: str = "ssh") -> Target:
    """Parse inline target string: NAME:HOST[:VENDOR][:PORT] or NAME:HOST[:PORT][:VENDOR].

    Handles port-style targets (e.g., SW1:10.0.0.1:5000:telnet-ios)
    and vendor-style targets (e.g., R1:10.0.0.1:junos). A spec that names
    no vendor gets default_vendor (the CLI passes --transport). An IPv6
    host goes in brackets, since its own colons would read as separators
    (e.g., R1:[2001:db8::1]:830:junos); the brackets are stripped.
    """
    m = _BRACKETED_HOST.match(spec)
    if m:
        parts = [m.group(1), m.group(2)]
        if m.group(3) is not None:
            parts += m.group(3).split(":")
    else:
        parts = spec.split(":")
    if len(parts) < 2:
        raise ValueError(f"Invalid target: {spec!r} (expected name:host[:vendor][:port])")

    name = parts[0]
    host = parts[1]

    def port_of(text: str) -> int:
        if not text.isdigit():
            raise ValueError(f"Invalid target: {spec!r} (port {text!r} is not a number)")
        return check_port(text, f"Invalid target {spec!r}")

    if len(parts) == 2:
        return Target(name=name, host=host, vendor=default_vendor)
    elif len(parts) == 3:
        if parts[2].isdigit():
            return Target(name=name, host=host, port=port_of(parts[2]), vendor=default_vendor)
        return Target(name=name, host=host, vendor=parts[2].lower())
    elif len(parts) == 4:
        if parts[2].isdigit():
            return Target(name=name, host=host, port=port_of(parts[2]), vendor=parts[3].lower())
        return Target(name=name, host=host, vendor=parts[2].lower(), port=port_of(parts[3]))
    else:
        raise ValueError(f"Invalid target: {spec!r} (expected name:host[:vendor][:port]; "
                         "an IPv6 host goes in brackets)")


CONFIRM_MINUTES = (1, 65535)   # what Junos accepts for `commit confirmed`


def check_confirm_minutes(minutes) -> None:
    """A rollback timer that cannot be armed is a ValueError, never a plain
    commit: 0 and negative values once committed permanently behind a banner
    promising a rollback."""
    if minutes is None:
        return
    lo, hi = CONFIRM_MINUTES
    if not isinstance(minutes, int) or isinstance(minutes, bool) or not lo <= minutes <= hi:
        raise ValueError(f"commit_confirmed must be {lo}..{hi} minutes, got {minutes!r}; "
                         "nothing was sent to the device")


@dataclass
class JobEntry:
    """A single entry from a job file."""
    target: Target
    mode: str      # "show" or "edit"
    command: str   # The command or config payload


def load_jobs(path: str, default_vendor: str = "ssh") -> List[JobEntry]:
    """Load a JSON job file.

    Job file format — JSON array of objects:
    [
      {"target": "R1:192.168.1.1:junos", "show": "show bgp summary"},
      {"target": "R2:192.168.1.2:junos", "edit": "set system host-name R2-new"}
    ]

    Each entry must have:
      - "target": "NAME:HOST[:PORT][:VENDOR]" (no vendor: default_vendor)
      - Exactly one of: "show", "edit"
    """
    if path == "-":
        data = json.load(sys.stdin)
    else:
        with open(path) as f:
            data = json.load(f)
    return parse_jobs(data, default_vendor)


def parse_jobs(data, default_vendor: str = "ssh") -> List[JobEntry]:
    """The job entries from already-parsed data (a --job file, or the `jobs:`
    list of a run file), checked the same way."""
    if not isinstance(data, list) or len(data) == 0:
        raise ValueError("Job file must be a non-empty JSON array")

    entries = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Job entry {i}: must be a JSON object")
        if "target" not in item:
            raise ValueError(f"Job entry {i}: missing 'target'")
        unknown = sorted(set(item) - {"target", "show", "edit", "port"})
        if unknown:
            raise ValueError(f"Job entry {i}: unknown key(s) {', '.join(unknown)} (target, show, edit, port)")
        for key in ("target", "show", "edit"):
            if key in item and not isinstance(item[key], str):
                raise ValueError(f"Job entry {i}: '{key}' must be a string")

        try:
            target = parse_inline_target(item["target"], default_vendor)
        except ValueError as e:
            raise ValueError(f"Job entry {i}: {e}") from e

        # Optional port override
        if "port" in item:
            target.port = check_port(item["port"], f"Job entry {i}")

        has_show = "show" in item
        has_edit = "edit" in item
        if has_show == has_edit:
            raise ValueError(f"Job entry {i} ({target.name}): must have exactly one of 'show' or 'edit'")
        # As for -sC and -eC: a show is one line of text (stripped, as a run
        # file's commands are, so a closing line break is not part of it),
        # an edit plain text, and neither is whitespace alone: such an edit
        # has nothing to apply, and the plain ssh and openssh drivers logged
        # in, sent nothing and said ok (#142).
        key = "show" if has_show else "edit"
        command = item[key].strip() if has_show else item[key]
        if not command.strip():
            raise ValueError(f"Job entry {i} ({target.name}): '{key}' is empty")
        what = control_character(command, line_breaks=has_edit)
        if what:
            raise ValueError(f"Job entry {i} ({target.name}): '{key}' has {what} ({command!r}); "
                             f"{'a command is one line of text' if has_show else 'a payload is plain text'}")

        if has_show:
            entries.append(JobEntry(target=target, mode="show", command=command))
        else:
            entries.append(JobEntry(target=target, mode="edit-cmd", command=item["edit"]))

    return entries


def set_file_payload(text: str, comments: Tuple[str, ...] = ("#",)) -> str:
    """What a -eD or -eB file sends, to every driver: its lines with blank and
    full-line comment lines dropped, nothing else touched; '' when nothing
    is left. A comment line starts with one of `comments`, the target
    dialect's comment_prefixes: '#' on every driver, and '!' too on an
    IOS-shaped one. An inline '#' is part of the line (`set snmp community
    ab#12 ...`), the rule junos._strip_comments applies to every set
    payload. The plain ssh and openssh drivers run each line as a command
    of its own, so the rule is applied before any driver gets the payload,
    not by each."""
    lines = [ln for ln in text.splitlines() if not _is_comment_or_empty(ln, comments)]
    return "\n".join(lines) + "\n" if lines else ""


def comments_named(comments: Tuple[str, ...]) -> str:
    """Comment prefixes as a refusal names them: `'#'`, `'#' or '!'`."""
    return " or ".join(f"'{c}'" for c in comments)


def read_set_file_for_device(config_dir: str, dev_name: str, comments: Tuple[str, ...] = ("#",)) -> str:
    """The -eD payload for one device: `<config_dir>/<dev_name>.set` as
    set_file_payload() makes it for the device's dialect (`comments`), so
    -eD sends what the syntax guard validated, and what -eB sends from the
    same file.
    """
    path = path_inside(config_dir, f"{validate_device_name(dev_name)}.set")
    if not path.is_file():
        raise FileNotFoundError(f"Missing config file for {dev_name}: {path}")
    payload = set_file_payload(path.read_text(encoding="utf-8-sig"), comments)
    if not payload:
        raise ValueError(f"Empty config after filtering: {path}")
    return payload


def is_file(path: Path) -> bool:
    """Path.is_file() the same on every Python: False when nothing is there,
    and any other reason the path cannot be looked at (a directory on the way
    that may not be searched) raised, to be said and not taken for 'not
    found'. Path.is_file() raises that on 3.12; newer ones say False."""
    return _stat_is(path, stat.S_ISREG)


def is_dir(path: Path) -> bool:
    """is_file() for a directory."""
    return _stat_is(path, stat.S_ISDIR)


def _stat_is(path: Path, kind) -> bool:
    try:
        mode = path.stat().st_mode
    except (FileNotFoundError, NotADirectoryError, ValueError):     # nothing there, or a NUL in the name
        return False
    return kind(mode)


def read_failure(e: Exception) -> str:
    """Why a text file could not be read, for an ERROR line: 'not UTF-8 text'
    for one in another encoding, else the system's reason ('Permission denied')."""
    if isinstance(e, UnicodeDecodeError):
        return "not UTF-8 text"
    return getattr(e, "strerror", None) or str(e)


# What a command may not carry: the C0 and C1 control characters and DEL,
# the line breaks among them. A tab is text, except to the CLI engine: the
# one class with the Tab added, so the two cannot come apart.
# C0 controls but Tab, DEL, C1 controls, and the lone surrogates Python makes
# of bytes that are not UTF-8 (an argv, a JSON \udcXX escape): not text.
_CONTROL_CLASS = r"\x00-\x08\x0a-\x1f\x7f-\x9f\ud800-\udfff"
_CONTROL = re.compile(f"[{_CONTROL_CLASS}]")
_CONTROL_OR_TAB = re.compile(f"[\\t{_CONTROL_CLASS}]")
_CONTROL_NAMES = {"\n": "a line break", "\r": "a carriage return", "\x00": "a NUL", "\x1b": "an ESC",
                  "\x7f": "a DEL", "\t": "a Tab"}


def control_character(text: str, line_breaks: bool = False, tabs: bool = True) -> Optional[str]:
    """The first control character in `text`, named ('a line break', 'a NUL',
    'an ESC', else 'a control character' and its repr), or None. A command
    is one line of text: a line break in it runs two commands (and a retry
    both again), a NUL or an ESC is not text. An edit payload is lines, so
    `line_breaks` lets the line breaks through. A Tab is text (NETCONF's
    `load set` reads it as a space) unless `tabs` is False: the CLI engine
    types none, since a CLI completes the word on it."""
    for m in (_CONTROL if tabs else _CONTROL_OR_TAB).finditer(text):
        ch = m.group()
        if line_breaks and ch in "\r\n":
            continue
        if "\ud800" <= ch <= "\udfff":
            return f"a byte that is not UTF-8 {ch!r}"
        return _CONTROL_NAMES.get(ch, f"a control character {ch!r}")
    return None


def control_line(text: str, tabs: bool = True) -> Optional[Tuple[int, str, str]]:
    """What control_character() finds in a payload, its line breaks let
    through, with where it is: (line number, the line, what), for a refusal
    that names the line; None when the payload is plain text."""
    for n, line in enumerate(text.split("\n"), 1):
        line = line.rstrip("\r")
        what = control_character(line, line_breaks=True, tabs=tabs)
        if what:
            return n, line, what
    return None


# Junos logs a commit comment of 1 to 512 bytes of UTF-8; another fails the
# commit at its commit check ("Length N is not within range (1..512)").
COMMENT_BYTES = 512
COMMENT_RULE = f"a commit comment is one line of text, at most {COMMENT_BYTES} bytes"


def comment_fault(comment: str) -> Optional[str]:
    """Why a commit comment, stripped already, cannot be logged as it is, or
    None. Junos keeps only the last line of one with a line break, and fails
    an empty one or one over 512 bytes at the commit check, after the lock,
    the load and the diff; the XML that NETCONF carries it in has no room
    for a control character (an ESC, a NUL) or for U+FFFE and U+FFFF; and
    the CLI engine types it, where a control character or a Tab is a key."""
    if not comment:
        return "has no text"
    what = control_character(comment, tabs=False)
    if what:
        return f"has {what}"
    for ch in comment:
        if ch in "\ufffe\uffff":
            return f"has a character XML cannot carry {ch!r}"
    size = len(comment.encode("utf-8"))
    if size > COMMENT_BYTES:
        return f"is {size} bytes"
    return None


def check_comment(comment, outcome: str = "nothing was sent to the device") -> Optional[str]:
    """The commit comment to send: `comment` stripped of the blanks around
    it (the line break a YAML block ends with among them), or None for none.
    One that cannot be logged as it is (comment_fault) is a ValueError,
    raised before anything is sent: a line break, a control character, only
    blanks, '' or over 512 bytes. Its text ends with `outcome`, what the
    refusal leaves on the device: nothing sent, or for a Transaction's
    commit(), which begin() has locked, loaded and checked, its own."""
    if comment is None:
        return None
    if not isinstance(comment, str):
        raise ValueError(f"the comment must be text, not {type(comment).__name__}; {outcome}")
    fault = comment_fault(comment.strip())
    if fault:
        raise ValueError(f"the comment {comment!r} {fault}; {COMMENT_RULE}; {outcome}")
    return comment.strip()


def read_command_file_lines(path: Path) -> List[str]:
    data = path.read_text(encoding="utf-8-sig").splitlines()
    out = []
    for ln in data:
        if _is_comment_or_empty(ln):
            continue
        ln = ln.split("#", 1)[0].strip()
        if ln:
            out.append(ln)
    return out


def resolve_target_port(target: Target) -> int:
    """The target's port, or its transport's default (830 for NETCONF, 23 for
    telnet, 22 otherwise)."""
    if target.port is not None:
        return target.port
    try:
        return drivers.get(target.vendor).transport.default_port
    except ValueError:
        return 22


# The Junos edit guard lives with its dialect; these names stay for importers.
from .dialects.junos import SET_PREFIX_VERBS as JUNOS_SET_PREFIX_VERBS  # noqa: E402
from .dialects.junos import check_edit as validate_junos_set_syntax  # noqa: E402


def _merge_shortcuts(commands: Dict, path: Path) -> None:
    if path.is_file():
        try:
            commands.update(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            pass


def shipped_shortcuts(spec: str) -> Path:
    """Where a dialect's own library is: `junos` is the stem of a file shipped
    next to the built-in dialects, `/opt/acme/acme.json` (anything ending in
    .json) is the file itself, for a dialect from another package."""
    if spec.endswith(".json"):
        return Path(spec).expanduser()
    return Path(__file__).resolve().parent / "dialects" / f"{spec}.json"


def _load_commands_json(vendor: str) -> Dict:
    """The shortcut library for a target's vendor name: what its dialect
    ships (hssh/dialects/<dialect>.json for a built-in one; a dialect from
    another package names its own file by path), with the operator's own
    entries on top from ~/.h-ssh/commands/<dialect>.json and, as before #81,
    from ~/.h-ssh/commands/<vendor as typed>.json. An unknown vendor has none."""
    try:
        dialect = drivers.get(vendor).dialect
    except ValueError:
        return {}
    commands: Dict = {}
    if dialect.shortcuts:
        _merge_shortcuts(commands, shipped_shortcuts(dialect.shortcuts))
    home = Path.home() / ".h-ssh" / "commands"
    for stem in dict.fromkeys((dialect.name, vendor)):
        _merge_shortcuts(commands, home / f"{stem}.json")
    return commands


def resolve_command(cmd: str, vendor: str) -> str:
    """Resolve command from template library if short name, otherwise return as-is."""
    if ' ' in cmd:
        return cmd

    commands = _load_commands_json(vendor)
    if cmd in commands:
        entry = commands[cmd]
        if isinstance(entry, dict):
            return entry.get("command", cmd)
        return str(entry)

    return cmd


def resolve_structured(cmd: str, vendor: str) -> Optional[Dict]:
    """Return the structured binding for a shortcut, or None if it has none.

    A template entry may carry an optional "structured" key. Its meaning is
    vendor-specific and deliberately not normalised across vendors:

      (an empty mapping marks a vendor whose structured path needs no field map)
      junos:  {rpc, item, key, fields}
                            -- a PyEZ Table/View definition, fetched over
                               NETCONF as a different request than the CLI one

    Absence of a binding is not an error; the caller falls back to text.
    """
    if ' ' in cmd:
        return None

    commands = _load_commands_json(vendor)
    entry = commands.get(cmd)
    if isinstance(entry, dict):
        binding = entry.get("structured")
        if binding:
            return binding if isinstance(binding, dict) else {}
    return None


def get_available_commands(vendor: str) -> Dict[str, str]:
    """Get available command shortcuts for a vendor."""
    commands = _load_commands_json(vendor)
    result = {}
    for name, entry in sorted(commands.items()):
        if isinstance(entry, dict):
            result[name] = entry.get("description", "")
        else:
            result[name] = ""
    return result


def refusal_line(*texts: str, dialect=None):
    """The first line in which the device refused the command, or None. A CLI
    that exits 0 after refusing a line still said so; how it says so is the
    dialect's (`refused`). Without one, the `none` dialect's rule: a line
    starting with "error:" (Junos) or "% " (IOS, EOS, NX-OS). A line the
    dialect's `informational` matches as well (IOS's `% Warning: ...`) is the
    CLI taking the command with a warning, not refusing it."""
    dialect = dialect or drivers.NONE
    for text in texts:
        for m in dialect.refused.finditer(text or ""):
            line = (text[m.start():].strip().splitlines() or [""])[0].strip()
            if not (dialect.informational and dialect.informational.search(line)):
                return line
    return None


def refused_reply(err: str, out: str, dialect=None):
    """The refusal a show got instead of an answer, or None. A CLI that
    refuses a show says so first: Junos answers "error: syntax error, …"
    and nothing else, IOS a caret line then "% Invalid input …". So only a
    refusal that opens the reply counts (blank and caret-only lines
    skipped); "error:" further down is the device's output, as in a log.
    The reply is stdout (`out`), judged first, and stderr (`err`) only when
    stdout has no line to judge: anything on stderr, a warning or a login
    message, stopped the look there and hid a refusal opening stdout, and
    the refused show came back OK (#143)."""
    pattern = (dialect or drivers.NONE).refused
    for text in (out, err):
        for line in (text or "").splitlines():
            if not line.strip() or set(line.strip()) == {"^"}:
                continue
            return line.strip() if pattern.match(line) else None
    return None
