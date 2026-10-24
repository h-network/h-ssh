"""Core utilities for h-ssh package."""

import csv
import json
import re
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


def _is_comment_or_empty(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#")


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
    not contradictions. Raises ValueError naming the duplicate."""
    by_name: dict = {}
    by_host: dict = {}
    for t in targets:
        where = (t.host, t.port)
        if t.name in by_name and by_name[t.name] != where:
            other = by_name[t.name]
            raise ValueError(f"device name {t.name!r} is used for two hosts: "
                             f"{other[0]}{':' + str(other[1]) if other[1] else ''} and "
                             f"{t.host}{':' + str(t.port) if t.port else ''}")
        if where in by_host and by_host[where] != t.name:
            raise ValueError(f"host {t.host}{':' + str(t.port) if t.port else ''} is listed under two names: "
                             f"{by_host[where]!r} and {t.name!r}")
        if not allow_repeats and t.name in by_name:
            raise ValueError(f"device {t.name!r} ({t.host}) is listed twice")
        by_name[t.name] = where
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
        if key and value:
            config[key] = value
    return config


# NAME:[v6]... — an IPv6 literal has colons of its own, so it goes in brackets.
_BRACKETED_HOST = re.compile(r"^([^:]+):\[([^\]]+)\](?::(.*))?$")


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

        if has_show:
            entries.append(JobEntry(target=target, mode="show", command=item["show"]))
        else:
            entries.append(JobEntry(target=target, mode="edit-cmd", command=item["edit"]))

    return entries


def read_set_file_for_device(config_dir: str, dev_name: str) -> str:
    """The -eD payload for one device: `<config_dir>/<dev_name>.set` with blank
    and full-line '#' comment lines dropped, nothing else touched.

    An inline '#' is part of the line (`set snmp community ab#12 ...`), the
    same rule junos._strip_comments applies to every set payload: -eD sends
    what the syntax guard validated, and what -eB sends from the same file.
    """
    path = path_inside(config_dir, f"{validate_device_name(dev_name)}.set")
    if not path.is_file():
        raise FileNotFoundError(f"Missing config file for {dev_name}: {path}")
    lines = [ln for ln in path.read_text(encoding="utf-8-sig").splitlines()
             if not _is_comment_or_empty(ln)]
    if not lines:
        raise ValueError(f"Empty config after filtering: {path}")
    return "\n".join(lines) + "\n"


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


def _load_commands_json(vendor: str) -> Dict:
    """The shortcut library for a target's vendor name: what its dialect
    ships (hssh/dialects/<dialect>.json), with the operator's own entries on
    top from ~/.h-ssh/commands/<dialect>.json and, as before #81, from
    ~/.h-ssh/commands/<vendor as typed>.json. An unknown vendor has none."""
    try:
        dialect = drivers.get(vendor).dialect
    except ValueError:
        return {}
    commands: Dict = {}
    if dialect.shortcuts:
        _merge_shortcuts(commands, Path(__file__).resolve().parent / "dialects" / f"{dialect.shortcuts}.json")
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
    starting with "error:" (Junos) or "% " (IOS, EOS, NX-OS)."""
    pattern = (dialect or drivers.NONE).refused
    for text in texts:
        m = pattern.search(text or "")
        if m:
            return (text[m.start():].strip().splitlines() or [""])[0].strip()
    return None


def refused_reply(*texts: str, dialect=None):
    """The refusal a show got instead of an answer, or None. A CLI that
    refuses a show says so first: Junos answers "error: syntax error, …"
    and nothing else, IOS a caret line then "% Invalid input …". So only a
    refusal that opens the reply counts (blank and caret-only lines
    skipped); "error:" further down is the device's output, as in a log."""
    pattern = (dialect or drivers.NONE).refused
    for text in texts:
        for line in (text or "").splitlines():
            if not line.strip() or set(line.strip()) == {"^"}:
                continue
            return line.strip() if pattern.match(line) else None
    return None
