"""Core utilities for h-ssh package."""

import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class Target:
    name: str
    host: str  # IP or resolvable hostname
    vendor: str = "ssh"  # Default: plain SSH, the transport that assumes least
    port: Optional[int] = None  # None = vendor default (22/23/830)


def _is_comment_or_empty(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#")


def load_devices_csv(path: str) -> List[Target]:
    """
    Accepts:
      - CSV with header name,ip or name,ip,vendor
      - CSV without header
      - Lines with just a name
      - Inline or full-line comments '#'
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Devices file not found: {path}")

    targets: List[Target] = []
    raw_lines = p.read_text(encoding="utf-8").splitlines()

    filtered = [ln for ln in raw_lines if not _is_comment_or_empty(ln)]

    # If no comma anywhere, treat as "one name per line"
    if not any("," in ln for ln in filtered):
        for ln in filtered:
            name = ln.split("#", 1)[0].strip()
            if name:
                targets.append(Target(name=name, host=name))
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

    for r in rows[start_idx:]:
        if not r:
            continue
        name = r[0].strip()
        ip = r[1].strip() if len(r) > 1 else ""
        vendor = r[2].strip() if len(r) > 2 else "ssh"
        port_str = r[3].strip() if len(r) > 3 else ""
        port = int(port_str) if port_str else None
        if not name:
            continue
        host = ip if ip else name
        targets.append(Target(name=name, host=host, vendor=vendor, port=port))

    return targets


def parse_inline_target(spec: str) -> Target:
    """Parse inline target string: NAME:HOST[:VENDOR][:PORT] or NAME:HOST[:PORT][:VENDOR].

    Handles port-style targets (e.g., SW1:10.0.0.1:5000:telnet-ios)
    and vendor-style targets (e.g., R1:10.0.0.1:junos).
    """
    parts = spec.split(":")
    if len(parts) < 2:
        raise ValueError(f"Invalid target: {spec!r} (expected name:host[:vendor][:port])")

    name = parts[0]
    host = parts[1]

    if len(parts) == 2:
        return Target(name=name, host=host)
    elif len(parts) == 3:
        if parts[2].isdigit():
            return Target(name=name, host=host, port=int(parts[2]))
        return Target(name=name, host=host, vendor=parts[2])
    elif len(parts) == 4:
        if parts[2].isdigit():
            return Target(name=name, host=host, port=int(parts[2]), vendor=parts[3])
        return Target(name=name, host=host, vendor=parts[2], port=int(parts[3]))
    else:
        raise ValueError(f"Invalid target: {spec!r}")


@dataclass
class JobEntry:
    """A single entry from a job file."""
    target: Target
    mode: str      # "show" or "edit"
    command: str   # The command or config payload


def load_jobs(path: str) -> List[JobEntry]:
    """Load a JSON job file.

    Job file format — JSON array of objects:
    [
      {"target": "R1:192.168.1.1:junos", "show": "show bgp summary"},
      {"target": "R2:192.168.1.2:junos", "edit": "set system host-name R2-new"}
    ]

    Each entry must have:
      - "target": "NAME:HOST[:PORT][:VENDOR]"
      - Exactly one of: "show", "edit"
    """
    if path == "-":
        data = json.load(sys.stdin)
    else:
        with open(path) as f:
            data = json.load(f)

    if not isinstance(data, list) or len(data) == 0:
        raise ValueError("Job file must be a non-empty JSON array")

    entries = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Job entry {i}: must be a JSON object")
        if "target" not in item:
            raise ValueError(f"Job entry {i}: missing 'target'")

        target = parse_inline_target(item["target"])

        # Optional port override
        if "port" in item:
            target.port = int(item["port"])

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
    path = Path(config_dir) / f"{dev_name}.set"
    if not path.is_file():
        raise FileNotFoundError(f"Missing config file for {dev_name}: {path}")
    data = path.read_text(encoding="utf-8").splitlines()

    lines = []
    for ln in data:
        if _is_comment_or_empty(ln):
            continue
        ln = ln.split("#", 1)[0].rstrip()
        if ln.strip():
            lines.append(ln)

    payload = "\n".join(lines).strip()
    if not payload:
        raise ValueError(f"Empty config after filtering: {path}")
    return payload + "\n"


def read_command_file_lines(path: Path) -> List[str]:
    data = path.read_text(encoding="utf-8").splitlines()
    out = []
    for ln in data:
        if _is_comment_or_empty(ln):
            continue
        ln = ln.split("#", 1)[0].strip()
        if ln:
            out.append(ln)
    return out


def _load_commands_json(vendor: str) -> Dict:
    """Load command templates from JSON file for a vendor.

    Lookup order:
    - ~/.h-ssh/commands/{vendor}.json (user overrides)
    - ./commands/{vendor}.json (shipped defaults)
    """
    commands = {}

    local_path = Path("commands") / f"{vendor}.json"
    if local_path.is_file():
        commands.update(json.loads(local_path.read_text(encoding="utf-8")))

    home_path = Path.home() / ".h-ssh" / "commands" / f"{vendor}.json"
    if home_path.is_file():
        commands.update(json.loads(home_path.read_text(encoding="utf-8")))

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

      arista: true          -- ask eAPI for JSON instead of flattening to text
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
