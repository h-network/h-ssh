"""Run files: one YAML or JSON file that describes a whole fleet run.

    h-ssh --run fleet-bgp.yaml

Every key is a flag name (`workers`, `session-timeout` or `session_timeout`,
`commit_confirmed`, ...), held to the same validation as the config file. A
flag typed on the command line wins over the file; the file wins over the
environment and ~/.h-ssh/config. Relative paths in the file resolve against
the file's directory, so a run directory moves as one. A run file never
carries a credential: the password comes from HSSH_PASSWORD, --password or
the prompt, exactly as without a file.

Three keys have no flag of their own and are the reason the file exists:
`devices:` may be an inline list of targets, `commands:` is an inline batch,
`jobs:` is the list a --job file would hold.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # PyYAML comes with the junos extra; a JSON run file needs nothing
    import yaml
except ImportError:  # pragma: no cover - exercised through monkeypatching
    yaml = None

# Keys a run file may hold, with the argparse destination and the type the
# value must have. The lists are not flags; main() reads them by name.
RUN_KEYS: Dict[str, tuple] = {
    "devices": ("devices", (str, list)),
    "transport": ("transport", str),
    "user": ("user", str),
    "structured": ("structured", bool),
    "show": ("show_command", str),
    "commands": ("batch_commands", list),
    "batch": ("batch", str),
    "edit": ("edit_command", str),
    "edit_dir": ("edit_dir", str),
    "edit_broadcast": ("edit_broadcast", str),
    "jobs": ("jobs_data", list),
    "rollback": ("rollback", int),
    "commit_status": ("commit_status", bool),
    "comment": ("comment", str),
    "show_diff": ("show_diff", bool),
    "retries": ("retries", int),
    "workers": ("workers", int),
    "session_timeout": ("session_timeout", int),
    "command_timeout": ("command_timeout", int),
    "dry_run": ("dry_run", bool),
    "commit_confirmed": ("commit_confirmed", int),
    "yes": ("yes", bool),
    "assume_yes": ("yes", bool),     # the same flag, for YAML editors that quote `yes`
    "verbose": ("verbose", bool),
    "diff": ("diff", bool),
    "raw": ("raw", bool),
    "json": ("json", bool),
    "format": ("format", str),
    "save_output": ("save_output", str),
    "log": ("log", str),
    "audit_log": ("audit_log", str),
    "safety_file": ("safety_file", str),
}

# A file on a shared jumphost or in a git repository is the wrong home for a
# secret; these keys are refused, whatever their value.
CREDENTIAL_KEYS = ("password", "passwd", "secret", "token", "pass")

# Paths in the file are relative to the file, not to the shell's cwd.
PATH_KEYS = ("devices", "batch", "edit_dir", "edit_broadcast", "save_output",
             "log", "audit_log", "safety_file")

FORMAT_CHOICES = ("text", "json", "xml")


def _normalize_key(key: Any) -> str:
    if key is True:          # YAML 1.1 reads a bare `yes:` as the boolean key True
        return "yes"
    return str(key).strip().replace("-", "_").lower()


def load_run_file(path: str) -> Dict[str, Any]:
    """Read a run file into a dict of normalized keys. YAML or JSON by content:
    JSON is tried first (it is YAML too, but PyYAML may be absent), then YAML.
    Raises ValueError naming what is wrong; the caller turns that into exit 2."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"cannot read run file '{path}': {e.strerror or e}") from e
    data: Any = None
    try:
        data = json.loads(text)
    except ValueError:
        if yaml is None:
            raise ValueError(
                f"run file '{path}' is not JSON and PyYAML is not installed: "
                "pip install pyyaml, or write the run file as JSON")
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:  # type: ignore[union-attr]
            raise ValueError(f"run file '{path}' is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"run file '{path}' must be a mapping of option: value, "
                         f"not {type(data).__name__}")
    out: Dict[str, Any] = {}
    for raw_key, value in data.items():
        key = _normalize_key(raw_key)
        if key in CREDENTIAL_KEYS:
            raise ValueError(
                f"run file '{path}': '{raw_key}' is not allowed, a run file never carries a "
                "credential: use HSSH_PASSWORD, --password, or the prompt")
        if key not in RUN_KEYS:
            raise ValueError(f"run file '{path}': unknown option '{raw_key}'")
        if key == "assume_yes":
            key = "yes"
        if key in out:
            raise ValueError(f"run file '{path}': option '{raw_key}' given twice")
        out[key] = value
    return out


def _check_type(path: str, key: str, value: Any, expected) -> None:
    kinds = expected if isinstance(expected, tuple) else (expected,)
    # bool is an int in Python; a run file saying `workers: true` is a mistake
    if isinstance(value, bool) and bool not in kinds:
        raise ValueError(f"run file '{path}': '{key}' must be a {_kind_name(kinds)}, not a boolean")
    if not isinstance(value, kinds):
        raise ValueError(f"run file '{path}': '{key}' must be a {_kind_name(kinds)}, "
                         f"not {type(value).__name__}")


def _kind_name(kinds) -> str:
    names = {str: "string", int: "number", bool: "boolean", list: "list"}
    return " or ".join(names.get(k, k.__name__) for k in kinds)


def target_spec(item: Any, path: str, index: int) -> str:
    """One `devices:` list entry as the inline NAME:HOST[:VENDOR][:PORT] spec
    parse_inline_target() reads: a string as it is, a mapping assembled."""
    if isinstance(item, str):
        if not item.strip():
            raise ValueError(f"run file '{path}': devices[{index}] is empty")
        return item.strip()
    if isinstance(item, dict):
        unknown = sorted(set(map(_normalize_key, item)) - {"name", "host", "vendor", "port"})
        if unknown:
            raise ValueError(f"run file '{path}': devices[{index}] has unknown field(s) "
                             f"{', '.join(unknown)} (name, host, vendor, port)")
        fields = {_normalize_key(k): v for k, v in item.items()}
        for req in ("name", "host"):
            if not isinstance(fields.get(req), str) or not fields[req].strip():
                raise ValueError(f"run file '{path}': devices[{index}] needs a '{req}' string")
        spec = f"{fields['name'].strip()}:{fields['host'].strip()}"
        if "vendor" in fields:
            if not isinstance(fields["vendor"], str):
                raise ValueError(f"run file '{path}': devices[{index}] 'vendor' must be a string")
            spec += f":{fields['vendor'].strip()}"
        if "port" in fields:
            if isinstance(fields["port"], bool) or not isinstance(fields["port"], int):
                raise ValueError(f"run file '{path}': devices[{index}] 'port' must be a number")
            spec += f":{fields['port']}"
        return spec
    raise ValueError(f"run file '{path}': devices[{index}] must be a 'name:host:vendor' "
                     f"string or a mapping, not {type(item).__name__}")


def validate_run(data: Dict[str, Any], path: str, transports, floors: Dict[str, int]) -> Dict[str, Any]:
    """Type-check every value and resolve the file's relative paths. Returns a
    new dict ready for apply_run(); raises ValueError naming the key."""
    base = Path(path).resolve().parent
    out: Dict[str, Any] = {}
    for key, value in data.items():
        dest, expected = RUN_KEYS[key]
        _check_type(path, key, value, expected)
        if key in floors and value < floors[key]:
            raise ValueError(f"run file '{path}': '{key}' must be at least {floors[key]}, not {value}")
        if key == "transport" and value not in transports:
            raise ValueError(f"run file '{path}': 'transport' must be one of "
                             f"{', '.join(transports)}, not '{value}'")
        if key == "format" and value not in FORMAT_CHOICES:
            raise ValueError(f"run file '{path}': 'format' must be one of "
                             f"{', '.join(FORMAT_CHOICES)}, not '{value}'")
        if key == "rollback" and not 0 <= value <= 49:
            raise ValueError(f"run file '{path}': 'rollback' takes a number from 0 to 49, not {value}")
        if key == "commit_confirmed" and not 1 <= value <= 65535:
            raise ValueError(f"run file '{path}': 'commit_confirmed' takes 1..65535 minutes, not {value}")
        if key == "commands":
            if not value or not all(isinstance(c, str) and c.strip() for c in value):
                raise ValueError(f"run file '{path}': 'commands' must be a non-empty list of command strings")
            value = [c.strip() for c in value]
        if key == "jobs":
            if not value or not all(isinstance(j, dict) for j in value):
                raise ValueError(f"run file '{path}': 'jobs' must be a non-empty list of job entries")
        if key == "devices":
            if isinstance(value, list):
                if not value:
                    raise ValueError(f"run file '{path}': 'devices' list is empty")
                value = [target_spec(item, path, i) for i, item in enumerate(value)]
            else:
                value = str(base / value) if not Path(value).is_absolute() else value
        elif key in PATH_KEYS and isinstance(value, str) and value and not Path(value).is_absolute():
            value = str(base / value)
        out[key] = value
    return out


def apply_run(args, run: Dict[str, Any], parser) -> List[str]:
    """Fill `args` from the run file where the command line did not set the
    option: a value still at argparse's default is taken as unset. Returns the
    option names the file set, for the banner."""
    applied: List[str] = []
    for key, value in run.items():
        dest, _ = RUN_KEYS[key]
        if key == "devices" and isinstance(value, list):
            if getattr(args, "target", None):
                continue                  # --target on the command line wins
            args.target = list(value)
            applied.append(key)
            continue
        if dest in ("batch_commands", "jobs_data"):
            setattr(args, dest, value)
            applied.append(key)
            continue
        current = getattr(args, dest, None)
        if current is not None and current != parser.get_default(dest):
            continue                      # given on the command line
        setattr(args, dest, value)
        applied.append(key)
    return applied


def edit_needs_timer(args, is_confirm) -> bool:
    """True when the run file leads to a commit on devices without a
    commit-confirmed timer: refused, since nobody is watching a pipeline."""
    if args.dry_run or args.commit_confirmed is not None:
        return False
    edits = [c for c in (args.edit_command,) if c]
    jobs = getattr(args, "jobs_data", None) or []
    edits += [j["edit"] for j in jobs if isinstance(j, dict) and isinstance(j.get("edit"), str)]
    has_edit = bool(args.edit_command or args.edit_dir or args.edit_broadcast
                    or args.rollback is not None or edits)
    if not has_edit:
        return False
    # A confirm is not a new commit; it cannot carry a timer anyway.
    if edits and all(is_confirm(c) for c in edits) and not (args.edit_dir or args.edit_broadcast
                                                             or args.rollback is not None):
        return False
    return True
