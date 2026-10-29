"""Run files: one YAML or JSON file holding a whole run. Every key is a CLI option name; a typed flag wins over the file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None

# key -> (argparse destination, accepted type)
RUN_KEYS: dict[str, tuple[str, type | tuple[type, ...]]] = {
    "devices": ("devices", (str, list)),
    "transport": ("transport", str),
    "user": ("user", str),
    "show": ("show_command", str),
    "commands": ("batch_commands", list),
    "batch": ("batch", str),
    "profile": ("profile", str),
    "format": ("format", str),
    "edit": ("edit_command", str),
    "edit_file": ("edit_file", str),
    "confirm": ("confirm", bool),
    "commit_status": ("commit_status", bool),
    "yes": ("yes", bool),
    "assume_yes": ("yes", bool),
    "commit_confirmed": ("commit_confirmed", int),
    "comment": ("comment", str),
    "retries": ("retries", int),
    "retry_pause": ("retry_pause", int),
    "workers": ("workers", int),
    "connect_timeout": ("connect_timeout", int),
    "command_timeout": ("command_timeout", int),
    "commit_timeout": ("commit_timeout", int),
    "host_key_policy": ("host_key_policy", str),
    "probe": ("probe", bool),
    "cooldown": ("cooldown", int),
    "rate_limit": ("rate_limit", int),
    "safety_file": ("safety_file", str),
    "store": ("store", str),
    "no_store": ("no_store", bool),
    "audit_log": ("audit_log", str),
    "log": ("log", str),
    "save_output": ("save_output", str),
    "json": ("json", bool),
    "raw": ("raw", bool),
    "verbose": ("verbose", bool),
}

# A run file never carries a secret, whatever the value.
CREDENTIAL_KEYS = ("password", "passwd", "secret", "token", "pass")

# Relative to the file, not to the shell's cwd.
PATH_KEYS = ("devices", "batch", "edit_file", "safety_file", "store", "audit_log", "log", "save_output")


def _normalize_key(key: Any) -> str:
    if key is True:
        return "yes"
    return str(key).strip().replace("-", "_").lower()


def load_run_file(path: str) -> dict[str, Any]:
    """Read a run file into a dict of normalized keys; JSON first, then YAML. ValueError names what is wrong."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"cannot read run file '{path}': {e.strerror or e}") from e
    try:
        data = json.loads(text)
    except ValueError:
        if yaml is None:
            raise ValueError(f"run file '{path}' is not JSON and PyYAML is not installed")
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise ValueError(f"run file '{path}' is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"run file '{path}' must be a mapping of option: value, not {type(data).__name__}")
    out: dict[str, Any] = {}
    for raw_key, value in data.items():
        key = _normalize_key(raw_key)
        if key in CREDENTIAL_KEYS:
            raise ValueError(f"run file '{path}': '{raw_key}' is not allowed, a run file never carries a credential")
        if key not in RUN_KEYS:
            raise ValueError(f"run file '{path}': unknown option '{raw_key}'")
        if key == "assume_yes":
            key = "yes"
        if key in out:
            raise ValueError(f"run file '{path}': option '{raw_key}' given twice")
        out[key] = value
    return out


def _check_type(path: str, key: str, value: Any, expected: type | tuple[type, ...]) -> None:
    kinds = expected if isinstance(expected, tuple) else (expected,)
    if isinstance(value, bool) and bool not in kinds:
        raise ValueError(f"run file '{path}': '{key}' must not be a boolean")
    if not isinstance(value, kinds):
        raise ValueError(f"run file '{path}': '{key}' must be a {' or '.join(k.__name__ for k in kinds)}, "
                         f"not {type(value).__name__}")


def target_spec(item: Any, path: str, index: int) -> str:
    """One `devices:` entry as the NAME:HOST[:VENDOR][:PORT] string the CLI parses."""
    if isinstance(item, str):
        if not item.strip():
            raise ValueError(f"run file '{path}': devices[{index}] is empty")
        return item.strip()
    if isinstance(item, dict):
        fields = {_normalize_key(k): v for k, v in item.items()}
        unknown = sorted(set(fields) - {"name", "host", "vendor", "port"})
        if unknown:
            raise ValueError(f"run file '{path}': devices[{index}] has unknown field(s) {', '.join(unknown)}")
        for req in ("name", "host"):
            if not isinstance(fields.get(req), str) or not fields[req].strip():
                raise ValueError(f"run file '{path}': devices[{index}] needs a '{req}' string")
        spec = f"{fields['name'].strip()}:{fields['host'].strip()}"
        if "vendor" in fields:
            spec += f":{str(fields['vendor']).strip()}"
        if "port" in fields:
            spec += f":{int(fields['port'])}"
        return spec
    raise ValueError(f"run file '{path}': devices[{index}] must be a string or a mapping")


def validate_run(data: dict[str, Any], path: str) -> dict[str, Any]:
    """Type-check every value and resolve the file's relative paths; returns a dict for apply_run()."""
    base = Path(path).resolve().parent
    out: dict[str, Any] = {}
    for key, value in data.items():
        _, expected = RUN_KEYS[key]
        _check_type(path, key, value, expected)
        if key == "commands":
            if not value or not all(isinstance(c, str) and c.strip() for c in value):
                raise ValueError(f"run file '{path}': 'commands' must be a non-empty list of command strings")
            value = [c.strip() for c in value]
        if key == "devices" and isinstance(value, list):
            if not value:
                raise ValueError(f"run file '{path}': 'devices' list is empty")
            value = [target_spec(item, path, i) for i, item in enumerate(value)]
        elif key in PATH_KEYS and isinstance(value, str) and value and not Path(value).is_absolute():
            value = str(base / value)
        out[key] = value
    return out


def apply_run(args: Any, run: dict[str, Any], typed: set[str]) -> list[str]:
    """Fill `args` where the command line gave nothing; a typed target or --devices replaces the file's `devices`. Returns the keys applied."""
    applied: list[str] = []
    for key, value in run.items():
        dest, _ = RUN_KEYS[key]
        if key == "devices":
            if typed & {"devices", "target", "hosts"}:
                continue
            if isinstance(value, list):
                args.target = list(value)
            else:
                args.devices = value
            applied.append(key)
            continue
        if dest in typed:
            continue
        setattr(args, dest, value)
        applied.append(key)
    return applied
