"""Settings the CLI and the h-ssh-store reader resolve the same way: the flag (or run file), the environment, the config file, the default."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from hssh.orchestrator.defaults import DEFAULT_STORE

CREDENTIAL_KEYS = ("password", "passwd", "secret", "token", "pass")
TRANSPORT_CHOICES = ("ssh", "openssh", "netconf", "telnet")
HOST_KEY_CHOICES = ("accept-new", "strict", "off")
# What a flag accepts is what the config file and the run file accept: (floor, ceiling) per key.
RANGES: dict[str, tuple[int, int]] = {
    "workers": (1, 256), "retries": (0, 10), "retry_pause": (0, 3600), "connect_timeout": (1, 86400),
    "session_timeout": (1, 86400), "command_timeout": (1, 86400), "commit_timeout": (1, 86400),
    "cooldown": (0, 86400), "rate_limit": (1, 100000),
}
CHOICES = {"transport": TRANSPORT_CHOICES, "host_key_policy": HOST_KEY_CHOICES}
WORDS = {"yes": True, "true": True, "on": True, "1": True, "no": False, "false": False, "off": False, "0": False}


def config_path() -> Path:
    return Path.home() / ".h-ssh" / "config"


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


def path_setting(flag: str | None, env: str, key: str, config: Mapping[str, str] | None, default: str | None) -> str | None:
    sources = ((f"--{key.replace('_', '-')}", flag), (env, os.environ.get(env)), (f"config '{key}'", (config or {}).get(key)))
    for source, value in sources:
        if value is None:
            continue
        if not value.strip():
            raise ValueError(f"{source} is empty; name a file or leave it out")
        return os.path.expanduser(value)
    return default


def store_path(flag: str | None = None, config: Mapping[str, str] | None = None) -> str:
    return path_setting(flag, "HSSH_STORE", "store", config, DEFAULT_STORE)


def audit_log_path(flag: str | None = None, config: Mapping[str, str] | None = None) -> str | None:
    return path_setting(flag, "HSSH_AUDIT_LOG", "audit_log", config, None)


def safety_file_path(flag: str | None = None, config: Mapping[str, str] | None = None) -> str | None:
    return path_setting(flag, "HSSH_SAFETY_FILE", "safety_file", config, None)


def check_value(key: str, value: Any) -> Any:
    """A setting held to its flag's range or choices, naming the key; config-file strings are converted on the way."""
    if key in RANGES:
        low, high = RANGES[key]
        try:
            number = int(value) if not isinstance(value, bool) else None
        except (TypeError, ValueError):
            number = None
        if number is None:
            raise ValueError(f"{key} takes a whole number, not {value!r}")
        if not low <= number <= high:
            raise ValueError(f"{key} takes a number from {low} to {high}, not {number}")
        return number
    if key in CHOICES:
        word = str(value).strip().lower()
        if word not in CHOICES[key]:
            raise ValueError(f"{key} is one of {', '.join(CHOICES[key])}, not {value!r}")
        return word
    if key in ("probe", "skip_unreachable") and not isinstance(value, bool):
        word = str(value).strip().lower()
        if word not in WORDS:
            raise ValueError(f"{key} is yes or no, not {value!r}")
        return WORDS[word]
    return value
