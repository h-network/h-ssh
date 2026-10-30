"""Settings the CLI and the h-ssh-store reader resolve the same way: the flag (or run file), the environment, the config file, the default."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from hssh.orchestrator.defaults import DEFAULT_STORE

CREDENTIAL_KEYS = ("password", "passwd", "secret", "token", "pass")


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
