"""Settings the CLI and the h-ssh-store reader resolve the same way: the flag (or run file), the environment, the config file, the default."""

from __future__ import annotations

import os
from collections.abc import Mapping

from hssh.orchestrator.defaults import DEFAULT_STORE


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
