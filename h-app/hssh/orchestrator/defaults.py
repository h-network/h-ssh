"""The default of every RunSpec setting; front ends and the model take theirs from here (section 3.2)."""

from __future__ import annotations

import dataclasses
import getpass

from hssh.model import Credentials, EditSettings, HostKeyPolicy, PolicySettings, RunSpec, SafetySettings, Timeouts

DEFAULT_TIMEOUTS = Timeouts(connect=3, command=20, commit=60)
DEFAULT_POLICY = PolicySettings(retries=2, retry_pause=2)
DEFAULT_WORKERS = 8
DEFAULT_HOST_KEY_POLICY: HostKeyPolicy = "off"
DEFAULT_PROBE = True
DEFAULT_EDIT = EditSettings(apply=False)
DEFAULT_CONFIRMED_MINUTES = 10
DEFAULT_SAFETY = SafetySettings(cooldown_seconds=300, rate_limit=6)
DEFAULT_TRANSPORT = "ssh"
DEFAULT_VENDOR = "generic"
DEFAULT_STORE = "h-ssh.db"


def default_username() -> str:
    return getpass.getuser()


def default_credentials() -> Credentials:
    return Credentials(username=default_username())


def complete(spec: RunSpec) -> RunSpec:
    """The spec with every field left None filled from the defaults above; safety and recording None stay None, meaning off."""
    return dataclasses.replace(
        spec,
        credentials=spec.credentials or default_credentials(),
        timeouts=spec.timeouts or DEFAULT_TIMEOUTS,
        workers=DEFAULT_WORKERS if spec.workers is None else spec.workers,
        host_key_policy=spec.host_key_policy or DEFAULT_HOST_KEY_POLICY,
        probe=DEFAULT_PROBE if spec.probe is None else spec.probe,
        edit=spec.edit or DEFAULT_EDIT,
        policy=spec.policy or DEFAULT_POLICY,
    )
