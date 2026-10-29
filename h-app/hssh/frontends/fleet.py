"""The fleet as a library: build a RunSpec from plain arguments, run it, hand back the RunReport.

    from hssh.frontends.fleet import Fleet

    fleet = Fleet(["10.0.1.1", "cr2:10.0.1.2:junos"], transport="netconf", user="admin")
    report = fleet.show("show bgp summary")

The library reads no environment variable and no config file: what it is given is what it uses.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Callable, Union

from hssh.model import (
    Credentials, EditSettings, HostKeyPolicy, Mode, PolicySettings, RecordSettings, RunReport,
    RunSpec, SafetySettings, Target, Timeouts,
)
from hssh.orchestrator import DEFAULT_POLICY, DEFAULT_TIMEOUTS, run

Runner = Callable[[RunSpec], RunReport]

TargetLike = Union[str, Target, os.PathLike]

# NAME:[v6]... — an IPv6 literal has colons of its own, so it goes in brackets.
_BRACKETED_HOST = re.compile(r"^([^:]+):\[([^\]]+)\](?::(.*))?$")


def run_spec(spec: RunSpec) -> RunReport:
    """Hand the spec to the orchestrator; it raises Fault(LOCAL) only for a refusal before any device is contacted."""
    return run(spec)


def parse_target(spec: str, transport: str, vendor: str = "generic") -> Target:
    """`host` alone, `[v6]`, or NAME:HOST[:VENDOR][:PORT] in either order of the last two."""
    spec = spec.strip()
    if not spec:
        raise ValueError("invalid target: an empty word")
    if spec.startswith("[") and spec.endswith("]"):
        host = spec[1:-1]
        return Target(name=host, host=host, vendor=vendor, transport=transport)
    if ":" not in spec:
        return Target(name=spec, host=spec, vendor=vendor, transport=transport)
    m = _BRACKETED_HOST.match(spec)
    if m:
        parts = [m.group(1), m.group(2)] + (m.group(3).split(":") if m.group(3) is not None else [])
    else:
        parts = spec.split(":")
    if not 2 <= len(parts) <= 4:
        raise ValueError(f"invalid target: {spec!r} (expected name:host[:vendor][:port])")
    name, host, rest = parts[0], parts[1], parts[2:]
    port = None
    for part in rest:
        if part.isdigit():
            port = int(part)
        else:
            vendor = part.lower()
    return Target(name=name, host=host, vendor=vendor, transport=transport, port=port)


def load_devices_csv(path: str, transport: str, vendor: str = "generic") -> list[Target]:
    """`name,ip[,vendor[,port]]` rows with or without a header, or one name per line; `#` comments."""
    import csv

    lines = []
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    if not any("," in ln for ln in lines):
        return [Target(name=ln, host=ln, vendor=vendor, transport=transport) for ln in lines]
    rows = list(csv.reader(lines))
    if rows and rows[0][0].strip().lower() == "name":
        rows = rows[1:]
    targets = []
    for i, r in enumerate(rows, start=1):
        if len(r) > 4:
            raise ValueError(f"{path} row {i}: {len(r)} columns; expected name,ip[,vendor[,port]]")
        cells = [c.strip() for c in r] + [""] * (4 - len(r))
        name, ip, row_vendor, port = cells
        if not name:
            continue
        targets.append(Target(name=name, host=ip or name, vendor=(row_vendor or vendor).lower(),
                              transport=transport, port=int(port) if port else None))
    return targets


def as_targets(specs: Iterable[TargetLike] | TargetLike, transport: str, vendor: str = "generic") -> tuple[Target, ...]:
    """Targets, inline specs and inventory paths, in the order given."""
    if isinstance(specs, (str, Target, os.PathLike)):
        specs = [specs]
    out: list[Target] = []
    for item in specs:
        if isinstance(item, Target):
            out.append(item)
        elif isinstance(item, os.PathLike) or (isinstance(item, str) and Path(item).is_file()):
            out.extend(load_devices_csv(os.fspath(item), transport, vendor))
        else:
            out.append(parse_target(item, transport, vendor))
    return tuple(out)


class Fleet:
    """Devices and the settings every run on them shares; each method is one RunSpec run to a RunReport."""

    def __init__(self, targets: Iterable[TargetLike] | TargetLike, transport: str = "ssh",
                 vendor: str = "generic", user: str | None = None, password: str | None = None,
                 key_file: str | None = None, workers: int = 8, timeouts: Timeouts = DEFAULT_TIMEOUTS,
                 policy: PolicySettings = DEFAULT_POLICY, host_key_policy: HostKeyPolicy = "accept-new",
                 probe: bool = False, safety: SafetySettings | None = None,
                 recording: RecordSettings | None = None, runner: Runner = run_spec):
        self.targets = as_targets(targets, transport, vendor)
        if not self.targets:
            raise ValueError("no targets")
        self.credentials = Credentials(username=user or os.getlogin(), password=password, key_file=key_file)
        self.workers = workers
        self.timeouts = timeouts
        self.policy = policy
        self.host_key_policy = host_key_policy
        self.probe = probe
        self.safety = safety
        self.recording = recording
        self._runner = runner

    def spec(self, mode: Mode, commands: Sequence[str] = (), config_lines: Sequence[str] = (),
             format: str | None = None, edit: EditSettings | None = None) -> RunSpec:
        return RunSpec(targets=self.targets, mode=mode, commands=tuple(commands),
                       config_lines=tuple(config_lines), format=format, credentials=self.credentials,
                       timeouts=self.timeouts, workers=self.workers, host_key_policy=self.host_key_policy,
                       probe=self.probe, edit=edit, policy=self.policy, safety=self.safety,
                       recording=self.recording)

    def show(self, command: str) -> RunReport:
        return self._runner(self.spec("show", commands=[command]))

    def batch(self, commands: Iterable[str]) -> RunReport:
        return self._runner(self.spec("batch", commands=list(commands)))

    def structured(self, rpc: str, fmt: str = "json") -> RunReport:
        return self._runner(self.spec("structured", commands=[rpc], format=fmt))

    def edit(self, lines: Iterable[str], apply: bool = False, confirmed_minutes: int | None = None,
             comment: str | None = None) -> RunReport:
        """Dry run unless `apply`; `confirmed_minutes` leaves a pending commit for confirm()."""
        edit = EditSettings(apply=apply, confirmed_minutes=confirmed_minutes, comment=comment)
        return self._runner(self.spec("edit", config_lines=list(lines), edit=edit))

    def confirm(self) -> RunReport:
        return self._runner(self.spec("confirm"))

    def commit_status(self) -> RunReport:
        return self._runner(self.spec("commit_status"))

    def __len__(self) -> int:
        return len(self.targets)

    def __repr__(self) -> str:
        return f"Fleet({len(self.targets)} targets, user={self.credentials.username!r})"
