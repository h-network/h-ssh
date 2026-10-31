"""The fleet as a library: build a RunSpec from plain arguments, run it, hand back the RunReport.

    from hssh.frontends.fleet import Fleet

    fleet = Fleet(["10.0.1.1", "cr2:10.0.1.2:junos"], transport="netconf", user="admin")
    report = fleet.show("show bgp summary")

The library reads no environment variable and no config file: what it is given is what it uses.
"""

from __future__ import annotations

import asyncio
import dataclasses
import importlib.metadata
import logging
import os
import re
import threading
import weakref
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Callable, Union

from hssh.drivers import Registry
from hssh.model import (
    Credentials, EditSettings, Fault, HostKeyPolicy, Mode, PolicySettings, RecordSettings, RunReport,
    RunSpec, SafetySettings, Target, Timeouts,
)
from hssh.paths import validate_device_name
from hssh.orchestrator import (
    DEFAULT_EDIT, DEFAULT_HOST_KEY_POLICY, DEFAULT_POLICY, DEFAULT_PROBE, DEFAULT_SKIP_UNREACHABLE, DEFAULT_TIMEOUTS,
    DEFAULT_TRANSPORT,
    DEFAULT_VENDOR, DEFAULT_WORKERS, check_label, default_username, reachable, run,
)

Runner = Callable[[RunSpec], RunReport]

LIBRARY_LOGGERS = ("paramiko", "ncclient")


def package_version() -> str | None:
    """The installed h-ssh version for the run's provenance; None when running from source."""
    try:
        return importlib.metadata.version("h-ssh")
    except importlib.metadata.PackageNotFoundError:
        return None


def quiet_library_logs() -> None:
    """A NullHandler on each library logger, so paramiko's handshake tracebacks don't reach stderr through Python's last-resort handler; levels are left to the caller."""
    for name in LIBRARY_LOGGERS:
        lg = logging.getLogger(name)
        if not lg.handlers:
            lg.addHandler(logging.NullHandler())

TargetLike = Union[str, Target, os.PathLike]

# NAME:[v6]... — an IPv6 literal has colons of its own, so it goes in brackets.
_BRACKETED_HOST = re.compile(r"^([^:]+):\[([^\]]+)\](?::(.*))?$")


def parse_target(spec: str, transport: str, vendor: str = DEFAULT_VENDOR) -> Target:
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


def load_devices_csv(path: str, transport: str, vendor: str = DEFAULT_VENDOR) -> list[Target]:
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


def as_targets(specs: Iterable[TargetLike] | TargetLike, transport: str, vendor: str = DEFAULT_VENDOR) -> tuple[Target, ...]:
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
    for target in out:
        validate_device_name(target.name)
    check_unique(out)
    return tuple(out)


def port_in_use(target: Target, registry: Registry) -> int:
    """The target's port, else its communicator's default; 22 when no driver matches."""
    if target.port is not None:
        return target.port
    try:
        return registry.resolve(target).communicator.default_port
    except Fault:
        return 22


def check_unique(targets: Sequence[Target]) -> None:
    """One name is one device and one device is one name, a device being its host and the port in use; a repeated row is refused too."""
    registry = Registry()
    registry.load_entry_points()
    by_name: dict[str, tuple[tuple[str, int], str]] = {}
    by_host: dict[tuple[str, int], str] = {}
    for t in targets:
        where = (t.host, port_in_use(t, registry))
        typed = f"{t.host}:{t.port}" if t.port else t.host
        if t.name in by_name and by_name[t.name][0] != where:
            other, other_typed = by_name[t.name]
            if other_typed == typed:
                other_typed, typed = f"{other[0]}:{other[1]}", f"{where[0]}:{where[1]}"
            raise ValueError(f"device name {t.name!r} is used for two hosts: {other_typed} and {typed}")
        if where in by_host and by_host[where] != t.name:
            raise ValueError(f"host {typed} is listed under two names: {by_host[where]!r} and {t.name!r}")
        if t.name in by_name:
            raise ValueError(f"device {t.name!r} ({t.host}) is listed twice")
        by_name[t.name] = (where, typed)
        by_host[where] = t.name


Commands = Union[str, Sequence[str], Mapping[str, Union[str, Sequence[str]]]]


def split_commands(given: Commands) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
    """(commands for every target, commands by target name): a string is one command, a sequence several, a mapping per target."""
    def lines(value: str | Sequence[str]) -> tuple[str, ...]:
        return (value,) if isinstance(value, str) else tuple(value)

    if isinstance(given, Mapping):
        if not given:
            raise ValueError("no commands: the mapping is empty")
        return (), {name: lines(value) for name, value in given.items()}
    commands = lines(given)
    if not commands:
        raise ValueError("no commands")
    return commands, {}


def close_sessions(sessions, wait: float) -> None:
    """Close a Fleet's kept sessions; also what a Fleet dropped without close() runs on collection or at exit."""
    asyncio.run(sessions.close_all(timeout=wait))


class Fleet:
    """Devices and the settings every run on them shares; each method is one RunSpec run to a RunReport. The Fleet keeps its sessions: a device logged in once stays logged in until close(), the end of the `with` block, or the Fleet is collected."""

    def __init__(self, targets: Iterable[TargetLike] | TargetLike, transport: str = DEFAULT_TRANSPORT,
                 vendor: str = DEFAULT_VENDOR, user: str | None = None, password: str | None = None,
                 key_file: str | None = None, workers: int = DEFAULT_WORKERS, timeouts: Timeouts = DEFAULT_TIMEOUTS,
                 policy: PolicySettings = DEFAULT_POLICY, host_key_policy: HostKeyPolicy = DEFAULT_HOST_KEY_POLICY,
                 probe: bool = DEFAULT_PROBE, safety: SafetySettings | None = None,
                 recording: RecordSettings | None = None, label: str | None = None, runner: Runner | None = None):
        quiet_library_logs()
        if label is not None and (why := check_label(label)):
            raise ValueError(why)
        self.targets = as_targets(targets, transport, vendor)
        if not self.targets:
            raise ValueError("no targets")
        self.credentials = Credentials(username=user or default_username(), password=password, key_file=key_file)
        self.workers = workers
        self.timeouts = timeouts
        self.policy = policy
        self.host_key_policy = host_key_policy
        self.probe = probe
        self.safety = safety
        if recording is None and label is not None:
            recording = RecordSettings()
        if recording is not None:
            recording = dataclasses.replace(recording, origin=recording.origin or "fleet",
                                            version=recording.version or package_version(), label=label or recording.label)
        self.recording = recording
        self._busy = threading.Lock()
        self._closed = False
        self._sessions = self._finalizer = None
        if runner is None:
            from hssh.orchestrator import CLOSE_WAIT, SessionManager

            self._sessions = SessionManager(pool=True)
            self._finalizer = weakref.finalize(self, close_sessions, self._sessions, CLOSE_WAIT)
        self._runner = runner or self._run_pooled

    def _run_pooled(self, spec: RunSpec) -> RunReport:
        """One run on the Fleet's own session manager, so a device logged in once stays logged in for the next call."""
        return run(spec, sessions=self._sessions)

    def _run(self, spec: RunSpec) -> RunReport:
        if self._closed:
            raise RuntimeError("this Fleet is closed")
        if not self._busy.acquire(blocking=False):
            raise RuntimeError("a run on this Fleet is still in flight; one run at a time")
        try:
            return self._runner(spec)
        finally:
            self._busy.release()

    def close(self, wait: float = 0.0) -> None:
        """Close the kept sessions, giving the devices `wait` seconds in all to acknowledge; a closed Fleet refuses further runs."""
        if self._closed:
            return
        if self._busy.locked():
            raise RuntimeError("close() while a run is in flight; wait for it to return")
        self._closed = True
        if self._finalizer is not None:
            self._finalizer.detach()
        if self._sessions is not None:
            close_sessions(self._sessions, wait)

    def __enter__(self) -> "Fleet":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def spec(self, mode: Mode, commands: Sequence[str] = (), config_lines: Sequence[str] = (),
             payloads: Mapping[str, Sequence[str]] | None = None, format: str | None = None,
             edit: EditSettings | None = None, skip_unreachable: bool | None = None,
             commands_by_target: Mapping[str, Sequence[str]] | None = None) -> RunSpec:
        return RunSpec(targets=self.targets, mode=mode, commands=tuple(commands),
                       commands_by_target={name: tuple(lines) for name, lines in (commands_by_target or {}).items()},
                       config_lines=tuple(config_lines),
                       payloads={name: tuple(lines) for name, lines in (payloads or {}).items()},
                       format=format, credentials=self.credentials,
                       timeouts=self.timeouts, workers=self.workers, host_key_policy=self.host_key_policy,
                       probe=self.probe, skip_unreachable=skip_unreachable, edit=edit, policy=self.policy,
                       safety=self.safety, recording=self.recording)

    def show(self, command: Commands) -> RunReport:
        """One command on every target, or a mapping of target name to its own command (a target not named is skipped)."""
        commands, by_target = split_commands(command)
        if len(commands) > 1 or any(len(c) != 1 for c in by_target.values()):
            raise ValueError("show takes one command per target; use batch for several")
        return self._run(self.spec("show", commands=commands, commands_by_target=by_target))

    def batch(self, commands: Commands) -> RunReport:
        """Commands in order on every target, or a mapping of target name to its own list (a target not named is skipped)."""
        commands, by_target = split_commands(commands)
        return self._run(self.spec("batch", commands=commands, commands_by_target=by_target))

    def structured(self, command: Commands, fmt: str) -> RunReport:
        """The replies in `fmt`, json or xml, as the device returns them (NETCONF only): one command, a list (one reply each) or a mapping per target; the library's alone, the CLI has no --format."""
        if fmt not in ("json", "xml"):
            raise ValueError(f"fmt must be 'json' or 'xml', not {fmt!r}")
        commands, by_target = split_commands(command)
        return self._run(self.spec("structured", commands=commands, commands_by_target=by_target, format=fmt))

    def config(self, fmt: str) -> RunReport:
        """The whole committed configuration in `fmt`, json or xml, as the device returns it (NETCONF only); the library's alone."""
        if fmt not in ("json", "xml"):
            raise ValueError(f"fmt must be 'json' or 'xml', not {fmt!r}")
        return self._run(self.spec("config", format=fmt))

    def reachable(self, timeout: int | None = None) -> dict[str, Fault | None]:
        """Which targets answer within `timeout` seconds (the connect timeout by default): name to None, or the Fault that says why not; a target that cannot be probed is absent. No login, nothing recorded."""
        if self._closed:
            raise RuntimeError("this Fleet is closed")
        registry = Registry()
        registry.load_entry_points()
        timeouts = self.timeouts if timeout is None else dataclasses.replace(self.timeouts, connect=timeout)
        return asyncio.run(reachable(self.targets, registry, timeouts, self.credentials))

    def edit(self, lines: Iterable[str] | None = None, payloads: Mapping[str, Sequence[str]] | None = None,
             apply: bool = DEFAULT_EDIT.apply, confirmed_minutes: int | None = None, comment: str | None = None,
             skip_unreachable: bool = DEFAULT_SKIP_UNREACHABLE, synchronize: bool = False) -> RunReport:
        """`lines` for every target, or `payloads` per target name (a target in neither is skipped). Dry run unless `apply`; `confirmed_minutes` leaves a pending commit for confirm(); `skip_unreachable` goes on without the devices the probe found dead; `synchronize` asks for commit synchronize (NETCONF only)."""
        if lines is None and payloads is None:
            raise ValueError("edit needs lines or payloads")
        edit = EditSettings(apply=apply, confirmed_minutes=confirmed_minutes, comment=comment, synchronize=synchronize)
        return self._run(self.spec("edit", config_lines=list(lines or ()), payloads=payloads, edit=edit,
                                   skip_unreachable=skip_unreachable))

    def confirm(self, synchronize: bool = False) -> RunReport:
        edit = EditSettings(apply=True, synchronize=True) if synchronize else None
        return self._run(self.spec("confirm", edit=edit))

    def commit_status(self) -> RunReport:
        return self._run(self.spec("commit_status"))

    def __len__(self) -> int:
        return len(self.targets)

    def __repr__(self) -> str:
        return f"Fleet({len(self.targets)} targets, user={self.credentials.username!r})"
