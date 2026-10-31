"""Probe: optional pre-flight reachability check per target, expressed as fault kinds (section 3.2)."""

from __future__ import annotations

import asyncio
import errno
import os
import socket
import subprocess
import sys
from pathlib import Path

from collections.abc import Collection, Sequence

from hssh.drivers import DriverRegistry
from hssh.model import Credentials, Fault, FaultKind, Target, Timeouts
from hssh.orchestrator.defaults import FDS_BASE, open_file_limit

MAX_PROBES = 100
MAX_LINE = 255
MAX_LINES = 100
SSH_CONFIG = Path.home() / ".ssh" / "config"
SSH_G = ("ssh", "-G")
SSH_G_AT_ONCE = 8

Route = tuple[str, int] | None


def route(host: str, port: int | None, default_port: int) -> Route:
    """Where a paramiko-based connection to `host` goes, as PyEZ and ncclient read ~/.ssh/config: HostName and Port, the target's own port first. None when a ProxyCommand carries it, which the probe cannot follow; ProxyJump is not read by those libraries."""
    try:
        import paramiko

        found = paramiko.SSHConfig.from_path(str(SSH_CONFIG)).lookup(host)
    except (ImportError, OSError):
        return host, port if port is not None else default_port
    if found.get("proxycommand"):
        return None
    return found.get("hostname", host), port if port is not None else int(found.get("port", default_port))


def openssh_route(host: str, port: int | None, default_port: int, user: str | None, seconds: float) -> Route:
    """Where the OpenSSH client connects for `host`, as `ssh -G` prints it with the run's user and the target's own port: None behind a ProxyJump or ProxyCommand. Without an ssh binary, `host` as it is. Fault(LOCAL) when ssh -G cannot say."""
    argv = [*SSH_G, *(["-p", str(port)] if port else []), "--", f"{user}@{host}" if user else host]
    env = {k: v for k, v in os.environ.items() if k != "HSSH_PASSWORD"}
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=seconds, env=env, check=False)
    except FileNotFoundError:
        return host, port if port is not None else default_port
    except subprocess.TimeoutExpired:
        raise Fault(FaultKind.LOCAL, f"ssh -G {host} did not answer within {seconds:g}s", False) from None
    except OSError as e:
        raise Fault(FaultKind.LOCAL, f"ssh -G could not run: {e.strerror or e}", False) from e
    said: dict[str, str] = {}
    for line in done.stdout.decode("utf-8", "replace").splitlines():
        key, _, value = line.strip().partition(" ")
        said.setdefault(key.lower(), value.strip())
    if done.returncode != 0 or not said.get("hostname") or not said.get("port", "22").isdigit():
        complaint = next((ln.strip() for ln in done.stderr.decode("utf-8", "replace").splitlines()
                          if ln.strip() and not ln.startswith("Pseudo-terminal")), f"exit {done.returncode}")
        raise Fault(FaultKind.LOCAL, f"ssh -G {host}: {complaint}", False)
    if any(said.get(key, "none").lower() != "none" for key in ("proxyjump", "proxycommand")):
        return None
    return said["hostname"], int(said.get("port", port if port is not None else default_port))


async def where_to(target: Target, reader: str | None, default_port: int, user: str | None, seconds: float,
                ssh_g: asyncio.Semaphore) -> Route:
    """Where the transport that reads the ssh client's configuration as `reader` says ("paramiko", "openssh", None) connects for `target`; ssh -G runs on a thread, SSH_G_AT_ONCE at once."""
    if reader == "paramiko":
        return route(target.host, target.port, default_port)
    if reader == "openssh":
        async with ssh_g:
            try:
                return await asyncio.wait_for(
                    asyncio.to_thread(openssh_route, target.host, target.port, default_port, user, seconds), seconds + 1)
            except asyncio.TimeoutError:
                raise Fault(FaultKind.LOCAL, f"ssh -G {target.host} did not answer within {seconds:g}s", False) from None
    return target.host, target.port if target.port is not None else default_port


async def identification(reader: asyncio.StreamReader, banner: bytes, seen: list[bytes]) -> bytes | None:
    """The identification line, or None. RFC 4253 lets a server send lines before it, so up to MAX_LINES lines of MAX_LINE bytes are read, as paramiko and OpenSSH read them; every line read goes to `seen`."""
    for _ in range(MAX_LINES):
        line = (await reader.readline()).rstrip(b"\r\n")
        if not line and reader.at_eof():
            break
        seen.append(line)
        if line.startswith(banner):
            return line
        if len(line) > MAX_LINE:
            break
    return None


async def attempt(host: str, port: int, banner: bytes | None, seconds: float) -> Fault | None:
    """One try: TCP connect, then the server's identification when the protocol sends one (`banner`). None when the box is live."""
    at = f"{host}:{port}"
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), seconds)
    except asyncio.TimeoutError:
        return Fault(FaultKind.UNREACHABLE, f"no TCP answer from {at} within {seconds:g}s", False)
    except socket.gaierror as e:
        return Fault(FaultKind.UNREACHABLE, f"cannot resolve {host}: {e.strerror or e}", False)
    except OSError as e:
        if e.errno in (errno.EMFILE, errno.ENFILE):
            return Fault(FaultKind.LOCAL, f"no file descriptor to probe {at}", False)
        return Fault(FaultKind.UNREACHABLE, f"{at}: {e.strerror or e}", False)
    try:
        if banner is None:
            return None
        seen: list[bytes] = []
        if await asyncio.wait_for(identification(reader, banner, seen), seconds) is not None:
            return None
    except (asyncio.TimeoutError, OSError):
        if not seen:
            return Fault(FaultKind.UNREACHABLE, f"no {banner!r} line from {at} within {seconds:g}s", True)
    finally:
        writer.close()
    if not seen:
        return Fault(FaultKind.UNREACHABLE, f"{at} closed without a {banner!r} line", True)
    return Fault(FaultKind.UNREACHABLE, f"{at} answered {seen[0][:40]!r}, not {banner!r}", True)


async def probe_one(host: str, port: int, banner: bytes | None, seconds: float,
                    slots: asyncio.Semaphore) -> Fault | None:
    """One attempt at one address; any retry is the policy's decision."""
    async with slots:
        return await attempt(host, port, banner, seconds)


async def reachable(targets: Sequence[Target], registry: DriverRegistry, timeouts: Timeouts, creds: Credentials, *,
                    limit: int | None = None, held: Collection[str] = ()) -> dict[str, Fault | None]:
    """Whether each target answers where its transport connects, with no login and nothing recorded: None when it does, else the probe's Fault. A target the gate holds (`held`), whose driver is unknown, or reached through a proxy is not probed and absent. `limit` probes run at once; None fits MAX_PROBES to the open-file limit."""
    boxes, found = [], {}
    ssh_g = asyncio.Semaphore(SSH_G_AT_ONCE)
    for target in targets:
        if target.name in held:
            continue
        try:
            comm = registry.resolve(target).communicator
        except Fault:
            continue
        reader = comm.ssh_config if comm.banner is not None else None
        try:
            where = await where_to(target, reader, comm.default_port, creds.username, timeouts.connect, ssh_g)
        except Fault as f:
            found[target.name] = f
            continue
        if where is not None:
            boxes.append((target, where[0], where[1], comm.banner))
    if limit is None:
        open_files = open_file_limit()
        limit = MAX_PROBES if open_files is None else min(MAX_PROBES, open_files - FDS_BASE)
    return {**found, **await probe(boxes, timeouts.connect, limit=limit)}


async def probe(boxes: list[tuple[Target, str, int, bytes | None]], seconds: float,
                limit: int = MAX_PROBES) -> dict[str, Fault | None]:
    """Every (target, host, port, banner) probed, at most `limit` at once: target name to None (live) or the Fault that stands for it. A probe that says nothing about the box (no descriptor, an unexpected error) leaves its target out, as if unprobed, said once on stderr; the other probes go on."""
    slots = asyncio.Semaphore(max(1, limit))
    answers = await asyncio.gather(*(probe_one(host, port, banner, seconds, slots) for _, host, port, banner in boxes),
                                   return_exceptions=True)
    found, unprobed = {}, []
    for (target, _, _, _), answer in zip(boxes, answers):
        if isinstance(answer, Fault) and answer.kind is FaultKind.LOCAL:
            unprobed.append(answer.detail)
        elif isinstance(answer, BaseException) and not isinstance(answer, Fault):
            unprobed.append(f"{type(answer).__name__}: {answer}")
        else:
            found[target.name] = answer
    if unprobed:
        print(f"{len(unprobed)} target(s) not probed, the run goes on to them: {unprobed[0]}", file=sys.stderr)
    return found
