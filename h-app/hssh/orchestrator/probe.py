"""Probe: optional pre-flight reachability check per target, expressed as fault kinds (section 3.2)."""

from __future__ import annotations

import asyncio
import errno
import socket
from pathlib import Path

from hssh.model import Fault, FaultKind, Target

MAX_PROBES = 100
SSH_CONFIG = Path.home() / ".ssh" / "config"


def route(host: str, port: int | None, default_port: int) -> tuple[str, int] | None:
    """Where an SSH-based connection to `host` goes, as the libraries read ~/.ssh/config: HostName and Port, the target's own port first. None when a ProxyCommand or ProxyJump carries it, which the probe cannot follow."""
    try:
        import paramiko

        found = paramiko.SSHConfig.from_path(str(SSH_CONFIG)).lookup(host)
    except (ImportError, OSError):
        return host, port if port is not None else default_port
    if found.get("proxycommand") or found.get("proxyjump"):
        return None
    return found.get("hostname", host), port if port is not None else int(found.get("port", default_port))


async def attempt(host: str, port: int, banner: bytes | None, seconds: float) -> Fault | None:
    """One try: TCP connect, then the server's first line when the protocol sends one (`banner`). None when the box is live."""
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
        line = await asyncio.wait_for(reader.readline(), seconds)
        if line.startswith(banner):
            return None
        return Fault(FaultKind.UNREACHABLE, f"{at} answered {line[:40]!r}, not {banner!r}", True)
    except (asyncio.TimeoutError, OSError):
        return Fault(FaultKind.UNREACHABLE, f"nothing from {at} within {seconds:g}s", True)
    finally:
        writer.close()


async def probe_one(host: str, port: int, banner: bytes | None, seconds: float,
                    slots: asyncio.Semaphore) -> Fault | None:
    """One attempt at one address; any retry is the policy's decision."""
    async with slots:
        return await attempt(host, port, banner, seconds)


async def probe(boxes: list[tuple[Target, str, int, bytes | None]], seconds: float,
                limit: int = MAX_PROBES) -> dict[str, Fault | None]:
    """Every (target, host, port, banner) probed, at most `limit` at once: target name to None (live) or the Fault that stands for it."""
    slots = asyncio.Semaphore(max(1, limit))
    faults = await asyncio.gather(*(probe_one(host, port, banner, seconds, slots) for _, host, port, banner in boxes))
    return {t.name: f for (t, _, _, _), f in zip(boxes, faults)}
