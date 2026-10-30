"""Probe: optional pre-flight reachability check per target, expressed as fault kinds (section 3.2)."""

from __future__ import annotations

import asyncio
import errno
import socket
from pathlib import Path

from hssh.model import Fault, FaultKind, Target

MAX_PROBES = 100
MAX_LINE = 255
MAX_LINES = 100
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


async def probe(boxes: list[tuple[Target, str, int, bytes | None]], seconds: float,
                limit: int = MAX_PROBES) -> dict[str, Fault | None]:
    """Every (target, host, port, banner) probed, at most `limit` at once: target name to None (live) or the Fault that stands for it."""
    slots = asyncio.Semaphore(max(1, limit))
    faults = await asyncio.gather(*(probe_one(host, port, banner, seconds, slots) for _, host, port, banner in boxes))
    return {t.name: f for (t, _, _, _), f in zip(boxes, faults)}
