"""Probe: optional pre-flight reachability check per target, expressed as fault kinds (section 3.2)."""

from __future__ import annotations

import asyncio
import errno
import socket

from hssh.model import Fault, FaultKind, Target

MAX_PROBES = 100


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


async def probe_one(target: Target, port: int, banner: bytes | None, seconds: float,
                    slots: asyncio.Semaphore) -> Fault | None:
    """The target's probe: one attempt; any retry is the policy's decision."""
    async with slots:
        return await attempt(target.host, port, banner, seconds)


async def probe(boxes: list[tuple[Target, int, bytes | None]], seconds: float,
                limit: int = MAX_PROBES) -> dict[str, Fault | None]:
    """Every (target, port, banner) probed, at most `limit` at once: target name to None (live) or the Fault that stands for it."""
    slots = asyncio.Semaphore(max(1, limit))
    faults = await asyncio.gather(*(probe_one(t, port, banner, seconds, slots) for t, port, banner in boxes))
    return {t.name: f for (t, _, _), f in zip(boxes, faults)}
