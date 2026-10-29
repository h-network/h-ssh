"""Probe: optional pre-flight reachability check per target, expressed as fault kinds (section 3.2)."""

from __future__ import annotations

import asyncio
import errno
import socket

from hssh.model import Fault, FaultKind, Target

MAX_PROBES = 100
RETRY_PAUSE = 0.5
SSH_BANNER = b"SSH-"
DEFAULT_PORTS = {"netconf": 830, "telnet": 23}


def port_of(target: Target) -> int:
    return target.port if target.port is not None else DEFAULT_PORTS.get(target.transport, 22)


def expects_banner(target: Target) -> bool:
    """Telnet and a console port send no SSH identification: a TCP connect is all that is asked."""
    return target.transport != "telnet" and port_of(target) != 23


async def attempt(host: str, port: int, banner: bool, seconds: float) -> Fault | None:
    """One try: TCP connect, then the server's identification line when `banner`. None when the box is live."""
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
        if not banner:
            return None
        line = await asyncio.wait_for(reader.readline(), seconds)
        if line.startswith(SSH_BANNER):
            return None
        return Fault(FaultKind.UNREACHABLE, f"{at} answered {line[:40]!r}, not an SSH banner", True)
    except (asyncio.TimeoutError, OSError):
        return Fault(FaultKind.UNREACHABLE, f"no SSH banner from {at} within {seconds:g}s", True)
    finally:
        writer.close()


async def probe_one(target: Target, seconds: float, slots: asyncio.Semaphore) -> Fault | None:
    """The target's probe: one try, and one more after RETRY_PAUSE when the first did not find it live."""
    async with slots:
        fault = await attempt(target.host, port_of(target), expects_banner(target), seconds)
    if fault is None or fault.kind is FaultKind.LOCAL:
        return fault
    await asyncio.sleep(RETRY_PAUSE)
    async with slots:
        return await attempt(target.host, port_of(target), expects_banner(target), seconds)


async def probe(targets: list[Target], seconds: float, limit: int = MAX_PROBES) -> dict[str, Fault | None]:
    """Every target probed, at most `limit` at once: target name to None (live) or the Fault that stands for it."""
    slots = asyncio.Semaphore(max(1, limit))
    faults = await asyncio.gather(*(probe_one(t, seconds, slots) for t in targets))
    return {t.name: f for t, f in zip(targets, faults)}
