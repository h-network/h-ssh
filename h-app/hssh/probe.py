"""The probe (#127): is each box there, asked at the protocol level and
without logging in. A TCP connect; the server's first line read (an SSH
server speaks first: `SSH-2.0-...`) and checked to be SSH; the connection
closed. No key exchange, no login, no credential: on the router it is one
SSH connection closed before login (OpenSSH logs "Did not receive
identification string from ..." or "Connection closed by ... [preauth]"),
never a failed login. A box on telnet (frozen; it has no banner) is a TCP
connect alone. Plain TCP, so no root is needed.

Each box gets one result: live, with sshd's version string; refused; no
route; name not found; timed out, no TCP answer within the connect timeout;
silent, TCP accepted and no banner within it (or the connection closed
without one); not SSH, something else answered. A probe that fails is tried
once more after a short pause. At most `limit` run at once: MAX_PROBES
(hssh.limits), fitted by the caller to the open-file limit as the workers
are.

For a box that answers, two times, one sample each. The connect time is the
TCP handshake's round trip as the kernel measured it (TCP_INFO's tcpi_rtt on
Linux, exact whatever the concurrency; where TCP_INFO is missing, the wall
time of the connect, which counts this program's own queueing too when many
probes run at once). The banner time is the wall clock from the finished
handshake to the banner line: how fast sshd answers. A live box whose round
trip is above `slow_ms` is tagged slow; that is information, never a
failure.

What the probe cannot tell: whether the NETCONF subsystem works (the NETCONF
hello comes after login) or whether the credentials do.
"""

import asyncio
import concurrent.futures as cf
import errno
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import List, NamedTuple, Optional, Sequence

from . import drivers
from .core import Target, resolve_target_port
from .limits import MAX_PROBES
from .transports.connect import answered, no_banner, tcp_timed_out, where

__all__ = ["ProbeResult", "Answer", "probe", "in_thread", "attempt", "slow_tag", "ms_text", "kernel_rtt_ms", "tally",
           "RESULTS", "SLOW_MS", "RETRY_PAUSE", "MAX_PROBES"]

LIVE = "live"
REFUSED = "refused"
NO_ROUTE = "no route"
NO_NAME = "name not found"
TIMED_OUT = "timed out"
SILENT = "silent"
NOT_SSH = "not SSH"
RESULTS = (LIVE, REFUSED, NO_ROUTE, NO_NAME, TIMED_OUT, SILENT, NOT_SSH)

SLOW_MS = 10            # the threshold by default: --slow, `slow` in the config file, slow_ms=
RETRY_PAUSE = 0.5       # seconds before a failed probe is tried again
MAX_LINE = 255          # RFC 4253: the identification line, its CR LF included
_TCP_INFO_RTT = 68      # tcpi_rtt, in microseconds, in Linux's struct tcp_info
_TCP_INFO_LEN = 104
# The resolver's own answer that the name does not exist, as the ssh transport reads it.
_NO_SUCH_NAME = frozenset({socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)})

_clock = time.perf_counter      # the wall clock: banner times, the fallback, how long a box took


@dataclass(frozen=True)
class ProbeResult:
    """One box's probe, as a value. `device` (also `name`), `host`, `port`
    and `vendor` say which box; `result` is one of RESULTS, `ok` whether
    that is live. `connect_ms` is the TCP handshake's round trip (the
    kernel's measure; the connect's wall time where TCP_INFO is missing),
    for a box that accepted TCP; `banner_ms` the wall time from there to
    the banner line, for a live box on an SSH transport; `banner` sshd's
    version string as it came, without its CR LF; `reason` why a box is
    not live, in words; `slow` the tag of a live box whose round trip is
    above the threshold (`slow: answered in 10.7 ms (above 10 ms)`), else
    None; `duration_ms` the whole probe of the box, a second try included."""

    device: str
    host: str
    port: int
    vendor: str
    result: str
    connect_ms: Optional[float] = None
    banner_ms: Optional[float] = None
    banner: Optional[str] = None
    reason: Optional[str] = None
    slow: Optional[str] = None
    duration_ms: int = 0

    @property
    def name(self) -> str:
        return self.device

    @property
    def ok(self) -> bool:
        return self.result == LIVE

    @property
    def verdict(self) -> str:
        """`live`, or the result with its reason: `refused (connection refused by HOST:PORT)`."""
        return self.result if self.ok or not self.reason else f"{self.result} ({self.reason})"

    def to_dict(self) -> dict:
        """The probe as plain data, JSON-serialisable: the record --probe
        --json prints and the store keeps."""
        return {"device": self.device, "host": self.host, "port": self.port, "vendor": self.vendor,
                "ok": self.ok, "result": self.result, "connect_ms": self.connect_ms,
                "banner_ms": self.banner_ms, "banner": self.banner, "reason": self.reason,
                "slow": self.slow, "duration_ms": self.duration_ms}


class Answer(NamedTuple):
    """What one try at one box came to (see attempt())."""
    result: str
    reason: Optional[str] = None
    connect_ms: Optional[float] = None
    banner_ms: Optional[float] = None
    banner: Optional[str] = None


def ms_text(ms: float) -> str:
    """Milliseconds as printed: one decimal (`10.7`), two significant
    digits below a millisecond (`0.27`, `0.034`), so a LAN's round trip
    does not read as 0."""
    return f"{ms:.1f}" if ms >= 1 else f"{ms:.2g}"


def slow_tag(connect_ms: Optional[float], slow_ms: float) -> Optional[str]:
    """The tag of a box whose handshake took longer than `slow_ms`, else None."""
    if connect_ms is None or connect_ms <= slow_ms:
        return None
    return f"slow: answered in {ms_text(connect_ms)} ms (above {slow_ms:g} ms)"


def kernel_rtt_ms(sock) -> Optional[float]:
    """The TCP handshake's round trip as the kernel measured it, in ms:
    tcpi_rtt, microseconds at byte offset 68 of struct tcp_info, read right
    after the connect, when the handshake is its one sample. None where
    TCP_INFO is missing or has no sample yet (0)."""
    option = getattr(socket, "TCP_INFO", None)
    if option is None:
        return None
    try:
        info = sock.getsockopt(socket.IPPROTO_TCP, option, _TCP_INFO_LEN)
    except (OSError, ValueError):
        return None
    if len(info) < _TCP_INFO_RTT + 4:
        return None
    rtt_us = struct.unpack_from("=I", info, _TCP_INFO_RTT)[0]
    return rtt_us / 1000.0 if rtt_us else None


async def _lookup(host: str, port: int, seconds: float) -> list:
    """getaddrinfo for HOST:PORT over TCP. An address needs no resolver; a
    name is looked up on a daemon thread of its own and waited for at most
    `seconds`, so a resolver that does not answer costs the probe that and
    never holds up the end of the run."""
    try:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)
    except socket.gaierror:
        pass
    loop = asyncio.get_running_loop()
    answer = loop.create_future()

    def settle(found, error):
        if not answer.done():
            if error is None:
                answer.set_result(found)
            else:
                answer.set_exception(error)

    def look():
        try:
            found, error = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM), None
        except Exception as e:      # noqa: BLE001 - handed to the waiting probe
            found, error = None, e
        try:
            loop.call_soon_threadsafe(settle, found, error)
        except RuntimeError:        # the probe is over and its loop closed
            pass
    try:
        threading.Thread(target=look, name="hssh-probe-lookup", daemon=True).start()
    except RuntimeError:            # no thread to spare: looked up here, in the loop
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return await asyncio.wait_for(answer, seconds)


async def _connect(loop, sock, address) -> None:
    await loop.sock_connect(sock, address)


async def _first_line(loop, sock, banner: bytes) -> Optional[bytes]:
    """What the server says first, up to its first line break and without
    its CR LF, MAX_LINE bytes at most: read until the line ends, the server
    closes, MAX_LINE bytes came, or what came can no longer be `banner`.
    None for a server that closed without a word."""
    data = b""
    while b"\n" not in data and len(data) < MAX_LINE:
        if not (data.startswith(banner) or banner.startswith(data)):
            break                                   # not SSH: the rest of the line changes nothing
        chunk = await loop.sock_recv(sock, MAX_LINE)
        if not chunk:
            if not data:
                return None
            break
        data += chunk
    return data.split(b"\n", 1)[0][:MAX_LINE].rstrip(b"\r")


def _quoted(text: str, width: int = 40) -> str:
    return repr(text if len(text) <= width else text[:width] + "…")


async def _hear(loop, sock, at: str, banner: Optional[bytes], seconds: float, connect_ms: float,
                connected: float) -> Answer:
    """A connected box's first line, judged; the socket is closed after it."""
    try:
        if banner is None:                          # telnet: TCP is all there is to ask
            return Answer(LIVE, connect_ms=connect_ms)
        try:
            line = await asyncio.wait_for(_first_line(loop, sock, banner), seconds)
        except asyncio.TimeoutError:                # before OSError: on 3.11 and later it is one
            return Answer(SILENT, no_banner(at, seconds), connect_ms)
        except OSError as e:
            if e.errno == errno.ECONNRESET:
                return Answer(SILENT, f"{at} reset the connection without an SSH banner", connect_ms)
            return Answer(SILENT, f"{at} failed before an SSH banner: {e.strerror or e}", connect_ms)
        heard = _clock()
        if line is None:
            return Answer(SILENT, f"{at} closed the connection without an SSH banner", connect_ms)
        text = line.decode("latin-1")               # every byte as it came, one character each
        if not line.startswith(banner):
            return Answer(NOT_SSH, f"{at} answered {_quoted(text)}, not an SSH banner", connect_ms)
        return Answer(LIVE, None, connect_ms, (heard - connected) * 1000, text)
    finally:
        sock.close()


async def attempt(host: str, port: int, banner: Optional[bytes], seconds: float) -> Answer:
    """One try at one box: the name looked up, a TCP connect to each of its
    addresses in turn until one answers, then (with `banner`, the bytes an
    SSH server's first line starts with) the first line read and checked.
    Each wait, the lookup, the connect and the banner, gets `seconds`."""
    at = where(host, port)
    try:
        addresses = await _lookup(host, port, seconds)
    except socket.gaierror as e:
        if e.errno in _NO_SUCH_NAME:
            return Answer(NO_NAME, f"cannot resolve {host}")
        return Answer(NO_NAME, f"name lookup for {host} failed: {e.strerror or e}")
    except asyncio.TimeoutError:
        return Answer(NO_NAME, f"name lookup for {host} did not answer within {seconds:g}s")
    if not addresses:
        return Answer(NO_NAME, f"cannot resolve {host}")
    loop = asyncio.get_running_loop()
    failure: Optional[OSError] = None
    for family, kind, proto, _, address in addresses:
        try:
            sock = socket.socket(family, kind, proto)
        except OSError as e:                        # no descriptor to spare, a family switched off
            failure = e
            continue
        try:
            sock.setblocking(False)
            started = _clock()
            await asyncio.wait_for(_connect(loop, sock, address), seconds)
        except asyncio.TimeoutError:                # before OSError: on 3.11 and later it is one
            failure = TimeoutError()
        except OSError as e:
            failure = e
        except BaseException:
            sock.close()
            raise
        else:
            connected = _clock()
            rtt = kernel_rtt_ms(sock)
            connect_ms = rtt if rtt is not None else (connected - started) * 1000
            return await _hear(loop, sock, at, banner, seconds, connect_ms, connected)
        sock.close()
    if failure is None or isinstance(failure, TimeoutError) or failure.errno == errno.ETIMEDOUT:
        return Answer(TIMED_OUT, tcp_timed_out(at, seconds))
    return Answer(REFUSED if failure.errno == errno.ECONNREFUSED else NO_ROUTE, answered(failure, at))


def _ms(value: Optional[float]) -> Optional[float]:
    return None if value is None else round(value, 3)


async def _probe(t: Target, seconds: float, slow_ms: float, slots: asyncio.Semaphore) -> ProbeResult:
    """One box: a try, and for a box that did not answer, one more after
    RETRY_PAUSE (a box that was busy, a packet lost in the burst). The
    slot is given back for the pause."""
    port = resolve_target_port(t)
    banner = drivers.get(t.vendor).transport.banner
    started = _clock()
    async with slots:
        answer = await attempt(t.host, port, banner, seconds)
    if answer.result != LIVE:
        await asyncio.sleep(RETRY_PAUSE)
        async with slots:
            answer = await attempt(t.host, port, banner, seconds)
    tag = slow_tag(answer.connect_ms, slow_ms) if answer.result == LIVE else None
    return ProbeResult(t.name, t.host, port, t.vendor, answer.result, _ms(answer.connect_ms), _ms(answer.banner_ms),
                       answer.banner, answer.reason, tag, int((_clock() - started) * 1000))


async def probe(targets: Sequence[Target], seconds: float, slow_ms: float = SLOW_MS,
                limit: int = MAX_PROBES) -> List[ProbeResult]:
    """Every target probed, at most `limit` at once, the results in the
    targets' order. `seconds` is each wait's (the TCP connect, then the
    banner): the connect timeout."""
    slots = asyncio.Semaphore(max(1, int(limit)))
    return list(await asyncio.gather(*(_probe(t, seconds, slow_ms, slots) for t in targets)))


def in_thread(targets: Sequence[Target], seconds: float, slow_ms: float = SLOW_MS,
              limit: int = MAX_PROBES) -> cf.Future:
    """probe() for code without an event loop of its own (hssh.fleet): it
    runs on a daemon thread with a loop of its own, and the Future returned
    gets its results. A caller that stops waiting leaves the thread to end
    by itself, within the probe's own timeouts; it never holds up the
    interpreter's exit."""
    future: cf.Future = cf.Future()
    targets = list(targets)

    def run():
        if not future.set_running_or_notify_cancel():
            return
        try:
            found = asyncio.run(probe(targets, seconds, slow_ms, limit))
        except BaseException as e:      # noqa: BLE001 - the future carries it to the caller
            future.set_exception(e)
        else:
            future.set_result(found)
    threading.Thread(target=run, name="hssh-probe", daemon=True).start()
    return future


def tally(results: Sequence[ProbeResult]) -> str:
    """`N live, M dead (refused 1, timed out 2), K slow`: the summary's counts."""
    live = sum(1 for r in results if r.ok)
    dead = [r.result for r in results if not r.ok]
    text = f"{live} live"
    if dead:
        text += f", {len(dead)} dead (" + ", ".join(f"{what} {dead.count(what)}" for what in RESULTS
                                                     if what in dead) + ")"
    slow = sum(1 for r in results if r.slow)
    return text + (f", {slow} slow" if slow else "")
