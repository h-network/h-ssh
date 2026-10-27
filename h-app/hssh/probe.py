"""The probe (#127): is each box there, asked at the protocol level and
without logging in. A TCP connect; the server's lines read until one is its
identification (an SSH server speaks first: `SSH-2.0-...`, after other
lines if it likes, as RFC 4253 lets it) and that checked to be SSH; the
connection closed. No key exchange, no login, no credential: on the router
it is one SSH connection closed before login (OpenSSH logs "Did not receive
identification string from ..." or "Connection closed by ... [preauth]"),
never a failed login. A box on telnet (frozen; it has no banner) is a TCP
connect alone, and so is a junos box on port 23, which PyEZ reaches as a
console over telnet (Transport.console_port). Plain TCP, so no root is
needed.

The probe asks where the run will go. A transport that reads the ssh
client's configuration (Transport.ssh_config) connects where it says: the
OpenSSH client applies HostName, Port, ProxyJump and ProxyCommand, as
`ssh -G` prints them; PyEZ and ncclient, the junos transport's, read
~/.ssh/config for HostName, Port (over the target's own) and ProxyCommand.
A box reached through a proxy is not probed, since the probe would ask the
wrong host, and neither is one the caller holds back (the safety gate's
cooldown): the run goes to it as without the probe.

Each box gets one result: live, with sshd's version string; refused; no
route; name not found; timed out, no TCP answer within the connect timeout;
silent, TCP accepted and no banner within it (or the connection closed
without one); not SSH, something else answered; error, the probe itself
failed on something it did not expect; not probed. Every result but live
and not probed is a dead box. A probe that fails is tried once more after
a short pause. At most `limit` run at once: MAX_PROBES (hssh.limits),
fitted by the caller to the open-file limit as the workers are.

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
import os
import re
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import List, Mapping, NamedTuple, Optional, Sequence, Tuple

from . import drivers
from .core import Target, resolve_target_port
from .limits import MAX_PROBES
from .transports.connect import answered, no_banner, tcp_timed_out, where

__all__ = ["ProbeResult", "Answer", "Route", "probe", "in_thread", "attempt", "slow_tag", "ms_text",
           "kernel_rtt_ms", "tally", "RESULTS", "SLOW_MS", "RETRY_PAUSE", "MAX_PROBES"]

LIVE = "live"
REFUSED = "refused"
NO_ROUTE = "no route"
NO_NAME = "name not found"
TIMED_OUT = "timed out"
SILENT = "silent"
NOT_SSH = "not SSH"
ERROR = "error"
NOT_PROBED = "not probed"
RESULTS = (LIVE, REFUSED, NO_ROUTE, NO_NAME, TIMED_OUT, SILENT, NOT_SSH, ERROR, NOT_PROBED)

SLOW_MS = 10            # the threshold by default: --slow, `slow` in the config file, slow_ms=
RETRY_PAUSE = 0.5       # seconds before a failed probe is tried again
MAX_LINE = 255          # RFC 4253: the identification line, its CR LF included; here a line before it too
MAX_LINES = 100         # lines read at most, the identification the last of them, as paramiko reads them
_TCP_INFO_RTT = 68      # tcpi_rtt, in microseconds, in Linux's struct tcp_info
_TCP_INFO_LEN = 104
# The resolver's own answer that the name does not exist, as the ssh transport reads it.
_NO_SUCH_NAME = frozenset({socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)})

# How the transports read the ssh client's configuration: the OpenSSH
# client's own reading of its files, and the file PyEZ reads for the junos
# transport (None: ~/.ssh/config, found as PyEZ finds it). The suite points
# both at nothing.
SSH_G = ("ssh", "-G")
SSH_CONFIG: Optional[str] = None
SSH_G_AT_ONCE = 8       # ssh -G runs at once: a few descriptors each, inside the margin hssh.limits keeps

_clock = time.perf_counter      # the wall clock: banner times, the fallback, how long a box took


@dataclass(frozen=True)
class ProbeResult:
    """One box's probe, as a value. `device` (also `name`), `host`, `port`
    and `vendor` say which box, `port` the one asked (the ssh
    configuration's, where the transport reads one); `result` is one of
    RESULTS, `ok` whether that is live, `dead` whether the box was found
    not there (every result but live and not probed). `connect_ms` is the
    TCP handshake's round trip (the kernel's measure; the connect's wall
    time where TCP_INFO is missing), for a box that accepted TCP;
    `banner_ms` the wall time from there to the banner line, for a live
    box on an SSH transport; `banner` sshd's version string as it came,
    without its CR LF; `reason` why a box is not live, in words; `slow` the
    tag of a live box whose round trip is above the threshold (`slow:
    answered in 10.7 ms (above 10 ms)`), else None; `duration_ms` the whole
    probe of the box, a second try included."""

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
    def dead(self) -> bool:
        """Found not to be there: every result but live and not probed."""
        return self.result not in (LIVE, NOT_PROBED)

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


class Route(NamedTuple):
    """Where a box's transport connects: `host` and `port`, and `via`, the
    proxy it goes through (`ProxyJump bastion`), where the probe cannot."""
    host: str
    port: int
    via: Optional[str] = None


class _Unknown(Exception):
    """Where a box's transport connects cannot be told: it is not probed."""


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


async def _on_a_thread(call, seconds: float, name: str):
    """call() on a daemon thread of its own, waited for at most `seconds`
    (asyncio.TimeoutError past that): one that does not return costs the
    probe that and never holds up the end of the run. Without a thread to
    spare it is called here, in the loop."""
    loop = asyncio.get_running_loop()
    answer = loop.create_future()

    def settle(found, error):
        if not answer.done():
            if error is None:
                answer.set_result(found)
            else:
                answer.set_exception(error)

    def run():
        try:
            found, error = call(), None
        except Exception as e:      # noqa: BLE001 - handed to the waiting probe
            found, error = None, e
        try:
            loop.call_soon_threadsafe(settle, found, error)
        except RuntimeError:        # the probe is over and its loop closed
            pass
    try:
        threading.Thread(target=run, name=name, daemon=True).start()
    except RuntimeError:
        return call()
    return await asyncio.wait_for(answer, seconds)


async def _lookup(host: str, port: int, seconds: float) -> list:
    """getaddrinfo for HOST:PORT over TCP. An address needs no resolver; a
    name is looked up on a daemon thread of its own and waited for at most
    `seconds`, so a resolver that does not answer costs the probe that and
    never holds up the end of the run."""
    try:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)
    except socket.gaierror:
        pass
    return await _on_a_thread(lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM), seconds,
                              "hssh-probe-lookup")


async def _connect(loop, sock, address) -> None:
    await loop.sock_connect(sock, address)


async def _identification(loop, sock, banner: bytes, got: bytearray) -> Optional[bytes]:
    """The server's identification line, the first that starts with
    `banner`, without its CR LF and MAX_LINE bytes at most. RFC 4253 lets a
    server send other lines before it, and paramiko and OpenSSH pass them
    over: so does this, up to MAX_LINES lines in all, each MAX_LINE bytes
    at most. Every byte read is kept in `got`, for the caller to quote.
    None for a server that closed first, or sent a longer line or more
    lines than that."""
    start = 0
    for _ in range(MAX_LINES):
        while got.find(b"\n", start) < 0 and len(got) - start < MAX_LINE:
            chunk = await loop.sock_recv(sock, MAX_LINE)
            if not chunk:
                break                               # closed: what came last is a line too
            got += chunk
        end = got.find(b"\n", start)
        line = bytes(got[start:end if end >= 0 else len(got)])[:MAX_LINE].rstrip(b"\r")
        if line.startswith(banner):
            return line
        if end < 0:                                 # closed, or MAX_LINE bytes and no line break
            return None
        start = end + 1
    return None


def _quoted(text: str, width: int = 40) -> str:
    return repr(text if len(text) <= width else text[:width] + "…")


async def _hear(loop, sock, at: str, banner: Optional[bytes], seconds: float, connect_ms: float,
                connected: float) -> Answer:
    """A connected box's identification, judged; the socket is closed after it."""
    try:
        if banner is None:                          # telnet: TCP is all there is to ask
            return Answer(LIVE, connect_ms=connect_ms)
        got = bytearray()
        why = f"{at} closed the connection without an SSH banner"
        try:
            line = await asyncio.wait_for(_identification(loop, sock, banner, got), seconds)
        except asyncio.TimeoutError:                # before OSError: on 3.11 and later it is one
            line, why = None, no_banner(at, seconds)
        except OSError as e:
            line = None
            why = (f"{at} reset the connection without an SSH banner" if e.errno == errno.ECONNRESET
                   else f"{at} failed before an SSH banner: {e.strerror or e}")
        if line is not None:                        # latin-1: every byte as it came, one character each
            return Answer(LIVE, None, connect_ms, (_clock() - connected) * 1000, line.decode("latin-1"))
        first = bytes(got).split(b"\n", 1)[0][:MAX_LINE].rstrip(b"\r")
        if b"\n" in got or not (first.startswith(banner) or banner.startswith(first)):
            # a line came and no SSH one after it, or what came cannot begin one: something else is there
            return Answer(NOT_SSH, f"{at} answered {_quoted(first.decode('latin-1'))}, not an SSH banner",
                          connect_ms)
        return Answer(SILENT, why, connect_ms)
    finally:
        sock.close()


def _codec_words(e: ValueError) -> str:
    """Why a name is no name, in the idna codec's own words: its reason, or
    its message without the `encoding with 'idna' codec failed (...)` that
    Python 3.10 wraps around it."""
    reason = getattr(e, "reason", None)
    if isinstance(reason, str) and reason:
        return reason
    found = re.fullmatch(r"encoding with '[^']*' codec failed \(\w+: (.*)\)", str(e), re.S)
    return found.group(1) if found else str(e)


async def attempt(host: str, port: int, banner: Optional[bytes], seconds: float) -> Answer:
    """One try at one box: the name looked up, a TCP connect to each of its
    addresses in turn until one answers, then (with `banner`, the bytes an
    SSH server's identification starts with) its lines read and checked.
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
    except ValueError as e:     # UnicodeError too: a name no resolver takes (`10.0.0..1`, a label over 63)
        return Answer(NO_NAME, f"cannot resolve {host}: {_codec_words(e)}")
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


def _ssh_g(host: str, port: Optional[int], default: int, user: Optional[str], seconds: float) -> Route:
    """Where the OpenSSH client connects for HOST, as `ssh -G` prints it:
    its config files read as for the run, `-p` only for a target that
    names its port, as the openssh transport passes it. Without an ssh
    binary nothing reads those files: HOST as it is, on `port` or the
    transport's `default`."""
    argv = [*SSH_G, *(["-p", str(port)] if port else []), "--", f"{user}@{host}" if user else host]
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=seconds)
    except FileNotFoundError:
        return Route(host, port or default)
    except subprocess.TimeoutExpired:
        raise _Unknown(f"ssh -G did not answer within {seconds:g}s")
    except OSError as e:
        raise _Unknown(f"ssh -G could not run: {e.strerror or e}")
    said = {}
    for line in done.stdout.decode("utf-8", "replace").splitlines():
        key, _, value = line.strip().partition(" ")
        said.setdefault(key.lower(), value.strip())
    if done.returncode != 0 or not said.get("hostname") or not said.get("port", "22").isdigit():
        # ssh's own words; not its note that a pipe is no terminal
        complaint = next((ln.strip() for ln in done.stderr.decode("utf-8", "replace").splitlines()
                          if ln.strip() and not ln.startswith("Pseudo-terminal")), f"exit {done.returncode}")
        raise _Unknown(f"ssh -G {host}: {complaint}")
    to = Route(said["hostname"], int(said.get("port", port or default)))
    for key, name in (("proxyjump", "ProxyJump"), ("proxycommand", "ProxyCommand")):
        if said.get(key, "none").lower() != "none":
            return to._replace(via=f"{name} {said[key]} (ssh -G)")
    return to


def _pyez_config():
    """~/.ssh/config as PyEZ and ncclient read it for the junos transport,
    parsed by paramiko as they parse it; None where there is no such file
    (or no paramiko: then no PyEZ either)."""
    path = SSH_CONFIG or os.path.join(os.path.expanduser("~"), ".ssh", "config")
    if not os.path.exists(path):
        return None
    try:
        import paramiko
    except ImportError:
        return None
    config = paramiko.SSHConfig()
    with open(path) as fp:
        config.parse(fp)
    return config


def _pyez_route(config, host: str, port: int, console: bool = False) -> Route:
    """Where the junos transport connects for HOST: ncclient takes the
    file's HostName and ProxyCommand (not ProxyJump), PyEZ its Port over
    the target's own. A console (PyEZ's Console, over telnet) takes the
    Port alone: it telnets to HOST as given. (The command is not quoted:
    paramiko fills its %p with 22 unless told the port, as ncclient tells
    it.)"""
    found = config.lookup(host)
    try:
        to = Route(host if console else found.get("hostname", host), int(found.get("port", port)))
    except ValueError:
        raise _Unknown(f"~/.ssh/config gives {host} port {found.get('port')!r}")
    if console:
        return to
    return to._replace(via="ProxyCommand (~/.ssh/config)") if found.get("proxycommand") else to


class _Shared:
    """What one probe() shares between its boxes: the slots, the turns of
    ssh -G, the junos transport's ~/.ssh/config read once, and the boxes
    held back."""

    def __init__(self, seconds: float, slow_ms: float, limit: int, user: Optional[str],
                 held: Optional[Mapping[str, str]]):
        self.seconds, self.slow_ms, self.user = seconds, slow_ms, user
        self.held = dict(held or {})
        self.slots = asyncio.Semaphore(max(1, int(limit)))
        self.ssh_g = asyncio.Semaphore(SSH_G_AT_ONCE)
        self.pyez: Optional[Tuple[object, Optional[str]]] = None     # (the parsed file or None, why it is not)

    async def route(self, t: Target, port: int, reader: Optional[str], console: bool = False) -> Route:
        """Where the box's transport connects; _Unknown when that cannot be
        told (an ssh configuration that cannot be read: the run says why).
        `console`: the junos transport reaches the box as a console over
        telnet, which reads only the Port of ~/.ssh/config."""
        if reader == "openssh":
            try:
                async with self.ssh_g:
                    return await _on_a_thread(lambda: _ssh_g(t.host, t.port, port, self.user, self.seconds),
                                              self.seconds + 1, "hssh-probe-ssh-g")
            except asyncio.TimeoutError:
                raise _Unknown(f"ssh -G did not answer within {self.seconds:g}s")
        if reader == "paramiko":
            if self.pyez is None:
                try:
                    self.pyez = (_pyez_config(), None)
                except Exception as e:      # noqa: BLE001 - PyEZ will fail on it too, and say so
                    self.pyez = (None, str(e) or type(e).__name__)
            config, why = self.pyez
            if why is not None:
                raise _Unknown(f"~/.ssh/config: {why}")
            if config is not None:
                try:
                    return _pyez_route(config, t.host, port, console)
                except _Unknown:
                    raise
                except Exception as e:      # noqa: BLE001 - a Match the lookup cannot run, say
                    raise _Unknown(f"~/.ssh/config for {t.host}: {e}")
        return Route(t.host, port)

    async def once(self, to: Route, banner: Optional[bytes]) -> Answer:
        async with self.slots:
            return await attempt(to.host, to.port, banner, self.seconds)


async def _ask(t: Target, port: int, run: _Shared) -> Tuple[Answer, int]:
    """What one box comes to, and the port asked: a box held back or
    reached through a proxy is not probed; the others get a try, and one
    that did not answer one more after RETRY_PAUSE (a box that was busy, a
    packet lost in the burst). The slot is given back for the pause."""
    why = run.held.get(t.host)
    if why:
        return Answer(NOT_PROBED, why), port
    transport = drivers.get(t.vendor).transport
    # A console over telnet (PyEZ on port 23) sends no SSH banner: TCP alone, as for telnet.
    console = transport.console_port is not None and port == transport.console_port
    banner = None if console else transport.banner
    try:
        to = await run.route(t, port, transport.ssh_config, console)
    except _Unknown as e:
        return Answer(NOT_PROBED, str(e)), port
    if to.via:
        return Answer(NOT_PROBED, f"reached through {to.via}"), to.port
    answer = await run.once(to, banner)
    if answer.result != LIVE:
        await asyncio.sleep(RETRY_PAUSE)
        answer = await run.once(to, banner)
    return answer, to.port


def _ms(value: Optional[float]) -> Optional[float]:
    return None if value is None else round(value, 3)


async def _probe(t: Target, run: _Shared) -> ProbeResult:
    """One box's ProbeResult. Anything the probe did not expect is that
    box's result, error, and never the end of the other boxes' probe."""
    started = _clock()
    port = resolve_target_port(t)
    try:
        answer, port = await _ask(t, port, run)
    except Exception as e:      # noqa: BLE001 - one box's surprise is its own result
        answer = Answer(ERROR, f"the probe of {where(t.host, port)} failed: {type(e).__name__}: {e}")
    tag = slow_tag(answer.connect_ms, run.slow_ms) if answer.result == LIVE else None
    return ProbeResult(t.name, t.host, port, t.vendor, answer.result, _ms(answer.connect_ms), _ms(answer.banner_ms),
                       answer.banner, answer.reason, tag, int((_clock() - started) * 1000))


async def probe(targets: Sequence[Target], seconds: float, slow_ms: float = SLOW_MS,
                limit: int = MAX_PROBES, user: Optional[str] = None,
                held: Optional[Mapping[str, str]] = None) -> List[ProbeResult]:
    """Every target probed, at most `limit` at once, the results in the
    targets' order. `seconds` is each wait's (the TCP connect, then the
    banner): the connect timeout. `user` is the login the run will use,
    which an ssh configuration may match on; `held` maps a host the probe
    must not contact to why (the safety gate's cooldown): that box is not
    probed."""
    run = _Shared(seconds, slow_ms, limit, user, held)
    return list(await asyncio.gather(*(_probe(t, run) for t in targets)))


def in_thread(targets: Sequence[Target], seconds: float, slow_ms: float = SLOW_MS,
              limit: int = MAX_PROBES, user: Optional[str] = None) -> cf.Future:
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
            found = asyncio.run(probe(targets, seconds, slow_ms, limit, user))
        except BaseException as e:      # noqa: BLE001 - the future carries it to the caller
            future.set_exception(e)
        else:
            future.set_result(found)
    threading.Thread(target=run, name="hssh-probe", daemon=True).start()
    return future


def tally(results: Sequence[ProbeResult]) -> str:
    """`N live, M dead (refused 1, timed out 2), P not probed, K slow`: the summary's counts."""
    live = sum(1 for r in results if r.ok)
    dead = [r.result for r in results if r.dead]
    text = f"{live} live"
    if dead:
        text += f", {len(dead)} dead (" + ", ".join(f"{what} {dead.count(what)}" for what in RESULTS
                                                     if what in dead) + ")"
    passed = sum(1 for r in results if r.result == NOT_PROBED)
    slow = sum(1 for r in results if r.slow)
    return text + (f", {passed} not probed" if passed else "") + (f", {slow} slow" if slow else "")
