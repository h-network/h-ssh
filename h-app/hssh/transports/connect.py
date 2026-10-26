"""The connect phase the three SSH transports share (netconf, ssh, openssh):
the TCP connect and the wait for the device's SSH banner, which
--connect-timeout bounds between them, and the words for how it ended (#126).

A healthy sshd sends its banner within milliseconds of the TCP connect (a
cRPD within about 100 ms, 254 of them at once). A box that does not answer
at all, or a port that accepts and then says nothing (a load balancer or a
NAT answering for a dead box, an sshd that hangs or is still booting,
something other than SSH on the port), used to cost a whole
--session-timeout an attempt. Running out here is a ConnectTimeoutError:
nothing was sent, so the runner tries again after a short pause. An answer
(refused, no route, a name that does not resolve) is said in the OS's words
and is not tried again. The key exchange, the authentication and the
NETCONF hello keep --session-timeout, and the connect phase never gets more
than that."""

import errno
import re

DEFAULT = 3     # seconds: the CLI's --connect-timeout, Fleet's connect_timeout

# How a connect phase runs out: the transports' words, and the OpenSSH
# client's own when its ConnectTimeout fires before the transport's clock.
_TIMED_OUT = re.compile(r"tcp connect to \S+ timed out after [\d.]+s"
                        r"|no ssh banner from \S+ within [\d.]+s"
                        r"|connect to host \S+ port \d+: connection timed out"
                        r"|connection timed out during banner exchange")


def budget(connect_timeout, session_timeout):
    """The connect phase's seconds: --connect-timeout, never more than
    --session-timeout."""
    return min(connect_timeout, session_timeout)


def where(host, port) -> str:
    """HOST:PORT, an IPv6 address in brackets."""
    host = str(host)
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"


def tcp_timed_out(at: str, seconds) -> str:
    return f"TCP connect to {at} timed out after {seconds:g}s"


def no_banner(at: str, seconds) -> str:
    return f"no SSH banner from {at} within {seconds:g}s"


def is_timeout(err: BaseException) -> bool:
    """A TCP connect nobody answered: the socket's own timeout, or the OS
    giving up on it (ETIMEDOUT); both are TimeoutError."""
    return isinstance(err, TimeoutError)


def answered(err: OSError, at: str) -> str:
    """A TCP connect the OS answered, in its words: the device, or a router
    on the way, said no. The same call gets the same answer."""
    code = getattr(err, "errno", None)
    if code == errno.ECONNREFUSED:
        return f"connection refused by {at}"
    if code == errno.EHOSTUNREACH:
        return f"no route to host {at}"
    if code == errno.ENETUNREACH:
        return f"network is unreachable for {at}"
    return f"TCP connect to {at} failed: {getattr(err, 'strerror', None) or err}"


def timed_out(text) -> bool:
    """True when `text` says the connect phase ran out: no TCP answer, or
    no SSH banner, in time."""
    return _TIMED_OUT.search(str(text).lower()) is not None
