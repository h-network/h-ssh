"""Junos transport — PyEZ (NETCONF) for show, structured show and configuration.

Everything goes through junos-eznc, the official Juniper library, over a
NETCONF session: show uses Device.cli(), structured show uses a Table/View,
and config uses lock -> load -> commit_check -> diff -> commit (or rollback
for --dry-run) -> unlock. The NETCONF port defaults to 830 everywhere; set
the target's port to use NETCONF over SSH on 22.

A session is opened and closed per call unless the session pool is enabled
(hssh.pool.enable()), in which case each call borrows the router's open
session and gives it back. A session that fails underneath a call is
discarded, never handed to the next caller.
"""

import getpass
import hashlib
import os
import re
import socket
import threading
import time
from contextlib import contextmanager
from typing import List, Optional

from ..core import COMMENT_BYTES, check_comment, check_confirm_minutes, refused_reply
from ..dialects.junos import (SET_PREFIX_VERBS as JUNOS_SET_PREFIX_VERBS, COMMIT_PENDING as _PENDING,
                              DIALECT as _JUNOS)
# ConnectTimeoutError is h-ssh's (hssh.errors), not PyEZ's class of that name.
from ..errors import AmbiguousCommitError, ConnectTimeoutError, NotAppliedError, NothingToConfirmError
from ..drivers import results as R
from ..pool import POOL
from .connect import (DEFAULT as DEFAULT_CONNECT_TIMEOUT, answered, budget, is_timeout, no_banner,
                      tcp_timed_out, timed_out)

try:
    from jnpr.junos import Device as JunosDevice
    from jnpr.junos.utils.config import Config as JunosConfig
    from jnpr.junos.exception import (
        ConnectError, ConnectClosedError, LockError, ConfigLoadError, CommitError,
        RpcError, RpcTimeoutError,
    )
    AVAILABLE = True
except ImportError:
    AVAILABLE = False
    JunosDevice = JunosConfig = None

    class ConnectError(Exception):
        pass

    class ConnectClosedError(ConnectError):
        pass

    class LockError(Exception):
        pass

    class ConfigLoadError(Exception):
        pass

    class CommitError(Exception):
        pass

    class RpcError(Exception):
        pass

    class RpcTimeoutError(RpcError):     # as in PyEZ: a timeout is an RpcError too
        pass

try:
    from ncclient.transport.errors import TransportError
except ImportError:
    class TransportError(Exception):
        pass

try:
    import paramiko as _paramiko
    import ncclient.transport.ssh as _ncclient_ssh
except ImportError:
    _paramiko = _ncclient_ssh = None

# The deadlines of the _open() running on this thread, monotonic: `at` for
# the whole session set-up, `connect_at` for its connect phase (the TCP
# connect and the banner, #126); paramiko's Transport and the socket
# ncclient opens read them while the session is being set up, and the
# socket leaves what the OS answered its connect in `connect_error`.
_DEADLINE = threading.local()

_KEX_UNFINISHED = "the banner came, but key exchange did not finish"
_REVOKED = "its key is marked @revoked in "


if _paramiko is not None:
    class _DeadlineTransport(_paramiko.Transport):
        """paramiko waits 15 s for the SSH banner, 15 s for the key exchange
        and 30 s for authentication. Those are set in Transport.__init__ and
        neither ncclient nor PyEZ passes anything else, so a router that
        accepts TCP and then says nothing cost 15 s whatever --session-timeout
        said (H3). Each timeout now answers with what is left of this thread's
        deadlines, read when paramiko asks: the banner with what is left of
        the connect phase (#126), the key exchange and authentication with
        what is left of the session set-up. Without a deadline (another
        ncclient user in the same process) the defaults stay."""

        def __init__(self, *args, **kwargs):
            # Captured here, on the thread that runs _open(); the timeouts
            # are read on the Transport's own thread, where the local is unset.
            self._hssh_deadline = getattr(_DEADLINE, "at", None)
            self._hssh_connect_deadline = getattr(_DEADLINE, "connect_at", None)
            super().__init__(*args, **kwargs)

        def _timeout(name, default, connect_phase=False):
            def get(self):
                at = self.__dict__.get("_hssh_deadline")
                if connect_phase and self.__dict__.get("_hssh_connect_deadline") is not None:
                    at = self.__dict__["_hssh_connect_deadline"]
                own = self.__dict__.get(name, default)
                return own if at is None else max(0.1, at - time.monotonic())

            def set(self, value):
                self.__dict__[name] = value
            return property(get, set)

        banner_timeout = _timeout("_hssh_banner", 15, connect_phase=True)
        handshake_timeout = _timeout("_hssh_handshake", 15)
        auth_timeout = _timeout("_hssh_auth", 30)

        def start_client(self, event=None, timeout=None):
            # A key exchange that does not finish (the deadline, or the
            # server closing) ends in paramiko's bare EOFError, which ncclient
            # lets through and PyEZ renders "ConnectError" with nothing after it.
            try:
                return super().start_client(event=event, timeout=timeout)
            except EOFError as e:
                if not self.remote_version or self.initial_kex_done:
                    raise
                raise _paramiko.SSHException(_KEX_UNFINISHED) from e

    class _KnownHosts(_paramiko.HostKeys):
        """The known_hosts ncclient checks the router's key against
        (HSSH_NETCONF_HOSTKEY=yes), read as the ssh transport reads
        ~/.ssh/known_hosts. paramiko's own load() refused the whole file over
        an @cert-authority or @revoked line, which an SSH CA puts in every
        user's file: the first is passed over, and a key the second names is
        refused whatever else the file says."""

        def __init__(self, filename=None):
            self._revoked = {}          # key blob -> the file that revokes it
            super().__init__(filename)

        def load(self, filename):
            from .ssh import _parse
            with open(filename, "rb") as f:
                text = f.read().decode("utf-8", "surrogateescape")
            keys, revoked = _parse(text, filename, system=True)
            self._entries.extend(keys._entries)
            self._revoked.update(dict.fromkeys(revoked, filename))

        def check(self, hostname, key):
            where = self._revoked.get(key.asbytes())
            if where is not None:
                raise _paramiko.SSHException(_REVOKED + where)
            return super().check(hostname, key)

    class _ParamikoForNcclient:
        """ncclient's view of the paramiko module: as it is, except that
        Transport is the deadline-aware one and HostKeys reads known_hosts
        as the ssh transport does. Only ncclient sees this; paramiko itself
        and the ssh transport's SSHClient are untouched."""

        Transport = _DeadlineTransport
        HostKeys = _KnownHosts

        def __init__(self, module):
            self._module = module

        def __getattr__(self, name):
            return getattr(self._module, name)

    if _ncclient_ssh is not None and not isinstance(_ncclient_ssh.paramiko, _ParamikoForNcclient):
        _ncclient_ssh.paramiko = _ParamikoForNcclient(_ncclient_ssh.paramiko)

    class _ConnectSocket(socket.socket):
        """The socket ncclient opens to the router. Its connect gets what is
        left of this thread's connect phase, every address of the name
        together (ncclient gives each one the whole timeout again), and what
        the OS answered is kept: ncclient says only "Could not open socket",
        where the reason should say refused, no route or no answer (#126)."""

        def connect(self, address):
            at = getattr(_DEADLINE, "connect_at", None)
            if at is not None:
                left = max(0.001, at - time.monotonic())
                own = self.gettimeout()
                self.settimeout(left if own is None else min(own, left))
            try:
                return super().connect(address)
            except OSError as e:
                if at is not None:
                    _DEADLINE.connect_error = e
                raise

    class _SocketForNcclient:
        """ncclient's view of the socket module: as it is, except that the
        socket it opens to the router is a _ConnectSocket."""

        socket = _ConnectSocket

        def __init__(self, module):
            self._module = module

        def __getattr__(self, name):
            return getattr(self._module, name)

    if _ncclient_ssh is not None and not isinstance(_ncclient_ssh.socket, _SocketForNcclient):
        _ncclient_ssh.socket = _SocketForNcclient(_ncclient_ssh.socket)

DEFAULT_PORT = 830

# A pooled session idle this long is probed with a cheap RPC before reuse, so
# a router that silently dropped it is noticed here and not under an edit.
PROBE_AFTER = 30
# The probe, and closing a session, never deserve the command timeout: a dead
# socket would otherwise stall every caller queued on this router behind it.
SHORT_TIMEOUT = 5


def _require() -> None:
    if not AVAILABLE:
        raise RuntimeError("junos-eznc (PyEZ) not available.")


def _open(host: str, user: str, passwd: Optional[str], session_timeout: int,
          command_timeout: int, port: Optional[int], connect_timeout: int = DEFAULT_CONNECT_TIMEOUT):
    """Open a NETCONF session. Failures here mean nothing reached the device."""
    connect_s = budget(connect_timeout, session_timeout)
    params = {
        "host": host,
        "user": user,
        "port": port or DEFAULT_PORT,
        "gather_facts": False,
        # PyEZ hands this to ncclient for the TCP connect and for the wait
        # for the router's NETCONF hello (on port 23, a console over telnet,
        # for the whole login): the session timeout. _ConnectSocket holds
        # the TCP connect, every address of the name together, to what is
        # left of the connect phase.
        "conn_open_timeout": session_timeout,
        # A reply with a text node over 10 MB (a big configuration, a log
        # file) is rejected by lxml unless the parser is told to expect it.
        "huge_tree": True,
        # Off by default, deliberately: the lab and the management network
        # are trusted paths. HSSH_NETCONF_HOSTKEY=yes verifies the router's
        # key against ~/.ssh/known_hosts (an unknown or changed key refuses
        # the session), for a jump host on a path that is not.
        "hostkey_verify": os.environ.get("HSSH_NETCONF_HOSTKEY", "no").strip().lower() in ("yes", "1", "true"),
    }
    if passwd:
        params["passwd"] = passwd
        # The password is the credential: no ~/.ssh/id_* is tried first (and
        # never with the device password as its passphrase), no agent asked.
        params["look_for_keys"] = False
        params["allow_agent"] = False
    try:
        dev = JunosDevice(**params)
    except ValueError as e:
        # PyEZ validates the host itself: "only alphanumerics, dots,
        # underscores, hyphens, or bracketed IPv6 literals are permitted".
        raise NotAppliedError(f"NETCONF connect failed: PyEZ does not accept host {host!r}: {e}") from e
    started = time.monotonic()
    # One deadline for the session set-up, and a nearer one for its connect
    # phase: the TCP connect and the banner have --connect-timeout between
    # them (#126), the key exchange and authentication what is left of the
    # session timeout.
    _DEADLINE.at = started + session_timeout
    _DEADLINE.connect_at = started + connect_s
    _DEADLINE.connect_error = None
    try:
        dev.open()
    except Exception as e:
        os_error = getattr(_DEADLINE, "connect_error", None)
        # open() may have partially established the transport before
        # raising; close the local device so we don't leak it.
        try:
            dev.close()
        except Exception:
            pass
        if isinstance(e, ConnectError):
            reason = _connect_reason(e, host, _login(host, user, port, dev), params["port"], session_timeout,
                                     time.monotonic() - started, connect_timeout=connect_s, os_error=os_error)
            # A connect phase that ran out is retried; anything else in it is not.
            failed = ConnectTimeoutError if timed_out(reason) else NotAppliedError
            raise failed(f"NETCONF connect failed: {reason}") from e
        raise
    finally:
        _DEADLINE.at = _DEADLINE.connect_at = _DEADLINE.connect_error = None
    dev.timeout = command_timeout
    return dev


def _login(host: str, user: Optional[str], port: Optional[int] = None, dev=None) -> Optional[str]:
    """The name a NETCONF session to `host` logs in as, worked out as PyEZ
    and ncclient work it out, without connecting: `user` when there is one;
    without, PyEZ's Device takes the `User` ~/.ssh/config gives the host,
    else $USER (user=None is no user at all to it), and ncclient the name
    getpass finds when PyEZ has none. `dev` is a Device already made for
    the session, else one is made here and never opened. The history logs
    a commit under this name, and a login refused is named by it."""
    if user:
        return user
    try:
        if dev is None:
            dev = JunosDevice(host=host, user=user, port=port or DEFAULT_PORT, gather_facts=False)
        name = dev.user
    except Exception:
        name = None
    if not name:
        try:
            name = getpass.getuser()
        except Exception:
            name = None
    return name


def _connect_reason(exc: BaseException, host: str, user: str, port: int,
                    timeout: float, elapsed: float, connect_timeout: Optional[float] = None,
                    os_error: Optional[BaseException] = None) -> str:
    """Why the session did not open, in words. PyEZ names a connect failure
    by its class and picks the class by the clock: anything that fails
    within 3 s is ConnectRefusedError, whether the port was closed, the
    banner was garbage, sshd dropped the session or the host key was
    refused. The reason is in the exception PyEZ was handling, so read that,
    and for the TCP connect, which ncclient reports as "Could not open
    socket" whatever happened, what the OS answered it (`os_error`).
    `timeout` is the session timeout, `connect_timeout` what the TCP
    connect and the banner had between them (the session timeout when not
    given)."""
    where = f"{host}:{port}"
    seconds = timeout if connect_timeout is None else connect_timeout
    kind = type(exc).__name__
    cause = getattr(exc, "_orig", None) or exc.__context__ or exc.__cause__
    cause_kind = type(cause).__name__ if cause is not None else ""
    text = str(cause) if cause is not None else ""
    low = text.lower()
    if kind == "ConnectAuthError" or cause_kind == "AuthenticationError":
        return f"authentication failed for {user} at {where}"
    if kind == "ConnectUnknownHostError" or isinstance(cause, socket.gaierror):
        why = f"cannot resolve {host}"
        if ":" in host:
            why += " (an IPv6 literal is not accepted by this PyEZ/ncclient; use a name)"
        return why
    if cause_kind == "SSHUnknownHostError" or "unknown host key" in low:
        return (f"host key verification failed for {where}: not in ~/.ssh/known_hosts, or changed "
                "(HSSH_NETCONF_HOSTKEY=yes); nothing was sent")
    if _REVOKED in text:
        return f"host key verification failed for {where}: {text}; nothing was sent"
    if "malformed known_hosts line" in low:
        return text
    if "could not open socket" in low:
        if os_error is not None:
            return tcp_timed_out(where, seconds) if is_timeout(os_error) else answered(os_error, where)
        if elapsed >= seconds - 0.5:
            return tcp_timed_out(where, seconds)
        return f"connection refused by {where} (nothing listening, or no route)"
    if "ssh protocol banner" in low:
        detail = text.split("banner", 1)[1].strip()
        if "codec" in detail or "decode" in detail:
            return f"{where} is not an SSH server: the banner is not text"
        if detail and "timed out" not in detail:
            return (f"{where} dropped the session before login after {elapsed:.1f}s "
                    f"({detail}; sshd connection limit?)")
        # paramiko says the same for a banner that never came and a server
        # that closed first; what it was handling (a timeout, or an EOF)
        # tells them apart, and the clock does when that is not there.
        chain = list(_chain(cause))
        if any(isinstance(e, TimeoutError) for e in chain) or (
                not any(isinstance(e, EOFError) for e in chain) and elapsed >= seconds - 0.5):
            return no_banner(where, seconds)
        return f"{where} dropped the session before login after {elapsed:.1f}s (sshd connection limit?)"
    if _KEX_UNFINISHED in low:
        if elapsed < timeout / 2:
            return f"{where} dropped the session before login after {elapsed:.1f}s ({_KEX_UNFINISHED})"
        return f"no SSH session to {where} within {timeout}s: {_KEX_UNFINISHED}"
    if "negotiation failed" in low:
        return f"SSH negotiation with {where} failed: {text.split(':', 1)[1].strip()}"
    if kind == "ConnectTimeoutError":
        return tcp_timed_out(where, seconds)
    return f"{kind} for {where}" + (f": {text}" if text else "")


_CLOSES: "set[threading.Thread]" = set()
_CLOSES_LOCK = threading.Lock()


def _close(dev) -> Optional[threading.Thread]:
    """Close the session beside the work, not on the worker's clock.

    <close-session> and its acknowledgement are ~100 ms of waiting on the
    device, a quarter of what a show costs per device; a worker used to
    spend it before moving to its next device. A helper thread waits
    instead, the device still sees a clean NETCONF close, and
    wait_for_closes() at the end of a run joins what is still in flight.
    Returns that thread, for a caller that must see the close through (the
    pool, before it collects what a close leaves behind); None when the
    close ran here."""
    t = threading.Thread(target=_close_now, args=(dev,), name="hssh-netconf-close", daemon=True)
    with _CLOSES_LOCK:
        _CLOSES.add(t)
    try:
        t.start()
    except Exception:
        # The system refused the thread (ulimit -u, a container's pids.max).
        # Close here instead, on the caller's clock: ~100 ms, never the
        # result, and no entry in the set that nobody can join (#113).
        with _CLOSES_LOCK:
            _CLOSES.discard(t)
        _close_now(dev)
        return None
    return t


def _close_now(dev) -> None:
    try:
        dev.timeout = SHORT_TIMEOUT
        dev.close()
    except Exception:
        # close-session got no answer; PyEZ has already marked the Device
        # closed, so drop the transport ourselves or its reader thread lingers.
        try:
            dev._conn._session.close()
        except Exception:
            pass
    finally:
        with _CLOSES_LOCK:
            _CLOSES.discard(threading.current_thread())


def wait_for_closes(timeout: float = 1.0) -> int:
    """Wait for the session closes still in flight, `timeout` seconds in
    all. Returns how many had not finished by then; their transports go
    away with the process, and the device drops the session on the EOF."""
    deadline = time.monotonic() + timeout
    with _CLOSES_LOCK:
        pending = list(_CLOSES)
    for t in pending:
        try:
            t.join(max(0.0, deadline - time.monotonic()))
        except RuntimeError:
            pass    # not started yet: _close() is between adding it and start()
    return sum(1 for t in pending if t.is_alive())


def _alive(dev, idle: float) -> bool:
    """Is a pooled session worth reusing? PyEZ only clears `connected` when it
    closed the session itself; one the router dropped without a FIN still
    says connected, so after a long idle ask the router."""
    if not getattr(dev, "connected", True):
        return False
    if idle >= PROBE_AFTER:
        try:
            dev.rpc.get_system_uptime_information(dev_timeout=SHORT_TIMEOUT)
        except RpcTimeoutError:
            raise                        # no answer in time: dead, or as good as
        except RpcError:
            # The router answered, with a refusal: cRPD has no uptime RPC, a
            # login class may withhold it. A refusal is proof of a live
            # session; only the transport failing means dead (#59).
            return True
    return True


def _chain(exc: BaseException):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def _session_lost(exc: BaseException) -> bool:
    """True when the error, or what PyEZ wrapped it around, says the NETCONF
    session itself is gone."""
    return any(isinstance(e, (ConnectClosedError, TransportError, OSError))
               for e in _chain(exc))


def _timed_out(exc: BaseException) -> bool:
    return any(isinstance(e, RpcTimeoutError) for e in _chain(exc))


def _pool_key(host: str, port: Optional[int], user: str, passwd: Optional[str]) -> tuple:
    """What identifies a pooled session: the router, the user and a digest of
    the credential (never the password itself)."""
    return (host, port or DEFAULT_PORT, user, hashlib.sha256((passwd or "").encode()).hexdigest()[:16])


@contextmanager
def _session(host: str, user: str, passwd: Optional[str], session_timeout: int,
             command_timeout: int, port: Optional[int], connect_timeout: int = DEFAULT_CONNECT_TIMEOUT):
    """A session for this router: fresh, or borrowed from the pool."""
    # The credential is part of a session's identity: a later call with a
    # different, wrong or absent password must not ride the session the
    # first one opened. A digest of it, not the password, sits in the key.
    key = _pool_key(host, port, user, passwd)
    with POOL.get_connection(
        key,
        opener=lambda: _open(host, user, passwd, session_timeout, command_timeout, port, connect_timeout),
        closer=_close,
        timeout=command_timeout,
        alive=_alive,
    ) as lease:
        yield lease


def _on_session(host, user, passwd, session_timeout, command_timeout, port, fn,
                connect_timeout=DEFAULT_CONNECT_TIMEOUT):
    """Run fn(lease) on the router's session. A read is idempotent, so if a
    *reused* session turns out to be dead, open a new one and run it again
    once; a timeout or a dead fresh session is reported as before."""
    for attempt in (1, 2):
        with _session(host, user, passwd, session_timeout, command_timeout, port, connect_timeout) as lease:
            try:
                return fn(lease)
            except Exception as e:
                if _session_lost(e):
                    lease.discard()
                    if lease.reused and attempt == 1:
                        continue
                elif _timed_out(e):
                    lease.discard()  # a reply may still be in flight
                raise


def _cli(dev, cmd: str) -> str:
    # NETCONF returns the whole reply, so a pager hint is meaningless here.
    if cmd.rstrip().endswith("| no-more"):
        cmd = cmd.rstrip()[: -len("| no-more")].rstrip()
    out = dev.cli(cmd, warning=False)
    return (out or "").rstrip()


def _shown(dev, cmd: str) -> str:
    """A show's reply: _cli's text, unless the CLI refused the command. Most
    Junos refusals come back as an rpc-error, which PyEZ raises; one carried
    as the reply's text (`<output>error: could not resolve file: ...`) was
    handed back as the show's output, OK, where ssh and openssh fail it as
    refused (#143). The runner tries a refusal once."""
    text = _cli(dev, cmd)
    refused = refused_reply("", text, dialect=_JUNOS)
    if refused:
        raise RuntimeError("'%s' was refused by the device: %s" % (cmd, refused))
    return text


def show(host: str, user: str, passwd: str, cmd: str,
         session_timeout: int, command_timeout: int,
         port: int = None, vendor_hint: str = None, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> str:
    """Execute a show command over NETCONF. A read finds a dead reused
    session and runs once more on a new one; anything else (`request …`)
    is sent once, as rpc() does. A reply that opens with the CLI's refusal
    is a failure, not output (_shown). `connect_timeout` bounds the TCP
    connect and the SSH banner, never more than `session_timeout` (every
    function here that opens a session takes it)."""
    _require()
    run_on = _on_session if _is_read(cmd) else _on_session_once
    return run_on(host, user, passwd, session_timeout, command_timeout, port,
                  lambda lease: _shown(lease.dev, cmd), connect_timeout)


def show_structured(host: str, user: str, passwd: str, cmd: str,
                    session_timeout: int, command_timeout: int,
                    port: int = None, vendor_hint: str = None,
                    binding: Optional[dict] = None, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT):
    """Fetch structured data over NETCONF using a PyEZ Table/View binding.

    Note this is *not* a parse of the `cmd` text — it issues the RPC named in
    the binding, so the CLI path and this path are two different requests
    against two different representations. `cmd` is accepted only to keep the
    signature aligned with show().

    The binding is the "structured" entry from hssh/dialects/junos.json:

        {"rpc": "get-bgp-neighbor-information",
         "item": "bgp-peer",
         "key": "peer-address",
         "fields": {"remote_as": {"peer-as": "int"}, ...}}

    Field values are PyEZ view field specs: either a bare xpath string, or a
    single-key mapping of xpath to a type or value test ("int", "True=Established").
    Returns a dict keyed by the binding's key field.
    """
    _require()
    if not binding:
        raise ValueError(
            f"No structured binding for '{cmd}' on junos. "
            "Add a \"structured\" key to the entry in hssh/dialects/junos.json."
        )

    from jnpr.junos.factory import FactoryLoader

    table_name = "hssh_table"
    view_name = "hssh_view"
    fields = {}
    for field, spec in (binding.get("fields") or {}).items():
        fields[field] = spec

    definition = {
        table_name: {
            "rpc": binding["rpc"],
            "item": binding["item"],
            "key": binding["key"],
            "view": view_name,
        },
        view_name: {"fields": fields},
    }

    table_cls = FactoryLoader().load(definition)[table_name]

    def fetch(lease):
        table = table_cls(lease.dev)
        table.get()
        return {key: dict(item) for key, item in table.items()}

    return _on_session(host, user, passwd, session_timeout, command_timeout, port, fetch, connect_timeout)


def _config_format(payload: str) -> str:
    """"set" when every meaningful line is a set-style command, else "text"."""
    lines = [ln.strip() for ln in payload.splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    if lines and all(ln.startswith(JUNOS_SET_PREFIX_VERBS) for ln in lines):
        return "set"
    return "text"


def _strip_comments(payload: str) -> str:
    return "\n".join(ln for ln in payload.splitlines()
                     if ln.strip() and not ln.strip().startswith("#"))


def _lock(cu, lease) -> None:
    """Take the configuration lock on the borrowed session. A refusal is a
    NotAppliedError: nothing was sent, the caller may retry."""
    try:
        cu.lock()
    except LockError as e:
        # PyEZ wraps a timed-out or dead-session lock RPC in LockError
        # too; the device may have granted that lock, so the session
        # goes, which releases it, and the retry gets a fresh one.
        if _session_lost(e) or _timed_out(e):
            lease.discard()
        raise NotAppliedError(f"Failed to lock config: {e}") from e
    except Exception as e:
        if _session_lost(e):
            lease.discard()
            raise NotAppliedError(f"NETCONF session lost before lock: {e}") from e
        raise


def _unlock_quietly(cu) -> Optional[str]:
    try:
        cu.unlock()
        return None
    except Exception as e:
        return str(e)


MAX_ROLLBACK = 49   # Junos keeps rollback 0-49


class Transaction:
    """An open change on the router's session: locked, loaded, checked and
    diffed, waiting for commit() or abort(). Made by begin(); meant for a gate
    that wants to look at `diff` — or at the device, through show()/rpc() on
    the same session — before deciding. Leaving a `with` block without
    commit() aborts.

    The pooled session stays borrowed while the transaction is open: other
    threads wanting this router wait, this thread may keep using it.
    """

    def __init__(self, cm, lease, cu, diff: str, label: str, command_timeout: int):
        self._cm = cm
        self._lease = lease
        self._cu = cu
        self.diff = diff
        self.label = label
        self._timeout = command_timeout
        self.open = True
        # The pool's per-router lock is re-entrant and owned by this thread;
        # only this thread can hand the session back.
        self._owner = threading.get_ident()

    @property
    def dev(self):
        return self._lease.dev

    def show(self, cmd: str) -> str:
        """A show on the transaction's session, judged as show() judges
        one: a reply that opens with the CLI's refusal raises (_shown). It
        was handed back as the output, and a gate that looked for a word in
        it went on to commit on a command the device refused (#143)."""
        self._require_open()
        return _shown(self.dev, cmd)

    def rpc(self, command: str, args: Optional[dict] = None, fmt: str = "json"):
        self._require_open()
        return _rpc_on_lease(self._lease, command, args, fmt)

    def commit(self, confirmed: Optional[int] = None, comment: Optional[str] = None) -> str:
        """Commit the candidate: COMMIT OK, or COMMIT CONFIRMED (n minutes)
        when `confirmed` is set, with the diff. NO CHANGES if there were none.
        If the session died while the transaction was open (a nested show()
        hit a timeout or a dropped transport), nothing is sent: the lock and
        candidate went with the session, and that is a NotAppliedError. A
        comment that cannot be logged as it is (core.check_comment: a line
        break, a control character, no text, over 512 bytes) is refused
        before the commit RPC is built: nothing was committed, so the
        candidate is discarded and the lock released, and the ValueError
        says so."""
        self._require_open()
        check_confirm_minutes(confirmed)   # before anything else: the candidate stays open
        if self._lease.doomed or not getattr(self.dev, "connected", True):
            self._lease.discard()
            self._finish(rollback=False, unlock=False)
            raise NotAppliedError("NETCONF session lost during the transaction; nothing committed")
        try:
            comment = check_comment(comment, outcome="nothing was committed: the candidate was discarded "
                                                     "and the lock released")
        except ValueError:
            # An ESC reached PyEZ, which refused it before the RPC was sent,
            # and the except below called that an unknown outcome: the
            # session dropped, the candidate and the lock left to it (#146).
            # No commit was sent, so nothing was committed. begin() has sent
            # the lock, the load and the check, and the abort sends the
            # rollback and the unlock: the error says so, not "nothing was
            # sent".
            self.abort()
            raise
        if not self.diff.strip():
            self.abort()
            return R.EditResult(R.NO_CHANGES, label=self.label)
        kwargs = {"timeout": self._timeout}
        if confirmed is not None:
            kwargs["confirm"] = confirmed
        if comment:
            kwargs["comment"] = comment
        try:
            self._cu.commit(**kwargs)
        except CommitError as e:
            self._finish(rollback=True, unlock=True)
            raise RuntimeError(f"Config error: {e}") from e
        except Exception as e:
            # The commit RPC was sent. We cannot tell whether it landed: leave
            # the candidate alone, drop the session.
            self._lease.discard()
            self._finish(rollback=False, unlock=False)
            raise AmbiguousCommitError(
                f"commit outcome unknown ({type(e).__name__}: {e}); "
                "check the device before retrying") from e
        self._finish(rollback=False, unlock=True)
        if confirmed is not None:
            return R.EditResult(R.CONFIRMED, diff=self.diff, minutes=confirmed, label=self.label)
        return R.EditResult(R.COMMITTED, diff=self.diff, label=self.label)

    def abort(self) -> None:
        """Discard the candidate and release the lock."""
        self._finish(rollback=True, unlock=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.open and threading.get_ident() == self._owner:
            self.abort()
        return False

    def _require_open(self) -> None:
        if not self.open:
            raise RuntimeError("transaction is no longer open")
        if threading.get_ident() != self._owner:
            # A commit from here would land on the device and then fail to
            # release the owner's lock, with the slot wedged for every other
            # caller. Refuse before any RPC: nothing is sent.
            raise RuntimeError("transaction must be used and finished on the thread that opened it; "
                               "nothing was sent to the device")

    def _finish(self, rollback: bool, unlock: bool) -> None:
        if not self.open:
            return
        if threading.get_ident() != self._owner:
            raise RuntimeError("transaction must be used and finished on the thread that opened it; "
                               "nothing was sent to the device")
        self.open = False
        try:
            if rollback:
                try:
                    self._cu.rollback()
                except Exception:
                    self._lease.discard()
            if unlock and _unlock_quietly(self._cu) is not None:
                self._lease.discard()
        finally:
            self._cm.__exit__(None, None, None)


def _begin(host: str, user: str, passwd: Optional[str], session_timeout: int,
           command_timeout: int, port: Optional[int], stage, label: str,
           connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> Transaction:
    """lock -> stage(cu) -> diff -> commit_check, left open as a Transaction.
    `stage` puts the change into the candidate: a load for edit(), a rollback
    for rollback(). Raises NotAppliedError for failures before anything could
    change on the device and RuntimeError for rejected config; on any failure
    the candidate is discarded and the lock released."""
    cm = _session(host, user, passwd, session_timeout, command_timeout, port, connect_timeout)
    lease = cm.__enter__()
    cu = None
    locked = False
    try:
        cu = JunosConfig(lease.dev)
        _lock(cu, lease)
        locked = True
        try:
            stage(cu)
            diff = (cu.diff() or "")
            if diff.strip():
                cu.commit_check(timeout=command_timeout)
        except (ConfigLoadError, CommitError) as e:
            raise RuntimeError(f"Config error: {e}") from e
        return Transaction(cm, lease, cu, diff, label, command_timeout)
    except BaseException as e:
        if isinstance(e, Exception) and (_session_lost(e) or _timed_out(e)):
            lease.discard()
        if cu is not None and locked:
            try:
                cu.rollback()
            except Exception:
                lease.discard()
            if _unlock_quietly(cu) is not None:
                lease.discard()
        cm.__exit__(type(e), e, e.__traceback__)
        raise


def _transaction(host: str, user: str, passwd: str, session_timeout: int,
                 command_timeout: int, port: Optional[int], stage, label: str,
                 dry_run: bool, commit_confirmed: Optional[int],
                 comment: Optional[str] = None, expected_diff: Optional[str] = None,
                 connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> str:
    """begin() and finish in one go: commit (confirmed if asked), or for
    dry_run show the diff the device produced and discard it. With
    `expected_diff` (the diff a dry run showed) the commit goes ahead only
    if the candidate produces that diff again. Only NotAppliedError is safe
    to retry; AmbiguousCommitError means a commit was sent and its outcome
    is unknown."""
    tx = _begin(host, user, passwd, session_timeout, command_timeout, port, stage, label, connect_timeout)
    if expected_diff is not None and tx.diff.strip() != expected_diff.strip():
        # The device, or the file, changed between the preview and the y:
        # what would be committed is not what was approved.
        tx.abort()
        raise RuntimeError("diff changed since preview; nothing committed")
    if not tx.diff.strip():
        tx.abort()
        return R.EditResult(R.NO_CHANGES, label=label)
    if dry_run:
        diff = tx.diff
        tx.abort()
        return R.EditResult(R.DRY_RUN, diff=diff, label=label, note="commit check passed, nothing committed")
    return tx.commit(confirmed=commit_confirmed, comment=comment)


def begin(host: str, user: str, passwd: str, payload: Optional[str],
          session_timeout: int, command_timeout: int,
          port: int = None, vendor_hint: str = None, rollback: Optional[int] = None,
          connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> Transaction:
    """Open a change and hand it back for a decision: `payload` (set/text
    config) or `rollback=n`, locked, loaded, checked and diffed on the
    router's session. Then tx.commit(confirmed=, comment=) or tx.abort().

        with transports.netconf.begin(host, user, None, payload, 30, 20) as tx:
            print(tx.diff)
            if looks_right(tx.diff):
                tx.commit(confirmed=10, comment="C1 cutover")
    """
    _require()
    if (payload is None) == (rollback is None):
        raise ValueError("begin() takes a payload or rollback=n, not both and not neither")
    if rollback is not None:
        n = _rollback_number(rollback)
        return _begin(host, user, passwd, session_timeout, command_timeout, port,
                      stage=lambda cu: cu.rollback(n), label=f"ROLLBACK {n}: ", connect_timeout=connect_timeout)
    fmt = _config_format(payload)
    body = _strip_comments(payload) if fmt == "set" else payload
    return _begin(host, user, passwd, session_timeout, command_timeout, port,
                  stage=lambda cu: cu.load(body, format=fmt, ignore_warning=IGNORED_LOAD_WARNINGS), label="",
                  connect_timeout=connect_timeout)


# Load warnings that do not fail the device. A delete of a statement the
# device does not have is "warning: statement not found": the intended state
# is already there, so a broadcast of deletes stays idempotent (M2). Every
# other warning is still an error.
IGNORED_LOAD_WARNINGS = "statement not found"


def _rollback_number(n) -> int:
    try:
        n = int(n)
    except (TypeError, ValueError):
        raise ValueError(f"rollback number must be an integer 0-{MAX_ROLLBACK}, not {n!r}")
    if not 0 <= n <= MAX_ROLLBACK:
        raise ValueError(f"rollback number must be 0-{MAX_ROLLBACK}, not {n}")
    return n


def edit(host: str, user: str, passwd: str, payload: str,
         session_timeout: int, command_timeout: int,
         commit_confirmed: int = None, port: int = None,
         vendor_hint: str = None, dry_run: bool = False,
         comment: Optional[str] = None, expected_diff: Optional[str] = None,
         connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> str:
    """Apply configuration over NETCONF: load the payload into the candidate
    and run it through _transaction() (lock -> load -> diff -> commit_check
    -> commit, or rollback for dry_run -> unlock). `comment` is logged with
    the commit and shows in `show system commit`; `expected_diff`, the diff
    an earlier dry_run showed, is what the candidate must still produce or
    nothing is committed. A comment is checked before anything is sent
    (core.check_comment) and sent stripped."""
    _require()
    check_confirm_minutes(commit_confirmed)
    comment = check_comment(comment)
    fmt = _config_format(payload)
    body = _strip_comments(payload) if fmt == "set" else payload
    return _transaction(host, user, passwd, session_timeout, command_timeout, port,
                        stage=lambda cu: cu.load(body, format=fmt, ignore_warning=IGNORED_LOAD_WARNINGS), label="",
                        dry_run=dry_run, commit_confirmed=commit_confirmed, comment=comment,
                        expected_diff=expected_diff, connect_timeout=connect_timeout)


def rollback(host: str, user: str, passwd: str, n: int,
             session_timeout: int, command_timeout: int,
             port: int = None, vendor_hint: str = None,
             dry_run: bool = False, commit_confirmed: int = None,
             comment: Optional[str] = None, expected_diff: Optional[str] = None,
             connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> str:
    """Return to rollback `n` (0-49) over NETCONF, with the same gates as an
    edit: lock -> rollback n -> diff -> commit_check -> commit (confirmed if
    asked), or show the diff and discard it for dry_run, or refuse it when
    it is not the `expected_diff` a dry run showed. "NO CHANGES" when
    rollback n equals the running configuration. A comment is held to
    edit()'s rule."""
    _require()
    check_confirm_minutes(commit_confirmed)
    comment = check_comment(comment)
    n = _rollback_number(n)
    return _transaction(host, user, passwd, session_timeout, command_timeout, port,
                        stage=lambda cu: cu.rollback(n), label=f"ROLLBACK {n}: ",
                        dry_run=dry_run, commit_confirmed=commit_confirmed, comment=comment,
                        expected_diff=expected_diff, connect_timeout=connect_timeout)


def confirm(host: str, user: str, passwd: str,
            session_timeout: int, command_timeout: int,
            port: int = None, vendor_hint: str = None,
            comment: Optional[str] = None, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> str:
    """Confirm a pending commit-confirmed with a plain commit, under the
    configuration lock. The commit takes the whole shared candidate with
    it, another user's uncommitted edits included; the lock is refused
    while the candidate is modified, and that refusal is a NotAppliedError
    (nothing sent, retried like any other) rather than their change going
    in with the confirmation. A comment is held to edit()'s rule."""
    _require()
    comment = check_comment(comment)
    return _confirm(host, user, passwd, session_timeout, command_timeout, port, comment, connect_timeout)


class _Moved(Exception):
    """The commit confirmed guarded_commit() made is no longer the one
    waiting: why (`reason`), and the history read under the lock (`entries`)."""

    def __init__(self, reason: str, entries: List[dict]):
        super().__init__(reason)
        self.reason = reason
        self.entries = entries


def _release_lock(cu, lease, exc: Optional[BaseException] = None) -> None:
    """Give up the configuration lock taken on the borrowed session, nothing
    committed: unlock it, or, after `exc` lost the session or left it in
    doubt, drop the session and the lock with it."""
    if exc is not None and (_session_lost(exc) or _timed_out(exc)):
        lease.discard()
    elif _unlock_quietly(cu) is not None:
        lease.discard()


def _confirm(host: str, user: str, passwd: Optional[str], session_timeout: int, command_timeout: int,
             port: Optional[int], comment: Optional[str], connect_timeout: int,
             ours: Optional[dict] = None) -> str:
    """confirm(), and guarded_commit()'s. With `ours`, the commit confirmed
    guarded_commit() made, the history is read once the lock is held, and
    the plain commit goes only while that entry is still the one waiting
    at sequence 0; otherwise the lock is released, nothing committed, and
    _Moved says why. A commit that lands after the lock cannot come
    between that read and the confirmation; one read before it could."""
    with _session(host, user, passwd, session_timeout, command_timeout, port, connect_timeout) as lease:
        # A plain commit with nothing waiting is not a confirmation: the
        # timer expired (the change is gone) or someone confirmed before.
        # Either way the operator must know; a commit would only hide it.
        if ours is None and _pending_on(lease.dev, command_timeout) is None:
            raise NothingToConfirmError(
                "nothing to confirm: no commit-confirmed is pending on the device "
                "(the timer expired, or it was confirmed already); nothing was sent")
        cu = JunosConfig(lease.dev)
        _lock(cu, lease)
        if ours is not None:
            try:
                entries = _history_on(lease.dev, command_timeout)
            except Exception as e:
                _release_lock(cu, lease, e)
                raise
            moved = _history_moved(ours, entries)
            if moved:
                _release_lock(cu, lease)
                raise _Moved(moved, entries)
        try:
            if comment:
                cu.commit(timeout=command_timeout, comment=comment)
            else:
                cu.commit(timeout=command_timeout)
        except CommitError as e:
            if _unlock_quietly(cu) is not None:
                lease.discard()
            raise RuntimeError(f"Commit failed: {e}") from e
        except Exception as e:
            # The commit RPC was sent and the session is in doubt: it goes,
            # and the lock with it.
            lease.discard()
            raise AmbiguousCommitError(
                f"commit outcome unknown ({type(e).__name__}: {e}); "
                "check the device before retrying") from e
        if _unlock_quietly(cu) is not None:
            lease.discard()
        return R.EditResult(R.CONFIRMED_OK)


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = None,
               connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> List[dict]:
    """Execute several show commands on one NETCONF session.

    A rejected or timed-out command, or one whose reply opens with the
    CLI's refusal (_shown), is reported in its own result and the batch
    goes on (after a timeout the session is not kept, a late reply may
    still be coming). A session that dies is a failure of the whole batch;
    a reused one gets show()'s reopen-once treatment only when every command
    is a read, as rpc_batch() does."""
    _require()

    def run(lease):
        results = []
        for cmd in cmds:
            try:
                results.append({"command": cmd, "ok": True, "output": _shown(lease.dev, cmd)})
            except Exception as e:
                if _session_lost(e):
                    raise
                if _timed_out(e):
                    lease.discard()
                results.append({"command": cmd, "ok": False, "error": str(e)})
        return R.BatchResult(results)

    run_on = _on_session if all(_is_read(c) for c in cmds) else _on_session_once
    return run_on(host, user, passwd, session_timeout, command_timeout, port, run, connect_timeout)


def _is_cli_command(text: str) -> bool:
    """"show chassis hardware" is a CLI command; "get-chassis-inventory" and
    "get_chassis_inventory" are RPC names."""
    return " " in text.strip() or not all(ch.isalnum() or ch in "-_" for ch in text.strip())


def _rpc_element(dev, command: str, args: Optional[dict]):
    """The RPC to send, as an lxml element: translated by the router from a
    CLI command (what `| display xml rpc` does), or built from an RPC name
    and its arguments."""
    from lxml import etree

    command = command.strip()
    if _is_cli_command(command):
        if args:
            raise ValueError("args go with an RPC name; put them in the CLI command instead")
        reply = dev.rpc.cli(command + " | display xml rpc", format="xml")
        try:
            return reply.getparent().find(".//rpc")[0]
        except (AttributeError, IndexError, TypeError):
            raise ValueError(f"no RPC equivalent for CLI command {command!r}") from None
    element = etree.Element(command.replace("_", "-"))
    for key, value in (args or {}).items():
        child = etree.SubElement(element, key.replace("_", "-"))
        if value is not True and value is not None:
            child.text = str(value)
    return element


def _rpc_format(fmt: Optional[str]) -> str:
    fmt = (fmt or "json").lower()
    if fmt not in ("json", "xml"):
        raise ValueError(f"fmt must be 'json' or 'xml', not {fmt!r}")
    return fmt


def _rpc_reply(dev, command: str, args: Optional[dict], fmt: str):
    """Send the RPC for `command` and return the reply as the router produces
    it: a dict for json, the reply XML as a string for xml."""
    from lxml import etree

    element = _rpc_element(dev, command, args)
    if fmt == "json":
        element.set("format", "json")
        return dev.execute(element)
    reply = dev.execute(element)
    return etree.tostring(reply, pretty_print=True, encoding="unicode")


def _is_read(command: str) -> bool:
    """A get-* RPC (any "show ..." command) is a read and safe to send twice;
    a string with a line break is not, whatever its first line says."""
    text = command.strip()
    return "\n" not in text and "\r" not in text and (text.startswith("show ") or text.startswith("get"))


def _on_session_once(host, user, passwd, session_timeout, command_timeout, port, fn,
                     connect_timeout=DEFAULT_CONNECT_TIMEOUT):
    """Run fn(lease) on the router's session exactly once: a failure drops a
    session left in doubt and is never re-sent, reused session or not."""
    with _session(host, user, passwd, session_timeout, command_timeout, port, connect_timeout) as lease:
        try:
            return fn(lease)
        except Exception as e:
            if _session_lost(e) or _timed_out(e):
                lease.discard()
            raise


def _rpc_on_lease(lease, command: str, args: Optional[dict], fmt: str):
    """_rpc_reply on a borrowed session (what Transaction.rpc() uses)."""
    return _rpc_reply(lease.dev, command, args, _rpc_format(fmt))


def rpc(host: str, user: str, passwd: str, command: str,
        session_timeout: int, command_timeout: int,
        port: int = None, vendor_hint: str = None,
        args: Optional[dict] = None, fmt: str = "json", connect_timeout: int = DEFAULT_CONNECT_TIMEOUT):
    """Call a Junos RPC and return the reply as the router produces it: a
    dict for fmt="json", the reply XML as a string for fmt="xml".

    `command` is either the CLI command you already know — "show chassis
    hardware", "show interfaces ge-0/0/0 terse" — in which case the router is
    asked which RPC that is, or an RPC name — "get-chassis-inventory" — with
    `args` as its arguments ({"interface-name": "ge-0/0/0", "terse": True}).

    A get-* RPC (any "show ..." command) is a read and, on a dead reused
    pooled session, is reopened and sent once more like show(). Anything else
    (request-*, ...) is never re-sent: it fails, and the session is dropped.
    """
    _require()
    fmt = _rpc_format(fmt)
    run_on = _on_session if _is_read(command) else _on_session_once
    return run_on(host, user, passwd, session_timeout, command_timeout, port,
                  lambda lease: _rpc_reply(lease.dev, command, args, fmt), connect_timeout)


def rpc_batch(host: str, user: str, passwd: str, cmds: List[str],
              session_timeout: int, command_timeout: int,
              port: int = None, vendor_hint: str = None,
              fmt: str = "json", connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> List[dict]:
    """rpc() for several CLI commands on one NETCONF session, each answered
    in its own {command, ok, output|error} the way show_batch() reports.

    A command the router has no RPC for, or rejects, or that times out, is
    reported in its result and the batch goes on (after a timeout the session
    is not kept). A session that dies fails the whole batch; it is reopened
    and the batch sent once more only when every command is a read, as rpc()
    does for one.
    """
    _require()
    fmt = _rpc_format(fmt)

    def run(lease):
        results = []
        for cmd in cmds:
            try:
                results.append({"command": cmd, "ok": True,
                                "output": _rpc_reply(lease.dev, cmd, None, fmt)})
            except Exception as e:
                if _session_lost(e):
                    raise
                if _timed_out(e):
                    lease.discard()
                results.append({"command": cmd, "ok": False, "error": str(e)})
        return R.BatchResult(results)

    run_on = _on_session if all(_is_read(c) for c in cmds) else _on_session_once
    return run_on(host, user, passwd, session_timeout, command_timeout, port, run, connect_timeout)




def commit_status(host: str, user: str, passwd: str,
                  session_timeout: int, command_timeout: int,
                  port: int = None, vendor_hint: str = None,
                  connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> List[dict]:
    """`show system commit` as data: one dict per entry, newest first —
    seq, user, client, time, epoch, comment (what was logged with the
    commit), note (the device's own text, "commit confirmed, rollback in
    5mins") and pending_rollback_minutes, set only on the latest entry
    (seq 0) when it carries that note: a commit confirmed that was
    confirmed by a later commit keeps its note in the history, but a
    later commit is exactly what means it is no longer waiting. The
    device's number is the authority on how long is left. (A confirm made
    with `commit check` writes no entry, so seq 0 still reads as pending
    after it; h-ssh confirms with a commit.)"""
    _require()
    doc = rpc(host, user, passwd, "get-commit-information", session_timeout, command_timeout, port=port,
              connect_timeout=connect_timeout)
    return R.CommitStatus(_commit_entries(doc))


def _commit_entries(doc: dict) -> List[dict]:
    """commit_status()'s entries from the router's get-commit-information reply."""
    def text(d, key):
        v = d.get(key)
        return v[0].get("data") if isinstance(v, list) and v and isinstance(v[0], dict) else None

    def attr(d, key, name):
        v = d.get(key)
        return (v[0].get("attributes") or {}).get(name) if isinstance(v, list) and v and isinstance(v[0], dict) else None

    out = []
    info = doc.get("commit-information") or []
    for entry in (info[0].get("commit-history") if info else []) or []:
        note = text(entry, "comment") or ""
        pending = _PENDING.search(note)
        epoch = attr(entry, "date-time", "junos:seconds")
        seq = int(text(entry, "sequence-number") or 0)
        out.append({
            "seq": seq,
            "user": text(entry, "user"),
            "client": text(entry, "client"),
            "time": text(entry, "date-time"),
            "epoch": float(epoch) if epoch else None,
            "comment": text(entry, "log"),
            "note": note or None,
            "pending_rollback_minutes": int(pending.group(1)) if pending and seq == 0 else None,
        })
    return out


def _history_on(dev, command_timeout: int) -> List[dict]:
    """commit_status()'s entries, read on an open session."""
    return _commit_entries(_rpc_reply(dev, "get-commit-information", None, "json"))


def _pending_on(dev, command_timeout: int) -> Optional[dict]:
    """The commit-confirmed still waiting on an open session's router, if any."""
    return pending_commit(_history_on(dev, command_timeout))


def pending_commit(entries: List[dict]) -> Optional[dict]:
    """The entry of commit_status() whose confirmed commit is still waiting, if any."""
    for e in entries:
        if e.get("pending_rollback_minutes") is not None:
            return e
    return None


def _same_commit(a: dict, b: dict) -> bool:
    """Two commit_status() entries for one commit: what the device logged
    about it, not the minutes left on its timer."""
    return all(a.get(k) == b.get(k) for k in ("user", "client", "time", "epoch", "comment"))


def _history_moved(ours: Optional[dict], entries: List[dict]) -> Optional[str]:
    """Why the commit confirmed `ours` is no longer the one waiting on the
    device, or None while it still is: it has to be the latest commit
    (sequence 0) and the same entry the device logged after the edit."""
    if ours is None:
        return "no pending commit confirmed of ours found after the edit"
    now = pending_commit(entries)
    if now is None or now.get("seq") != 0 or not _same_commit(ours, now):
        return "commit history changed since the edit (another commit landed, or the timer expired)"
    return None


def _ours(entries: List[dict], user: Optional[str], before: List[dict]) -> Optional[dict]:
    """The commit confirmed this login just made, in the history read right
    after it (`entries`, newest first), or None: the entry at sequence 0,
    still waiting, logged under the name the session logged in as
    (_login()), and the commit right after the one that was the latest when
    our lock was taken (`before`, the history read under the lock just
    before the commit, when no other commit could land): its time is the
    commit's. A commit that landed after ours, of this login too, puts ours
    at sequence 1 and is not taken for it. Never the comment: Junos keeps
    one as it keeps it (of one with a line break, only the last line)."""
    entry = entries[0] if entries else None
    if entry is None or entry.get("seq") != 0 or entry.get("user") != user:
        return None
    if entry.get("pending_rollback_minutes") is None:
        return None
    previous = entries[1] if len(entries) > 1 else None
    latest = before[0] if before else None
    if (previous is None) != (latest is None) or (latest is not None and not _same_commit(previous, latest)):
        return None
    return entry


# What guarded_commit() logs with its confirmation and its rollback, after
# the caller's comment.
_CONFIRMED = " (confirmed)"
_ROLLED_BACK = " (rolled back: checks failed)"


def guarded_commit(host: str, user: str, passwd: str, payload: str,
                   session_timeout: int, command_timeout: int, minutes: int, check,
                   port: int = None, comment: Optional[str] = None,
                   connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> dict:
    """Commit confirmed, run `check()`, then confirm — or roll straight back.

    `check` is the caller's verdict (anything true to keep the change); an
    exception counts as a failed check. On failure `rollback 1` is committed
    at once instead of waiting the timer out, so the device is back before
    the window closes. Returns {"final": "confirmed" | "rolled back" |
    "no changes", "commit": ..., "checks": ..., "confirm"/"rollback": ...}.

    Its own commit is the pending entry at sequence 0 of `show system
    commit` read right after it, logged under the name the session logged
    in as (`user`, or with user=None the one PyEZ takes: ~/.ssh/config's
    User for the host, else $USER) and right after the commit that was the
    latest when its lock was taken (the history is read under the lock,
    before the commit): found by its place and its login, never by the
    comment, which Junos keeps as it likes. The confirmation and the
    rollback each take the configuration lock first (the rollback with
    `rollback 1` loaded and checked, as begin(rollback=1) has it) and only
    then read the history again and compare it with that entry, so no
    commit lands between the look and the commit. When that is no longer
    the pending one — another commit landed (which confirmed ours too), or
    the checks outlasted the timer and the device rolled back by itself —
    nothing is committed and the lock is released, since `rollback 1`
    would now re-apply the change that just failed, and the result is "not
    confirmed" / "not rolled back" with the reason and the history under
    "status" (for "not rolled back" the check's own failure is under
    "check_error").

    `comment` is held to edit()'s rule, and so are the comments logged with
    the confirmation and the rollback, it with " (confirmed)" or " (rolled
    back: checks failed)" after it: one that leaves them no room within 512
    bytes is refused before anything is sent.
    """
    check_confirm_minutes(minutes)
    comment = check_comment(comment)
    confirmed_comment = f"{comment}{_CONFIRMED}" if comment else None
    rollback_comment = f"{comment}{_ROLLED_BACK}" if comment else "rolled back: checks failed"
    if len(rollback_comment.encode("utf-8")) > COMMENT_BYTES:
        raise ValueError(f"the comment {comment!r} is {len(comment.encode('utf-8'))} bytes: guarded_commit() "
                         f"logs its rollback as the comment and '{_ROLLED_BACK.strip()}', {COMMENT_BYTES} bytes "
                         f"at most, which leaves {COMMENT_BYTES - len(_ROLLED_BACK)} for the comment; "
                         "nothing was sent to the device")
    # The history logs the commit under the name the session logged in as,
    # with user=None PyEZ's (~/.ssh/config's User for the host, else $USER):
    # that name, not None, is what our entry carries.
    login = _login(host, user, port)
    with begin(host, user, passwd, payload, session_timeout, command_timeout, port=port,
               connect_timeout=connect_timeout) as tx:
        # The history under our lock: no other commit lands before ours
        # while it is held, so ours is the one logged right after this.
        before = _history_on(tx.dev, command_timeout) if tx.diff.strip() else []
        out = tx.commit(confirmed=minutes, comment=comment)
    if out.startswith("NO CHANGES"):
        return {"final": "no changes", "commit": out, "checks": None}
    ours = _ours(commit_status(host, user, passwd, session_timeout, command_timeout, port=port,
                               connect_timeout=connect_timeout), login, before)
    try:
        ok, reason = bool(check()), None
    except Exception as e:
        ok, reason = False, f"{type(e).__name__}: {e}"
    if ours is None:
        # No commit of ours to act on: the history as it is now, and nothing sent.
        entries = commit_status(host, user, passwd, session_timeout, command_timeout, port=port,
                                connect_timeout=connect_timeout)
        moved = _history_moved(None, entries)
        if ok:
            return {"final": "not confirmed", "commit": out, "checks": True, "reason": moved, "status": entries}
        return {"final": "not rolled back", "commit": out, "checks": False, "reason": moved,
                "check_error": reason, "status": entries}
    if ok:
        try:
            done = _confirm(host, user, passwd, session_timeout, command_timeout, port, confirmed_comment,
                            connect_timeout, ours=ours)
        except _Moved as e:
            return {"final": "not confirmed", "commit": out, "checks": True, "reason": e.reason,
                    "status": e.entries}
        return {"final": "confirmed", "commit": out, "checks": True, "confirm": done}
    with begin(host, user, passwd, None, session_timeout, command_timeout, port=port, rollback=1,
               connect_timeout=connect_timeout) as tx:
        # Under the lock, `rollback 1` loaded and checked: the history is
        # read now, and no commit lands between this look and the commit.
        entries = _history_on(tx.dev, command_timeout)
        moved = _history_moved(ours, entries)
        if moved:
            tx.abort()
            return {"final": "not rolled back", "commit": out, "checks": False, "reason": moved,
                    "check_error": reason, "status": entries}
        back = tx.commit(comment=rollback_comment)
    return {"final": "rolled back", "commit": out, "checks": False, "reason": reason, "rollback": back}
