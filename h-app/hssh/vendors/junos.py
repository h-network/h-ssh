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

import hashlib
import os
import re
import threading
from contextlib import contextmanager
from typing import List, Optional

from ..core import JUNOS_SET_PREFIX_VERBS, check_confirm_minutes
from ..errors import AmbiguousCommitError, NotAppliedError
from ..pool import POOL

try:
    from jnpr.junos import Device as JunosDevice
    from jnpr.junos.utils.config import Config as JunosConfig
    from jnpr.junos.exception import (
        ConnectError, ConnectClosedError, LockError, ConfigLoadError, CommitError,
        RpcTimeoutError,
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

    class RpcTimeoutError(Exception):
        pass

try:
    from ncclient.transport.errors import TransportError
except ImportError:
    class TransportError(Exception):
        pass

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
          command_timeout: int, port: Optional[int]):
    """Open a NETCONF session. Failures here mean nothing reached the device."""
    params = {
        "host": host,
        "user": user,
        "port": port or DEFAULT_PORT,
        "gather_facts": False,
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
    dev = JunosDevice(**params)
    try:
        dev.open()
    except Exception as e:
        # open() may have partially established the transport before
        # raising; close the local device so we don't leak it.
        try:
            dev.close()
        except Exception:
            pass
        if isinstance(e, ConnectError):
            raise NotAppliedError(f"NETCONF connect failed: {e}") from e
        raise
    dev.timeout = command_timeout
    return dev


def _close(dev) -> None:
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


def _alive(dev, idle: float) -> bool:
    """Is a pooled session worth reusing? PyEZ only clears `connected` when it
    closed the session itself; one the router dropped without a FIN still
    says connected, so after a long idle ask the router."""
    if not getattr(dev, "connected", True):
        return False
    if idle >= PROBE_AFTER:
        dev.rpc.get_system_uptime_information(dev_timeout=SHORT_TIMEOUT)
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
             command_timeout: int, port: Optional[int]):
    """A session for this router: fresh, or borrowed from the pool."""
    # The credential is part of a session's identity: a later call with a
    # different, wrong or absent password must not ride the session the
    # first one opened. A digest of it, not the password, sits in the key.
    key = _pool_key(host, port, user, passwd)
    with POOL.get_connection(
        key,
        opener=lambda: _open(host, user, passwd, session_timeout, command_timeout, port),
        closer=_close,
        timeout=command_timeout,
        alive=_alive,
    ) as lease:
        yield lease


def _on_session(host, user, passwd, session_timeout, command_timeout, port, fn):
    """Run fn(lease) on the router's session. A read is idempotent, so if a
    *reused* session turns out to be dead, open a new one and run it again
    once; a timeout or a dead fresh session is reported as before."""
    for attempt in (1, 2):
        with _session(host, user, passwd, session_timeout, command_timeout, port) as lease:
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


def show(host: str, user: str, passwd: str, cmd: str,
         session_timeout: int, command_timeout: int,
         port: int = None, vendor_hint: str = None) -> str:
    """Execute a show command over NETCONF."""
    _require()
    return _on_session(host, user, passwd, session_timeout, command_timeout, port,
                       lambda lease: _cli(lease.dev, cmd))


def show_structured(host: str, user: str, passwd: str, cmd: str,
                    session_timeout: int, command_timeout: int,
                    port: int = None, vendor_hint: str = None,
                    binding: Optional[dict] = None):
    """Fetch structured data over NETCONF using a PyEZ Table/View binding.

    Note this is *not* a parse of the `cmd` text — it issues the RPC named in
    the binding, so the CLI path and this path are two different requests
    against two different representations. `cmd` is accepted only to keep the
    signature aligned with show().

    The binding is the "structured" entry from commands/junos.json:

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
            "Add a \"structured\" key to the entry in commands/junos.json."
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

    return _on_session(host, user, passwd, session_timeout, command_timeout, port, fetch)


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
        self._require_open()
        return _cli(self.dev, cmd)

    def rpc(self, command: str, args: Optional[dict] = None, fmt: str = "json"):
        self._require_open()
        return _rpc_on_lease(self._lease, command, args, fmt)

    def commit(self, confirmed: Optional[int] = None, comment: Optional[str] = None) -> str:
        """Commit the candidate: COMMIT OK, or COMMIT CONFIRMED (n minutes)
        when `confirmed` is set, with the diff. NO CHANGES if there were none.
        If the session died while the transaction was open (a nested show()
        hit a timeout or a dropped transport), nothing is sent: the lock and
        candidate went with the session, and that is a NotAppliedError."""
        self._require_open()
        check_confirm_minutes(confirmed)   # before anything else: the candidate stays open
        if self._lease.doomed or not getattr(self.dev, "connected", True):
            self._lease.discard()
            self._finish(rollback=False, unlock=False)
            raise NotAppliedError("NETCONF session lost during the transaction; nothing committed")
        if not self.diff.strip():
            self.abort()
            return f"{self.label}NO CHANGES"
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
        head = f"COMMIT CONFIRMED ({confirmed} minutes)" if confirmed is not None else "COMMIT OK"
        return f"{self.label}{head}\n\nDIFF:\n{self.diff}"

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
           command_timeout: int, port: Optional[int], stage, label: str) -> Transaction:
    """lock -> stage(cu) -> diff -> commit_check, left open as a Transaction.
    `stage` puts the change into the candidate: a load for edit(), a rollback
    for rollback(). Raises NotAppliedError for failures before anything could
    change on the device and RuntimeError for rejected config; on any failure
    the candidate is discarded and the lock released."""
    cm = _session(host, user, passwd, session_timeout, command_timeout, port)
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
                 comment: Optional[str] = None, expected_diff: Optional[str] = None) -> str:
    """begin() and finish in one go: commit (confirmed if asked), or for
    dry_run show the diff the device produced and discard it. With
    `expected_diff` (the diff a dry run showed) the commit goes ahead only
    if the candidate produces that diff again. Only NotAppliedError is safe
    to retry; AmbiguousCommitError means a commit was sent and its outcome
    is unknown."""
    tx = _begin(host, user, passwd, session_timeout, command_timeout, port, stage, label)
    if expected_diff is not None and tx.diff.strip() != expected_diff.strip():
        # The device, or the file, changed between the preview and the y:
        # what would be committed is not what was approved.
        tx.abort()
        raise RuntimeError("diff changed since preview; nothing committed")
    if not tx.diff.strip():
        tx.abort()
        return f"{label}NO CHANGES"
    if dry_run:
        diff = tx.diff
        tx.abort()
        return f"{label}DRY-RUN: commit check passed, nothing committed\n\nDIFF:\n{diff}"
    return tx.commit(confirmed=commit_confirmed, comment=comment)


def begin(host: str, user: str, passwd: str, payload: Optional[str],
          session_timeout: int, command_timeout: int,
          port: int = None, vendor_hint: str = None, rollback: Optional[int] = None) -> Transaction:
    """Open a change and hand it back for a decision: `payload` (set/text
    config) or `rollback=n`, locked, loaded, checked and diffed on the
    router's session. Then tx.commit(confirmed=, comment=) or tx.abort().

        with vendors.junos.begin(host, user, None, payload, 30, 20) as tx:
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
                      stage=lambda cu: cu.rollback(n), label=f"ROLLBACK {n}: ")
    fmt = _config_format(payload)
    body = _strip_comments(payload) if fmt == "set" else payload
    return _begin(host, user, passwd, session_timeout, command_timeout, port,
                  stage=lambda cu: cu.load(body, format=fmt), label="")


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
         comment: Optional[str] = None, expected_diff: Optional[str] = None) -> str:
    """Apply configuration over NETCONF: load the payload into the candidate
    and run it through _transaction() (lock -> load -> diff -> commit_check
    -> commit, or rollback for dry_run -> unlock). `comment` is logged with
    the commit and shows in `show system commit`; `expected_diff`, the diff
    an earlier dry_run showed, is what the candidate must still produce or
    nothing is committed."""
    _require()
    check_confirm_minutes(commit_confirmed)
    fmt = _config_format(payload)
    body = _strip_comments(payload) if fmt == "set" else payload
    return _transaction(host, user, passwd, session_timeout, command_timeout, port,
                        stage=lambda cu: cu.load(body, format=fmt), label="",
                        dry_run=dry_run, commit_confirmed=commit_confirmed, comment=comment,
                        expected_diff=expected_diff)


def rollback(host: str, user: str, passwd: str, n: int,
             session_timeout: int, command_timeout: int,
             port: int = None, vendor_hint: str = None,
             dry_run: bool = False, commit_confirmed: int = None,
             comment: Optional[str] = None, expected_diff: Optional[str] = None) -> str:
    """Return to rollback `n` (0-49) over NETCONF, with the same gates as an
    edit: lock -> rollback n -> diff -> commit_check -> commit (confirmed if
    asked), or show the diff and discard it for dry_run, or refuse it when
    it is not the `expected_diff` a dry run showed. "NO CHANGES" when
    rollback n equals the running configuration."""
    _require()
    check_confirm_minutes(commit_confirmed)
    n = _rollback_number(n)
    return _transaction(host, user, passwd, session_timeout, command_timeout, port,
                        stage=lambda cu: cu.rollback(n), label=f"ROLLBACK {n}: ",
                        dry_run=dry_run, commit_confirmed=commit_confirmed, comment=comment,
                        expected_diff=expected_diff)


def confirm(host: str, user: str, passwd: str,
            session_timeout: int, command_timeout: int,
            port: int = None, vendor_hint: str = None,
            comment: Optional[str] = None) -> str:
    """Confirm a pending commit-confirmed with a plain commit, under the
    configuration lock. The commit takes the whole shared candidate with
    it, another user's uncommitted edits included; the lock is refused
    while the candidate is modified, and that refusal is a NotAppliedError
    (nothing sent, retried like any other) rather than their change going
    in with the confirmation."""
    _require()
    with _session(host, user, passwd, session_timeout, command_timeout, port) as lease:
        cu = JunosConfig(lease.dev)
        _lock(cu, lease)
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
        return "COMMIT CONFIRMED OK"


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = None) -> List[dict]:
    """Execute several show commands on one NETCONF session.

    A rejected or timed-out command is reported in its own result and the
    batch goes on (after a timeout the session is not kept, a late reply may
    still be coming). A session that dies is a failure of the whole batch:
    reads are idempotent, so a reused session gets the same reopen-once
    treatment as show()."""
    _require()

    def run(lease):
        results = []
        for cmd in cmds:
            try:
                results.append({"command": cmd, "ok": True, "output": _cli(lease.dev, cmd)})
            except Exception as e:
                if _session_lost(e):
                    raise
                if _timed_out(e):
                    lease.discard()
                results.append({"command": cmd, "ok": False, "error": str(e)})
        return results

    return _on_session(host, user, passwd, session_timeout, command_timeout, port, run)


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
    """A get-* RPC (any "show ..." command) is a read and safe to send twice."""
    text = command.strip()
    return text.startswith("show ") or text.startswith("get")


def _on_session_once(host, user, passwd, session_timeout, command_timeout, port, fn):
    """Run fn(lease) on the router's session exactly once: a failure drops a
    session left in doubt and is never re-sent, reused session or not."""
    with _session(host, user, passwd, session_timeout, command_timeout, port) as lease:
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
        args: Optional[dict] = None, fmt: str = "json"):
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
                  lambda lease: _rpc_reply(lease.dev, command, args, fmt))


def rpc_batch(host: str, user: str, passwd: str, cmds: List[str],
              session_timeout: int, command_timeout: int,
              port: int = None, vendor_hint: str = None,
              fmt: str = "json") -> List[dict]:
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
        return results

    run_on = _on_session if all(_is_read(c) for c in cmds) else _on_session_once
    return run_on(host, user, passwd, session_timeout, command_timeout, port, run)


_PENDING = re.compile(r"rollback in (\d+)\s*min", re.I)


def commit_status(host: str, user: str, passwd: str,
                  session_timeout: int, command_timeout: int,
                  port: int = None, vendor_hint: str = None) -> List[dict]:
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
    doc = rpc(host, user, passwd, "get-commit-information", session_timeout, command_timeout, port=port)

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


def _ours(entry: Optional[dict], user: str, comment: Optional[str]) -> Optional[dict]:
    """The pending entry when it is the commit this user just made (same
    user, and the comment that was sent with it), else None."""
    if entry is None or entry.get("seq") != 0 or entry.get("user") != user:
        return None
    if comment and entry.get("comment") != comment:
        return None
    return entry


def guarded_commit(host: str, user: str, passwd: str, payload: str,
                   session_timeout: int, command_timeout: int, minutes: int, check,
                   port: int = None, comment: Optional[str] = None) -> dict:
    """Commit confirmed, run `check()`, then confirm — or roll straight back.

    `check` is the caller's verdict (anything true to keep the change); an
    exception counts as a failed check. On failure `rollback 1` is committed
    at once instead of waiting the timer out, so the device is back before
    the window closes. Returns {"final": "confirmed" | "rolled back" |
    "no changes", "commit": ..., "checks": ..., "confirm"/"rollback": ...}.

    Before confirming or rolling back, `show system commit` is read again
    and compared with the entry the commit confirmed made. When that is no
    longer the pending one — another commit landed (which confirmed ours
    too), or the checks outlasted the timer and the device rolled back by
    itself — nothing is sent, since `rollback 1` would now re-apply the
    change that just failed, and the result is "not confirmed" / "not
    rolled back" with the reason and the history under "status" (for "not
    rolled back" the check's own failure is under "check_error").
    """
    check_confirm_minutes(minutes)
    out = edit(host, user, passwd, payload, session_timeout, command_timeout,
               commit_confirmed=minutes, port=port, comment=comment)
    if out.startswith("NO CHANGES"):
        return {"final": "no changes", "commit": out, "checks": None}
    ours = _ours(pending_commit(commit_status(host, user, passwd, session_timeout, command_timeout, port=port)),
                 user, comment)
    try:
        ok, reason = bool(check()), None
    except Exception as e:
        ok, reason = False, f"{type(e).__name__}: {e}"
    entries = commit_status(host, user, passwd, session_timeout, command_timeout, port=port)
    moved = _history_moved(ours, entries)
    if ok:
        if moved:
            return {"final": "not confirmed", "commit": out, "checks": True, "reason": moved, "status": entries}
        done = confirm(host, user, passwd, session_timeout, command_timeout, port=port,
                       comment=f"{comment} (confirmed)" if comment else None)
        return {"final": "confirmed", "commit": out, "checks": True, "confirm": done}
    if moved:
        return {"final": "not rolled back", "commit": out, "checks": False, "reason": moved,
                "check_error": reason, "status": entries}
    back = rollback(host, user, passwd, 1, session_timeout, command_timeout, port=port,
                    comment=f"{comment} (rolled back: checks failed)" if comment else "rolled back: checks failed")
    return {"final": "rolled back", "commit": out, "checks": False, "reason": reason, "rollback": back}
