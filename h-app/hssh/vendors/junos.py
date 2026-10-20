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

from contextlib import contextmanager
from typing import List, Optional

from ..core import JUNOS_SET_PREFIX_VERBS
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
    }
    if passwd:
        params["passwd"] = passwd
    dev = JunosDevice(**params)
    try:
        dev.open()
    except ConnectError as e:
        raise NotAppliedError(f"NETCONF connect failed: {e}") from e
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


@contextmanager
def _session(host: str, user: str, passwd: Optional[str], session_timeout: int,
             command_timeout: int, port: Optional[int]):
    """A session for this router: fresh, or borrowed from the pool."""
    key = (host, port or DEFAULT_PORT, user)
    with POOL.lease(
        key,
        opener=lambda: _open(host, user, passwd, session_timeout, command_timeout, port),
        closer=_close,
        alive=_alive,
    ) as lease:
        lease.dev.timeout = command_timeout
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


def _unlock_quietly(cu) -> Optional[str]:
    try:
        cu.unlock()
        return None
    except Exception as e:
        return str(e)


def edit(host: str, user: str, passwd: str, payload: str,
         session_timeout: int, command_timeout: int,
         commit_confirmed: int = None, port: int = None,
         vendor_hint: str = None, dry_run: bool = False) -> str:
    """Apply configuration over NETCONF.

    lock -> load -> diff -> commit_check -> commit (or rollback when dry_run)
    -> unlock. With dry_run the candidate is validated and diffed on the device
    and then discarded; nothing is committed.

    Raises NotAppliedError for failures before anything could change on the
    device, AmbiguousCommitError when a commit was sent and its outcome is
    unknown, and RuntimeError for rejected config. Only NotAppliedError is safe
    to retry.

    A pooled session is discarded whenever this leaves it in doubt: a commit
    whose outcome is unknown, a rollback or unlock that failed, a timeout, or
    the session dying underneath — so no candidate lock outlives the call.
    """
    _require()
    with _session(host, user, passwd, session_timeout, command_timeout, port) as lease:
        dev = lease.dev
        cu = None
        locked = False
        committed = False
        try:
            cu = JunosConfig(dev)
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
            locked = True

            fmt = _config_format(payload)
            body = _strip_comments(payload) if fmt == "set" else payload
            try:
                cu.load(body, format=fmt)
                diff = (cu.diff() or "")
                if not diff.strip():
                    return "NO CHANGES"
                cu.commit_check(timeout=command_timeout)
            except (ConfigLoadError, CommitError) as e:
                raise RuntimeError(f"Config error: {e}") from e

            if dry_run:
                return f"DRY-RUN: commit check passed, nothing committed\n\nDIFF:\n{diff}"

            try:
                if commit_confirmed and commit_confirmed > 0:
                    cu.commit(confirm=commit_confirmed, timeout=command_timeout)
                else:
                    cu.commit(timeout=command_timeout)
            except CommitError as e:
                raise RuntimeError(f"Config error: {e}") from e
            except Exception as e:
                # The commit RPC was sent. We cannot tell whether it landed.
                locked = False  # leave the candidate alone; the session is suspect
                lease.discard()
                raise AmbiguousCommitError(
                    f"commit outcome unknown ({type(e).__name__}: {e}); "
                    "check the device before retrying") from e
            committed = True

            if commit_confirmed and commit_confirmed > 0:
                head = f"COMMIT CONFIRMED ({commit_confirmed} minutes)"
            else:
                head = "COMMIT OK"
            return f"{head}\n\nDIFF:\n{diff}"
        except Exception as e:
            if _session_lost(e) or _timed_out(e):
                lease.discard()
            raise
        finally:
            if cu is not None and locked:
                if not committed:
                    try:
                        cu.rollback()
                    except Exception:
                        lease.discard()
                if _unlock_quietly(cu) is not None:
                    lease.discard()


def confirm(host: str, user: str, passwd: str,
            session_timeout: int, command_timeout: int,
            port: int = None, vendor_hint: str = None) -> str:
    """Confirm a pending commit-confirmed by issuing a plain commit."""
    _require()
    with _session(host, user, passwd, session_timeout, command_timeout, port) as lease:
        cu = JunosConfig(lease.dev)
        try:
            cu.commit(timeout=command_timeout)
        except CommitError as e:
            raise RuntimeError(f"Commit failed: {e}") from e
        except Exception as e:
            lease.discard()
            raise AmbiguousCommitError(
                f"commit outcome unknown ({type(e).__name__}: {e}); "
                "check the device before retrying") from e
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
    fmt = (fmt or "json").lower()
    if fmt not in ("json", "xml"):
        raise ValueError(f"fmt must be 'json' or 'xml', not {fmt!r}")
    from lxml import etree

    def run(lease):
        element = _rpc_element(lease.dev, command, args)
        if fmt == "json":
            element.set("format", "json")
            return lease.dev.execute(element)
        reply = lease.dev.execute(element)
        return etree.tostring(reply, pretty_print=True, encoding="unicode")

    text = command.strip()
    read_only = text.startswith("show ") or text.startswith("get")
    if read_only:
        return _on_session(host, user, passwd, session_timeout, command_timeout, port, run)
    with _session(host, user, passwd, session_timeout, command_timeout, port) as lease:
        try:
            return run(lease)
        except Exception as e:
            if _session_lost(e) or _timed_out(e):
                lease.discard()
            raise
