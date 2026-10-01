"""Junos transport — PyEZ (NETCONF) for show, structured show and configuration.

Everything goes through junos-eznc, the official Juniper library, over a single
NETCONF session per call: show uses Device.cli(), structured show uses a
Table/View, and config uses lock -> load -> commit_check -> diff -> commit
(or rollback for --dry-run) -> unlock. The NETCONF port defaults to 830
everywhere; set the target's port to use NETCONF over SSH on 22.
"""

from typing import List, Optional

from ..core import JUNOS_SET_PREFIX_VERBS
from ..errors import AmbiguousCommitError, NotAppliedError

try:
    from jnpr.junos import Device as JunosDevice
    from jnpr.junos.utils.config import Config as JunosConfig
    from jnpr.junos.exception import (
        ConnectError, LockError, ConfigLoadError, CommitError, RpcTimeoutError,
    )
    AVAILABLE = True
except ImportError:
    AVAILABLE = False
    JunosDevice = JunosConfig = None

    class ConnectError(Exception):
        pass

    class LockError(Exception):
        pass

    class ConfigLoadError(Exception):
        pass

    class CommitError(Exception):
        pass

    class RpcTimeoutError(Exception):
        pass

DEFAULT_PORT = 830


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
        dev.close()
    except Exception:
        pass


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
    dev = _open(host, user, passwd, session_timeout, command_timeout, port)
    try:
        return _cli(dev, cmd)
    finally:
        _close(dev)


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

    dev = _open(host, user, passwd, session_timeout, command_timeout, port)
    try:
        table = table_cls(dev)
        table.get()
        return {key: dict(item) for key, item in table.items()}
    finally:
        _close(dev)


def _config_format(payload: str) -> str:
    """"set" when every meaningful line is a set-style command, else "text"."""
    lines = [ln.strip() for ln in payload.splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    if lines and all(ln.lower().startswith(JUNOS_SET_PREFIX_VERBS) for ln in lines):
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
    """
    _require()
    dev = _open(host, user, passwd, session_timeout, command_timeout, port)
    cu = None
    locked = False
    committed = False
    try:
        cu = JunosConfig(dev)
        try:
            cu.lock()
        except LockError as e:
            raise NotAppliedError(f"Failed to lock config: {e}") from e
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
            raise AmbiguousCommitError(
                f"commit outcome unknown ({type(e).__name__}: {e}); "
                "check the device before retrying") from e
        committed = True

        if commit_confirmed and commit_confirmed > 0:
            head = f"COMMIT CONFIRMED ({commit_confirmed} minutes)"
        else:
            head = "COMMIT OK"
        return f"{head}\n\nDIFF:\n{diff}"
    finally:
        if cu is not None and locked:
            if not committed:
                try:
                    cu.rollback()
                except Exception:
                    pass
            _unlock_quietly(cu)
        _close(dev)


def confirm(host: str, user: str, passwd: str,
            session_timeout: int, command_timeout: int,
            port: int = None, vendor_hint: str = None) -> str:
    """Confirm a pending commit-confirmed by issuing a plain commit."""
    _require()
    dev = _open(host, user, passwd, session_timeout, command_timeout, port)
    try:
        cu = JunosConfig(dev)
        try:
            cu.commit(timeout=command_timeout)
        except CommitError as e:
            raise RuntimeError(f"Commit failed: {e}") from e
        except Exception as e:
            raise AmbiguousCommitError(
                f"commit outcome unknown ({type(e).__name__}: {e}); "
                "check the device before retrying") from e
        return "COMMIT CONFIRMED OK"
    finally:
        _close(dev)


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = None) -> List[dict]:
    """Execute several show commands on one NETCONF session."""
    _require()
    dev = _open(host, user, passwd, session_timeout, command_timeout, port)
    try:
        results = []
        for cmd in cmds:
            try:
                results.append({"command": cmd, "ok": True, "output": _cli(dev, cmd)})
            except Exception as e:
                results.append({"command": cmd, "ok": False, "error": str(e)})
        return results
    finally:
        _close(dev)
