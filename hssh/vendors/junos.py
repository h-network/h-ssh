"""Hybrid Junos transport — paramiko SSH for show commands, PyEZ NETCONF for configuration.

Show path uses paramiko exec_command (fast, low overhead).
Config path uses PyEZ NETCONF (lock -> load -> diff -> commit/rollback -> unlock).
"""

from typing import List, Optional

try:
    import paramiko
    from jnpr.junos import Device as JunosDevice
    from jnpr.junos.utils.config import Config as JunosConfig
    from jnpr.junos.exception import (
        ConnectError, LockError, ConfigLoadError, CommitError,
    )
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


def _ssh_connect(host: str, user: str, passwd: Optional[str],
                 session_timeout: int, port: int = None) -> "paramiko.SSHClient":
    """Create a paramiko SSH connection."""
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())
    kwargs = {
        "hostname": host,
        "username": user,
        "port": port or 22,
        "timeout": session_timeout,
        "allow_agent": True,
        "look_for_keys": True,
    }
    if passwd:
        kwargs["password"] = passwd
    client.connect(**kwargs)
    return client


def _ssh_exec(client: "paramiko.SSHClient", command: str, timeout: int) -> str:
    """Execute a command over SSH and return output."""
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err and "warning:" not in err.lower():
        return out + "\n" + err if out else err
    return out


def show(host: str, user: str, passwd: str, cmd: str,
         session_timeout: int, command_timeout: int,
         port: int = None, vendor_hint: str = None) -> str:
    """Execute a show command via paramiko SSH (fast path)."""
    if not AVAILABLE:
        raise RuntimeError("paramiko and junos-eznc not available.")
    if "| no-more" not in cmd:
        cmd = cmd + " | no-more"
    client = _ssh_connect(host, user, passwd, session_timeout, port=port)
    try:
        return _ssh_exec(client, cmd, command_timeout).rstrip()
    finally:
        client.close()


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
    if not AVAILABLE:
        raise RuntimeError("paramiko and junos-eznc not available.")
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

    conn_params = {
        "host": host,
        "user": user,
        "port": port or 830,
        "conn_open_timeout": session_timeout,
    }
    if passwd:
        conn_params["passwd"] = passwd

    dev = JunosDevice(**conn_params)
    dev.open()
    try:
        dev.timeout = command_timeout
        table = table_cls(dev)
        table.get()
        return {key: dict(item) for key, item in table.items()}
    finally:
        dev.close()


def edit(host: str, user: str, passwd: str, payload: str,
         session_timeout: int, command_timeout: int,
         commit_confirmed: int = None, port: int = None,
         vendor_hint: str = None) -> str:
    """Apply set-style configuration via PyEZ NETCONF."""
    if not AVAILABLE:
        raise RuntimeError("paramiko and junos-eznc not available.")

    conn_params = {
        "host": host,
        "user": user,
        "port": port or 22,
        "gather_facts": False,
        "timeout": session_timeout,
    }
    if passwd:
        conn_params["passwd"] = passwd
    else:
        conn_params["ssh_private_key_file"] = None

    # Bare commit: confirm a pending commit-confirmed
    if payload.strip() == "commit":
        with JunosDevice(**conn_params) as dev:
            cu = JunosConfig(dev)
            cu.commit(timeout=command_timeout)
            return "COMMIT CONFIRMED OK"

    dev = JunosDevice(**conn_params)
    dev.open()
    try:
        cu = JunosConfig(dev)
        cu.lock()
        try:
            fmt = "set" if payload.strip().startswith(("set ", "delete ")) else "text"
            cu.load(payload, format=fmt)
            diff = cu.diff()

            if diff is None:
                diff = ""

            if not diff.strip():
                cu.rollback()
                cu.unlock()
                return "NO CHANGES"

            # Validate before committing
            cu.commit_check(timeout=command_timeout)

            if commit_confirmed and commit_confirmed > 0:
                cu.commit(confirm=commit_confirmed, timeout=command_timeout)
                cu.unlock()
                return f"COMMIT CONFIRMED ({commit_confirmed} minutes)\n\nDIFF:\n{diff}"
            else:
                cu.commit(timeout=command_timeout)
                cu.unlock()
                return f"COMMIT OK\n\nDIFF:\n{diff}"

        except (ConfigLoadError, CommitError) as e:
            cu.rollback()
            cu.unlock()
            raise RuntimeError(f"Config error: {e}")
        except Exception:
            try:
                cu.rollback()
                cu.unlock()
            except Exception:
                pass
            raise
    except LockError as e:
        raise RuntimeError(f"Failed to lock config: {e}")
    except ConnectError as e:
        raise RuntimeError(f"NETCONF connect failed: {e}")
    finally:
        try:
            dev.close()
        except Exception:
            pass


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = None) -> List[dict]:
    """Execute multiple show commands on a single SSH connection."""
    if not AVAILABLE:
        raise RuntimeError("paramiko and junos-eznc not available.")
    client = _ssh_connect(host, user, passwd, session_timeout, port=port)
    try:
        results = []
        for cmd in cmds:
            try:
                full_cmd = cmd if "| no-more" in cmd else cmd + " | no-more"
                output = _ssh_exec(client, full_cmd, command_timeout)
                results.append({"command": cmd, "ok": True, "output": output.rstrip()})
            except Exception as e:
                results.append({"command": cmd, "ok": False, "error": str(e)})
        return results
    finally:
        client.close()
