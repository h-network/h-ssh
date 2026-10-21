"""Arista EOS implementation using pyeapi.

The switch's certificate is verified: against the system CAs, or against the
one in HSSH_EAPI_CA for a lab-issued certificate. Left to itself pyeapi turns
verification off; HSSH_EAPI_VERIFY=no is that choice made explicitly, for a
self-signed switch, the way HSSH_HOST_KEY_POLICY=no is for the SSH transports.

Edits go through an EOS configure session: the lines are loaded into the
session, its diff is read back, and commit makes them live together. A line
EOS rejects aborts the session, so running-config is left as it was.
"""

import os
import ssl
from typing import List, Optional

try:
    import pyeapi
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


def _tls_context() -> ssl.SSLContext:
    """A verifying context, or a knowingly unverifying one when asked for."""
    if os.environ.get("HSSH_EAPI_VERIFY", "yes").lower() == "no":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context(cafile=os.environ.get("HSSH_EAPI_CA") or None)


def _connect(host: str, user: str, passwd: str, port: Optional[int],
             session_timeout: int, command_timeout: int):
    """A pyeapi Node for the switch: verified TLS, both timeouts honoured.

    pyeapi has one timeout, the socket's, covering connect and reads alike.
    The connection's connect() is wrapped so the TCP and TLS handshake runs
    under session_timeout and each request after it under command_timeout.
    http.client reconnects before every request, so the wrapper applies to
    all of them, not just the first.
    """
    if not AVAILABLE:
        raise RuntimeError("pyeapi not available in this environment.")

    node = pyeapi.connect(
        transport='https',
        host=host,
        port=port or 443,
        username=user,
        password=passwd,
        timeout=session_timeout,
        context=_tls_context(),
        return_node=True,
    )

    transport = node.connection.transport
    handshake = transport.connect

    def connect():
        handshake()
        transport.sock.settimeout(float(command_timeout))

    transport.connect = connect
    return node


def show(host: str, user: str, passwd: str, cmd: str, session_timeout: int,
         command_timeout: int, port: int = None, vendor_hint: str = None) -> str:
    """Execute a show command on an Arista device."""
    node = _connect(host, user, passwd, port, session_timeout, command_timeout)

    result = node.enable([cmd])

    if result and len(result) > 0:
        output = result[0].get('result', {})
        if isinstance(output, dict):
            return _format_dict_output(output)
        return str(output)
    return "NO OUTPUT"


def show_structured(host: str, user: str, passwd: str, cmd: str, session_timeout: int,
                    command_timeout: int, port: int = None, vendor_hint: str = None,
                    binding=None):
    """Execute a show command and return eAPI's JSON rather than flattened text.

    eAPI already answers in JSON — show() throws that structure away in
    _format_dict_output. This is the same request, kept intact.

    The binding argument is accepted for interface symmetry with junos and
    ignored: there is no field map to apply. Commands EOS cannot render as
    JSON raise pyeapi CommandError ("unconverted command"); that propagates
    to the caller rather than being silently downgraded to text.
    """
    node = _connect(host, user, passwd, port, session_timeout, command_timeout)

    result = node.enable([cmd])

    if result and len(result) > 0:
        return result[0].get('result', {})
    return {}


def edit(host: str, user: str, passwd: str, payload: str, session_timeout: int,
         command_timeout: int, commit_confirmed: int = None, port: int = None,
         vendor_hint: str = None) -> str:
    """Apply configuration to an Arista device through a configure session.

    COMMIT OK with the session's diff, or NO CHANGES when the lines changed
    nothing. A rejected line raises pyeapi's CommandError with the session
    aborted, nothing applied.
    """
    if commit_confirmed is not None:
        raise ValueError("commit_confirmed is not supported by the 'arista' transport; "
                         "nothing was sent to the device")
    node = _connect(host, user, passwd, port, session_timeout, command_timeout)

    commands = [ln.strip() for ln in payload.strip().splitlines() if ln.strip()]
    node.configure_session()
    try:
        node.config(commands)
        diff = node.diff()
        if not diff.strip():
            node.abort()
            return "NO CHANGES"
        node.commit()
    except Exception:
        # A session outlives the request on the switch, so leave none behind.
        # The caller needs the original error, not an abort that may have
        # failed for the same reason.
        try:
            node.abort()
        except Exception:
            pass
        raise

    return f"COMMIT OK\n\nDIFF:\n{diff}"


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = None) -> List[dict]:
    """Execute multiple show commands on a single Arista eAPI connection."""
    node = _connect(host, user, passwd, port, session_timeout, command_timeout)

    results = []
    for cmd in cmds:
        try:
            result = node.enable([cmd])
            if result and len(result) > 0:
                output = result[0].get('result', {})
                if isinstance(output, dict):
                    output = _format_dict_output(output)
                else:
                    output = str(output)
            else:
                output = "NO OUTPUT"
            results.append({"command": cmd, "ok": True, "output": output})
        except Exception as e:
            results.append({"command": cmd, "ok": False, "error": str(e)})
    return results


def _format_dict_output(data: dict, indent: int = 0) -> str:
    """Format dictionary output into readable text."""
    lines = []
    prefix = "  " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.append(_format_dict_output(value, indent + 1))
        elif isinstance(value, list):
            lines.append(f"{prefix}{key}:")
            for item in value:
                if isinstance(item, dict):
                    lines.append(_format_dict_output(item, indent + 1))
                else:
                    lines.append(f"{prefix}  - {item}")
        else:
            lines.append(f"{prefix}{key}: {value}")
    return "\n".join(lines)
