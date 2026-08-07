"""Arista EOS implementation using pyeapi."""

from typing import List

try:
    import pyeapi
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


def show(host: str, user: str, passwd: str, cmd: str, session_timeout: int,
         command_timeout: int, port: int = None, vendor_hint: str = None) -> str:
    """Execute a show command on an Arista device."""
    if not AVAILABLE:
        raise RuntimeError("pyeapi not available in this environment.")

    node = pyeapi.connect(
        transport='https',
        host=host,
        port=port or 443,
        username=user,
        password=passwd,
        timeout=session_timeout
    )

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
    if not AVAILABLE:
        raise RuntimeError("pyeapi not available in this environment.")

    node = pyeapi.connect(
        transport='https',
        host=host,
        port=port or 443,
        username=user,
        password=passwd,
        timeout=session_timeout
    )

    result = node.enable([cmd])

    if result and len(result) > 0:
        return result[0].get('result', {})
    return {}


def edit(host: str, user: str, passwd: str, payload: str, session_timeout: int,
         command_timeout: int, commit_confirmed: int = None, port: int = None,
         vendor_hint: str = None) -> str:
    """Apply configuration commands to an Arista device."""
    if not AVAILABLE:
        raise RuntimeError("pyeapi not available in this environment.")

    node = pyeapi.connect(
        transport='https',
        host=host,
        port=port or 443,
        username=user,
        password=passwd,
        timeout=session_timeout
    )

    commands = [ln.strip() for ln in payload.strip().splitlines() if ln.strip()]
    node.config(commands)

    return f"CONFIG OK\n\nCommands applied:\n" + "\n".join(f"  {c}" for c in commands)


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = None) -> List[dict]:
    """Execute multiple show commands on a single Arista eAPI connection."""
    if not AVAILABLE:
        raise RuntimeError("pyeapi not available in this environment.")

    node = pyeapi.connect(
        transport='https',
        host=host,
        port=port or 443,
        username=user,
        password=passwd,
        timeout=session_timeout,
    )

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
