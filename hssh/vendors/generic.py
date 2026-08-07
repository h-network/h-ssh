"""Generic SSH implementation using Paramiko."""

from typing import List

try:
    import paramiko
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


def show(host: str, user: str, passwd: str, cmd: str, session_timeout: int,
         command_timeout: int, port: int = None, vendor_hint: str = None) -> str:
    """Execute a show command via SSH."""
    return _run_commands(host, user, passwd, [cmd], session_timeout, command_timeout, port=port)


def edit(host: str, user: str, passwd: str, payload: str, session_timeout: int,
         command_timeout: int, commit_confirmed: int = None, port: int = None,
         vendor_hint: str = None) -> str:
    """Execute configuration commands via SSH."""
    commands = [ln.strip() for ln in payload.strip().splitlines() if ln.strip()]
    return _run_commands(host, user, passwd, commands, session_timeout, command_timeout, port=port)


def _run_commands(host: str, user: str, passwd: str, commands: List[str],
                  session_timeout: int, command_timeout: int, port: int = None) -> str:
    """Execute commands via SSH on any device."""
    if not AVAILABLE:
        raise RuntimeError("paramiko not available in this environment.")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    session_timeout_float = float(session_timeout)
    command_timeout_float = float(command_timeout)

    conn_params = {
        "hostname": host,
        "username": user,
        "port": port or 22,
        "timeout": session_timeout_float,
        "banner_timeout": session_timeout_float,
        "auth_timeout": session_timeout_float,
    }

    if passwd is not None:
        conn_params["password"] = passwd
        conn_params["look_for_keys"] = False
        conn_params["allow_agent"] = False
    else:
        conn_params["look_for_keys"] = True
        conn_params["allow_agent"] = True

    client.connect(**conn_params)

    try:
        outputs = []
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=command_timeout_float)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            block = []
            block.append(f"$ {cmd}")
            if out.strip():
                block.append(out.rstrip())
            if err.strip():
                block.append("STDERR:")
                block.append(err.rstrip())
            outputs.append("\n".join(block))
        return "\n\n".join(outputs).strip() + "\n"
    finally:
        client.close()


def show_batch(host: str, user: str, passwd: str, cmds: List[str],
               session_timeout: int, command_timeout: int,
               port: int = None, vendor_hint: str = None) -> List[dict]:
    """Execute multiple commands on a single SSH connection."""
    if not AVAILABLE:
        raise RuntimeError("paramiko not available in this environment.")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    session_timeout_float = float(session_timeout)
    command_timeout_float = float(command_timeout)

    conn_params = {
        "hostname": host,
        "username": user,
        "port": port or 22,
        "timeout": session_timeout_float,
        "banner_timeout": session_timeout_float,
        "auth_timeout": session_timeout_float,
    }

    if passwd is not None:
        conn_params["password"] = passwd
        conn_params["look_for_keys"] = False
        conn_params["allow_agent"] = False
    else:
        conn_params["look_for_keys"] = True
        conn_params["allow_agent"] = True

    client.connect(**conn_params)
    try:
        results = []
        for cmd in cmds:
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=command_timeout_float)
                out = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace")
                output_parts = [f"$ {cmd}"]
                if out.strip():
                    output_parts.append(out.rstrip())
                if err.strip():
                    output_parts.append("STDERR:")
                    output_parts.append(err.rstrip())
                results.append({"command": cmd, "ok": True, "output": "\n".join(output_parts)})
            except Exception as e:
                results.append({"command": cmd, "ok": False, "error": str(e)})
        return results
    finally:
        client.close()
