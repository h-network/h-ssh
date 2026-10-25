"""
h-ssh: Multi-vendor network automation framework.

Parallel reads and gated edits across a fleet over NETCONF (Junos), SSH, the
OpenSSH client and telnet; a driver is one dialect on one transport.
"""

from .core import Target, load_devices_csv, resolve_command, get_available_commands, parse_inline_target, load_jobs
from .runner import run_for_target, run_for_target_async
from .safety import SafetyGate
from .audit import write_audit_entry
from . import pool
from . import drivers
from . import transports

__version__ = "1.0.0"
__all__ = [
    'Target', 'load_devices_csv', 'resolve_command', 'get_available_commands',
    'parse_inline_target', 'load_jobs',
    'run_for_target', 'run_for_target_async',
    'SafetyGate', 'write_audit_entry', 'pool', 'drivers', 'transports',
]
