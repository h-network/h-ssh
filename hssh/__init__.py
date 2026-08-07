"""
h-ssh: Multi-vendor network automation framework.

Supports parallel execution across Juniper, Arista, and other network devices
with multiple transport mechanisms: SSH, NETCONF, eAPI, telnet, and raw sockets.
"""

from .core import Target, load_devices_csv, resolve_command, get_available_commands, parse_inline_target, load_jobs
from .runner import run_for_target, run_for_target_async
from .safety import SafetyGate
from .audit import write_audit_entry
from . import vendors

__version__ = "1.0.0"
__all__ = [
    'Target', 'load_devices_csv', 'resolve_command', 'get_available_commands',
    'parse_inline_target', 'load_jobs',
    'run_for_target', 'run_for_target_async',
    'SafetyGate', 'write_audit_entry', 'vendors',
]
