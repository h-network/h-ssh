#!/usr/bin/env python3
"""
Example: Using h-ssh as a library in your own scripts.

A transport module (hssh.transports.netconf, .ssh, .openssh, .telnet) does
the work for every dialect on it; the runner picks the module from the
driver name a target carries (`junos`, `junos@ssh`, `eos@ssh`, ...).
"""

from hssh import Target
from hssh.transports import netconf, ssh

# Example 1: Junos over NETCONF, the module called directly
print("=== Example 1: Direct Junos call (NETCONF) ===")
try:
    result = netconf.show(
        host="192.168.1.1",
        user="admin",
        passwd="password",
        cmd="show version",
        session_timeout=30,
        command_timeout=20,
    )
    print(result)
except Exception as e:
    print(f"Error: {e}")


# Example 2: an EOS switch over SSH; the vendor_hint names the dialect
print("\n=== Example 2: Direct EOS call (SSH) ===")
try:
    result = ssh.show(
        host="192.168.1.2",
        user="admin",
        passwd="password",
        cmd="show version",
        session_timeout=30,
        command_timeout=20,
        vendor_hint="eos@ssh",
    )
    print(result)
except Exception as e:
    print(f"Error: {e}")


# Example 3: the runner, which resolves the driver from the target's vendor
print("\n=== Example 3: Using runner with custom targets ===")
from hssh.runner import run_for_target

targets = [
    Target(name="CR1", host="192.168.1.1", vendor="junos"),
    Target(name="SW1", host="192.168.1.2", vendor="eos@ssh"),
]

for target in targets:
    res = run_for_target(
        t=target,
        transport=target.vendor,
        mode="show",
        show_cmd="show version",
        edit_cmd=None,
        config_dir=None,
        broadcast_file=None,
        user="admin",
        passwd="password",
        session_timeout=30,
        command_timeout=20,
        dry_run=False,
        commit_confirmed=None,
        save_dir=None,
    )
    name, success, output, duration_ms = res
    print(f"\n{name}: {'OK' if success else 'FAIL'} ({duration_ms}ms)")
    print(output if success else res.error)


# Example 4: Load devices from CSV
print("\n=== Example 4: Load from CSV ===")
from hssh.core import load_devices_csv

try:
    devices = load_devices_csv("devices.csv")
    for dev in devices:
        print(f"Device: {dev.name}, Host: {dev.host}, Vendor: {dev.vendor}")
except FileNotFoundError:
    print("devices.csv not found")
