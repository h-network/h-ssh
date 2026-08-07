#!/usr/bin/env python3
"""
Example: Using h-ssh as a library in your own scripts.
"""

from hssh import Target, vendors

# Example 1: Direct vendor usage
print("=== Example 1: Direct Junos call ===")
try:
    result = vendors.junos.show(
        host="192.168.1.1",
        user="admin",
        passwd="password",
        cmd="show version",
        session_timeout=30,
        command_timeout=20
    )
    print(result)
except Exception as e:
    print(f"Error: {e}")


# Example 2: Direct Arista call
print("\n=== Example 2: Direct Arista call ===")
try:
    result = vendors.arista.show(
        host="192.168.1.2",
        user="admin",
        passwd="password",
        cmd="show version",
        session_timeout=30,
        command_timeout=20
    )
    print(result)
except Exception as e:
    print(f"Error: {e}")


# Example 3: Using the runner with custom logic
print("\n=== Example 3: Using runner with custom targets ===")
from hssh.runner import run_for_target

targets = [
    Target(name="CR1", host="192.168.1.1", vendor="junos"),
    Target(name="SW1", host="192.168.1.2", vendor="arista"),
]

for target in targets:
    name, success, output, duration_ms = run_for_target(
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
    print(f"\n{name}: {'OK' if success else 'FAIL'} ({duration_ms}ms)")
    print(output)


# Example 4: Load devices from CSV
print("\n=== Example 4: Load from CSV ===")
from hssh.core import load_devices_csv

try:
    devices = load_devices_csv("devices.csv")
    for dev in devices:
        print(f"Device: {dev.name}, Host: {dev.host}, Vendor: {dev.vendor}")
except FileNotFoundError:
    print("devices.csv not found")
