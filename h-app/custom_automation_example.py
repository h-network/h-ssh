#!/usr/bin/env python3
"""
Example: Custom automation script using hssh as a library.

This shows how you can build your own automation framework on top of hssh.
"""

import getpass
from hssh import Target, load_devices_csv
from hssh.vendors import junos

def check_junos_uptime(devices_file: str, username: str, password: str):
    """Custom function to check uptime on all Junos devices."""

    # Load devices from CSV
    devices = load_devices_csv(devices_file)

    print(f"\nChecking uptime for {len(devices)} devices...\n")

    results = []
    for device in devices:
        try:
            # Call Junos vendor module directly
            output = junos.show(
                host=device.host,
                user=username,
                passwd=password,
                cmd="show system uptime | no-more",
                session_timeout=45,
                command_timeout=20
            )

            # Parse the output (simple example)
            for line in output.split('\n'):
                if 'System booted:' in line:
                    results.append({
                        'device': device.name,
                        'status': 'UP',
                        'boot_time': line.split('System booted:')[1].strip()
                    })
                    break

        except Exception as e:
            results.append({
                'device': device.name,
                'status': 'ERROR',
                'error': str(e)
            })

    # Display results in custom format
    print("\n" + "="*70)
    print(f"{'Device':<20} {'Status':<10} {'Info':<40}")
    print("="*70)

    for result in results:
        if result['status'] == 'UP':
            print(f"{result['device']:<20} {result['status']:<10} {result.get('boot_time', 'N/A'):<40}")
        else:
            print(f"{result['device']:<20} {result['status']:<10} {result.get('error', 'N/A'):<40}")

    print("="*70)
    return results


if __name__ == "__main__":
    # This is your custom automation script
    # You can add any logic you want here

    print("Custom Junos Uptime Checker")
    print("Using hssh library for device access\n")

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    # Run your custom logic
    results = check_junos_uptime("test_devices.csv", username, password)

    # Do whatever you want with results - save to DB, generate reports, etc.
    print(f"\nProcessed {len(results)} devices")
