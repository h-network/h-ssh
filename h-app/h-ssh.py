#!/usr/bin/env python3
"""
h-ssh: Multi-vendor network automation CLI.

A simple wrapper around the hssh package.
For library usage, import hssh directly.
"""

from hssh.cli import main_sync

if __name__ == "__main__":
    main_sync()
