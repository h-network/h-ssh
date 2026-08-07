#!/usr/bin/env python3
"""
h-ssh: Multi-vendor network automation CLI.

A simple wrapper around the hssh package.
For library usage, import hssh directly.
"""

import asyncio
import sys
from hssh.cli import main

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
