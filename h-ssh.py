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
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        # Ctrl-C is a normal way to stop a fleet run; a stack trace is not a
        # useful thing to print at someone who already knows what they did.
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
