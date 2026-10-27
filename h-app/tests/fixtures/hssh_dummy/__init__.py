"""A driver from outside h-ssh, the way an internal package ships one: a
dialect of its own on a transport the registry already has. Installed, the
package would declare

    [project.entry-points."hssh.drivers"]
    dummy = "hssh_dummy:DRIVERS"

and the paramiko module (hssh.transports.ssh) would do its work, in this
dialect, as it does for ios@ssh or junos@ssh. The tests build the same
EntryPoint by hand, so nothing has to be installed.
"""

import re
from pathlib import Path

from hssh import drivers
from hssh.dialects.base import Dialect
from hssh.drivers import Driver

# How this CLI refuses a line. A dialect on a text transport needs one: the
# transports read every reply with it.
REFUSED = re.compile(r"^\s*dummy: (unknown|refused)\b", re.M)

# The package's own shortcut library, named by path: `-sC whoami` resolves
# through it once the driver is registered.
DIALECT = Dialect("dummy", "Dummy", "a dialect from a test package: shows only, no CLI to type at",
                  shortcuts=str(Path(__file__).with_name("dummy.json")), refused=REFUSED)

DRIVERS = [Driver(DIALECT, drivers.SSH, frozenset({"show", "show_batch"}))]


def make():
    """The callable form: an entry point may name a function returning the drivers."""
    return DRIVERS


# What an entry point must not hand over: an object that is not a Driver,
# and the same driver twice.
NOT_A_DRIVER = [DIALECT]
TWICE = DRIVERS + DRIVERS
