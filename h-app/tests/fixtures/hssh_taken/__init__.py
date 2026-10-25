"""Drivers that claim what the registry already has. DRIVERS pairs a clean
`taken@ssh` with a `taken@openssh` that takes `junos` as an alias; an entry
point is taken whole or not at all, so neither may register. same_name()
is a built-in's own name, `none@ssh`, from another package."""

import re

from hssh import drivers
from hssh.dialects.base import Dialect
from hssh.drivers import Driver

DIALECT = Dialect("taken", "Taken", "claims a name the registry already has",
                  refused=re.compile(r"^\s*% ", re.M))

DRIVERS = [
    Driver(DIALECT, drivers.SSH, frozenset({"show"})),
    Driver(DIALECT, drivers.OPENSSH, frozenset({"show"}), aliases=("junos",)),
]


def same_name():
    return [Driver(drivers.NONE, drivers.SSH, frozenset({"show"}))]
