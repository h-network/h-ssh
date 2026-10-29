"""Driver registry: dialect@transport names, built-ins and the hssh.drivers entry point group (section 3.3)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Protocol, Union

from hssh.communicators.base import Communicator
from hssh.model import Mode, Target

ENTRY_POINT_GROUP = "hssh.drivers"

EntryPointValue = Union["Driver", list["Driver"]]


@dataclass(frozen=True)
class Driver:
    """One dialect paired with one communicator, named dialect@transport."""

    name: str
    dialect: object
    communicator: Communicator


def driver_name(dialect: str, transport: str) -> str:
    """Build the dialect@transport name."""
    ...


def split_name(name: str) -> tuple[str, str]:
    """Split a dialect@transport name into its two parts."""
    ...


class DriverRegistry(Protocol):
    """Holds built-in and third-party drivers and maps targets to them."""

    def register(self, driver: Driver) -> None: ...

    def load_entry_points(self, group: str = ENTRY_POINT_GROUP) -> None:
        """Register every Driver or list of Drivers loaded from the entry point group."""
        ...

    def get(self, name: str) -> Driver: ...

    def resolve(self, target: Target) -> Driver: ...

    def check_mode(self, driver: Driver, mode: Mode) -> None:
        """Raise Fault(UNSUPPORTED) when the driver's capabilities don't include the mode."""
        ...

    def __iter__(self) -> Iterator[Driver]: ...
