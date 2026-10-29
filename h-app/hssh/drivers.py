"""Driver registry: dialect@transport names, built-ins and the hssh.drivers entry point group (section 3.3)."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from typing import Iterable, Iterator, Protocol, Union

from hssh.communicators.base import Communicator
from hssh.dialects.base import Dialect
from hssh.model import Fault, FaultKind, Mode, Target

ENTRY_POINT_GROUP = "hssh.drivers"

EntryPointValue = Union["Driver", list["Driver"]]


@dataclass(frozen=True)
class Driver:
    """One dialect paired with one communicator, named dialect@transport."""

    name: str
    dialect: Dialect
    communicator: Communicator


def driver_name(dialect: str, transport: str) -> str:
    """Build the dialect@transport name."""
    return f"{dialect}@{transport}"


def split_name(name: str) -> tuple[str, str]:
    """Split a dialect@transport name into its two parts."""
    dialect, sep, transport = name.partition("@")
    if not sep or not dialect or not transport:
        raise ValueError(f"driver name {name!r} is not dialect@transport")
    return dialect, transport


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


# Built-in drivers are registered here once the communicators and dialects exist.
BUILTIN: tuple[Driver, ...] = ()


def _drivers_in(obj: object) -> list[Driver]:
    found = [obj] if isinstance(obj, Driver) else list(obj)  # type: ignore[call-overload]
    for d in found:
        if not isinstance(d, Driver):
            raise TypeError(f"{d!r} is not a Driver")
    return found


class Registry:
    """The concrete DriverRegistry; entry points that fail to load are skipped and listed in broken."""

    def __init__(self, drivers: Iterable[Driver] = BUILTIN) -> None:
        self._drivers: dict[str, Driver] = {}
        self.broken: dict[str, str] = {}
        for driver in drivers:
            self.register(driver)

    def register(self, driver: Driver) -> None:
        split_name(driver.name)
        if driver.name in self._drivers:
            raise ValueError(f"driver {driver.name!r} is already registered")
        self._drivers[driver.name] = driver

    def load_entry_points(self, group: str = ENTRY_POINT_GROUP) -> None:
        for ep in metadata.entry_points(group=group):
            try:
                found = _drivers_in(ep.load())
                if len({d.name for d in found}) != len(found):
                    raise ValueError("a driver name is listed twice")
                for driver in found:
                    self.register(driver)
            except Exception as e:  # noqa: BLE001 - one bad package must not take the registry down
                self.broken[ep.name] = f"{type(e).__name__}: {e}"

    def get(self, name: str) -> Driver:
        driver = self._drivers.get(name)
        if driver is None:
            known = ", ".join(sorted(self._drivers)) or "none"
            raise Fault(FaultKind.LOCAL, f"unknown driver {name!r}; available: {known}", False)
        return driver

    def resolve(self, target: Target) -> Driver:
        return self.get(driver_name(target.vendor, target.transport))

    def check_mode(self, driver: Driver, mode: Mode) -> None:
        if mode not in driver.communicator.capabilities:
            raise Fault(FaultKind.UNSUPPORTED, f"driver {driver.name!r} does not support {mode!r}", False)

    def __iter__(self) -> Iterator[Driver]:
        return iter(self._drivers.values())
