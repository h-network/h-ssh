"""Every run is kept in a store (hssh.store), h-ssh.db in the current directory
by default. The suite runs from the repository, so the store goes to a
temporary place instead: once at import, for the test modules that snapshot
the environment for a subprocess at import time, and per test through
HSSH_STORE; a test of the default location clears the variable and changes
directory itself.

The driver registry holds the built-ins and whatever driver packages this
machine has installed; `installed` runs a test on both."""

import os
import tempfile

import pytest

_SUITE_STORE_DIR = tempfile.mkdtemp(prefix="hssh-tests-")
os.environ.setdefault("HSSH_STORE", os.path.join(_SUITE_STORE_DIR, "h-ssh.db"))


@pytest.fixture(autouse=True)
def _store_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("HSSH_STORE", str(tmp_path / "test-h-ssh.db"))


@pytest.fixture(params=["as installed here", "with a driver package installed"])
def installed(request, monkeypatch):
    """The registry as load() builds it from what this machine has installed,
    and again with one more package, as the README's acme would be (#110:
    the suite once took the built-ins for the whole registry and failed where
    such a package was installed). Yields the names the extra adds; the
    registry is rebuilt from what is really installed afterwards."""
    from importlib.metadata import EntryPoint
    from hssh import drivers
    if request.param == "as installed here":
        yield frozenset()
        return
    extra = EntryPoint("dummy", "tests.fixtures.hssh_dummy:DRIVERS", drivers.ENTRY_POINT_GROUP)
    real = drivers.metadata.entry_points
    with monkeypatch.context() as m:
        m.setattr(drivers.metadata, "entry_points",
                  lambda **kw: list(real(**kw)) + ([extra] if kw.get("group") == drivers.ENTRY_POINT_GROUP else []))
        drivers.load()
        yield frozenset({"dummy@ssh"})
    drivers.load()
