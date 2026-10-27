"""Every run is kept in a store (hssh.store), h-ssh.db in the current directory
by default. The suite runs from the repository, so the store goes to a
temporary place instead: once at import, for the test modules that snapshot
the environment for a subprocess at import time, and per test through
HSSH_STORE; a test of the default location clears the variable and changes
directory itself.

Every run is probed first (hssh.probe, #127): a TCP connect and the SSH
banner per box. The suite's devices are fakes behind drivers.MODULES at
addresses nothing listens on, so here every box answers as a healthy sshd
does and nothing is contacted (`probed` lists the boxes asked); a test of
the probe itself takes `real_probe`, against listeners on localhost. The
ssh client configuration the probe reads for the openssh and junos
transports is none here (`ssh -F /dev/null -G`, an empty ~/.ssh/config),
so the machine's own cannot move a test's box.

The driver registry holds the built-ins and whatever driver packages this
machine has installed, a broken one included; `installed` runs a test on
each."""

import os
import tempfile

import pytest

_SUITE_STORE_DIR = tempfile.mkdtemp(prefix="hssh-tests-")
os.environ.setdefault("HSSH_STORE", os.path.join(_SUITE_STORE_DIR, "h-ssh.db"))

from hssh import probe as _probe          # noqa: E402 - after the store's place is set

_REAL_ATTEMPT = _probe.attempt


@pytest.fixture(autouse=True)
def _store_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("HSSH_STORE", str(tmp_path / "test-h-ssh.db"))


@pytest.fixture(autouse=True)
def probed(monkeypatch):
    """Every box the probe asks answers live at once: a 0.3 ms handshake, the
    banner 7 ms later (TCP alone where the transport has no banner). The
    list returned is the (host, port) of every try, in the order asked."""
    asked = []

    async def answers_live(host, port, banner, seconds):
        asked.append((host, port))
        if banner is None:
            return _probe.Answer(_probe.LIVE, connect_ms=0.3)
        return _probe.Answer(_probe.LIVE, connect_ms=0.3, banner_ms=7.0, banner="SSH-2.0-OpenSSH_9.6")
    monkeypatch.setattr(_probe, "attempt", answers_live)
    monkeypatch.setattr(_probe, "SSH_G", ("ssh", "-F", os.devnull, "-G"))
    monkeypatch.setattr(_probe, "SSH_CONFIG", os.devnull)
    return asked


@pytest.fixture
def real_probe(monkeypatch):
    """The probe as it is: a test that takes this probes for real."""
    monkeypatch.setattr(_probe, "attempt", _REAL_ATTEMPT)


# What `installed` adds next to what this machine has: an entry point, and the drivers it brings.
_EXTRA = {
    "with a driver package installed": ("dummy", "tests.fixtures.hssh_dummy:DRIVERS", {"dummy@ssh"}),
    "with a broken one installed": ("broken", "tests.fixtures.hssh_broken", set()),
}


@pytest.fixture(params=["as installed here", *_EXTRA])
def installed(request, monkeypatch):
    """The registry as load() builds it from what this machine has installed,
    and again with one more package, as the README's acme would be, or with
    one that fails to import, which is listed by name while the rest load
    (#110: the suite once took the built-ins for the whole registry, with
    nothing broken, and failed where such a package was installed). Yields
    the names the extra adds; the registry is rebuilt from what is really
    installed afterwards."""
    from importlib.metadata import EntryPoint
    from hssh import drivers
    if request.param == "as installed here":
        yield frozenset()
        return
    name, value, adds = _EXTRA[request.param]
    extra = EntryPoint(name, value, drivers.ENTRY_POINT_GROUP)
    real = drivers.metadata.entry_points
    with monkeypatch.context() as m:
        m.setattr(drivers.metadata, "entry_points",
                  lambda **kw: list(real(**kw)) + ([extra] if kw.get("group") == drivers.ENTRY_POINT_GROUP else []))
        drivers.load()
        yield frozenset(adds)
    drivers.load()
